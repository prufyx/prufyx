// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func fullCRD(group, kind, plural, scope string, versions ...string) []byte {
	var b strings.Builder
	b.WriteString("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + group + "\n  names:\n    kind: " + kind + "\n    plural: " + plural + "\n  scope: " + scope + "\n  versions:\n")
	for i, v := range versions {
		b.WriteString(fmt.Sprintf("  - name: %s\n    served: true\n    storage: %t\n", v, i == len(versions)-1))
	}
	return []byte(b.String())
}

const gGroup = "demo.example.invalid"

// growBase: every tag installs config/crd/{a,b,c,d}.yaml (+ config/other/x.yaml).
func growBase() *memTree {
	m := newMemTree()
	for _, k := range []string{"a", "b", "c", "d"} {
		m.files["config/crd/"+k+".yaml"] = fullCRD(gGroup, strings.ToUpper(k), k+"s", "Namespaced", "v1")
	}
	m.files["config/other/x.yaml"] = fullCRD(gGroup, "X", "xs", "Cluster", "v1")
	m.files["README.md"] = []byte("readme\n")
	return m
}

func growSource(mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range collapseTags {
		m := growBase()
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func growInput(src Source, grow bool) Input {
	in := collapseInputFor(src, true)
	in.WindowGrowOnly = grow
	return in
}

// wantNoGrow asserts the oldest tag stayed withheld and nothing was grown.
func wantNoGrow(t *testing.T, label string, in Input, reasonPart string) {
	t.Helper()
	res, err := Generate(in)
	if err != nil {
		var se *StopError
		_ = asStop(err, &se)
		t.Fatalf("%s: unexpected stop: %v", label, err)
	}
	if res.Report.MinFrom != "1.1" || len(res.Report.WindowGrown) != 0 || res.FirstWithheld == nil || res.FirstWithheld.Tag != "v1.0.0" {
		t.Fatalf("%s: grow-only fired or window wrong: minFrom=%s grown=%v withheld=%v", label, res.Report.MinFrom, res.Report.WindowGrown, res.FirstWithheld)
	}
	if reasonPart != "" && !strings.Contains(res.FirstWithheld.Reason, reasonPart) {
		t.Fatalf("%s: reason %q lacks %q", label, res.FirstWithheld.Reason, reasonPart)
	}
}

func asStop(err error, se **StopError) bool {
	s, ok := err.(*StopError)
	if ok {
		*se = s
	}
	return ok
}

func TestGrowOnlyGoldenNothingDiffers(t *testing.T) {
	for name, src := range map[string]memSource{"collapse-base": collapseSource(nil), "grow-base": growSource(nil)} {
		off := mustGenerate(t, growInput(src, false))
		on := mustGenerate(t, growInput(src, true))
		if !bytes.Equal(off.A, on.A) || !bytes.Equal(off.B, on.B) || !bytes.Equal(off.TableRow, on.TableRow) || !bytes.Equal(off.Changelog, on.Changelog) {
			t.Fatalf("%s: emitted bytes differ with the flag", name)
		}
		r1, _ := marshal(off.Report)
		r2, _ := marshal(on.Report)
		if !bytes.Equal(r1, r2) || on.FirstWithheld != nil {
			t.Fatalf("%s: report differs with the flag", name)
		}
	}
}

func TestGrowOnlyPositiveExtendsWindow(t *testing.T) {
	src := growSource(func(tag string, m *memTree) {
		if tag == "v1.0.0" {
			delete(m.files, "config/crd/d.yaml")
		}
	})
	off := mustGenerate(t, growInput(src, false))
	if off.Report.MinFrom != "1.1" {
		t.Fatalf("flag off must keep withholding: %s", off.Report.MinFrom)
	}
	on := mustGenerate(t, growInput(src, true))
	if on.Report.MinFrom != "1.0" || len(on.Report.Dropped) != 0 || len(on.Report.WindowGrown) != 1 {
		t.Fatalf("window did not extend: %+v", on.Report)
	}
	g := on.Report.WindowGrown[0]
	if g.Tag != "v1.0.0" || strings.Join(g.Added, ",") != "config/crd/d.yaml" || !strings.Contains(g.Reason, "added by a later release") {
		t.Fatalf("typed reason missing: %+v", g)
	}
	// The target is the same directory entry as the unmutated run, only the
	// minFrom is earlier.
	full := mustGenerate(t, growInput(growSource(nil), false))
	if !bytes.Equal(on.A, full.A) || !bytes.Equal(on.B, full.B) {
		t.Fatalf("target bytes differ from the all-equal window:\n%s\n%s", on.A, full.A)
	}
	// Every tag of the window reads through the emitted directory entry.
	tg := loadEmitted(t, "demo", on.A)
	for _, tag := range collapseTags {
		entries, _ := src.trees[tag].Entries()
		got, err := loaderRead(tg.Paths[0], entries)
		if err != nil || len(got) < 3 {
			t.Fatalf("%s: %v %v", tag, got, err)
		}
	}
	if on.FirstWithheld != nil {
		t.Fatal("nothing was withheld")
	}
}

func TestGrowOnlyNegatives(t *testing.T) {
	lackD := func(tag string, m *memTree) {
		if tag == "v1.0.0" {
			delete(m.files, "config/crd/d.yaml")
		}
	}
	with := func(f func(m *memTree)) func(tag string, m *memTree) {
		return func(tag string, m *memTree) {
			lackD(tag, m)
			if tag == "v1.0.0" {
				f(m)
			}
		}
	}
	cases := []struct {
		name   string
		mutate func(tag string, m *memTree)
		reason string
	}{
		{"identity removed in a newer tag", func(tag string, m *memTree) {
			if tag != "v1.0.0" {
				delete(m.files, "config/crd/c.yaml")
			}
		}, "set shrinks"},
		{"renamed kind in same file", with(func(m *memTree) { m.files["config/crd/c.yaml"] = fullCRD(gGroup, "Renamed", "cs", "Namespaced", "v1") }), "identity facts"},
		{"other plural", with(func(m *memTree) { m.files["config/crd/c.yaml"] = fullCRD(gGroup, "C", "others", "Namespaced", "v1") }), "identity facts"},
		{"other scope", with(func(m *memTree) { m.files["config/crd/c.yaml"] = fullCRD(gGroup, "C", "cs", "Cluster", "v1") }), "identity facts"},
		{"other group", with(func(m *memTree) {
			m.files["config/crd/c.yaml"] = fullCRD("old.example.invalid", "C", "cs", "Namespaced", "v1")
		}), "identity facts"},
		{"versions shrank", func(tag string, m *memTree) {
			if tag == "v1.0.0" {
				delete(m.files, "config/crd/d.yaml")
				m.files["config/crd/c.yaml"] = fullCRD(gGroup, "C", "cs", "Namespaced", "v1")
			} else {
				m.files["config/crd/c.yaml"] = fullCRD(gGroup, "C", "cs", "Namespaced", "v1", "v2")
			}
		}, "identity facts"},
		{"versions grew is not allowed either", func(tag string, m *memTree) {
			if tag == "v1.0.0" {
				delete(m.files, "config/crd/d.yaml")
				m.files["config/crd/c.yaml"] = fullCRD(gGroup, "C", "cs", "Namespaced", "v1", "v2")
			}
		}, "identity facts"},
		{"moved to another directory", with(func(m *memTree) {
			m.files["config/crd2/d.yaml"] = fullCRD(gGroup, "D", "ds", "Namespaced", "v1")
		}), ""},
		{"moved to another file of the directory", with(func(m *memTree) {
			m.files["config/crd/c.yaml"] = append(append([]byte{}, m.files["config/crd/c.yaml"]...), append([]byte("---\n"), fullCRD(gGroup, "D", "ds", "Namespaced", "v1")...)...)
		}), "identity facts"},
		{"second directory absent at the older tag", with(func(m *memTree) { delete(m.files, "config/other/x.yaml") }), "has no install file"},
		{"second directory shrinks", with(func(m *memTree) { m.files["config/other/y.yaml"] = fullCRD(gGroup, "Y", "ys", "Namespaced", "v1") }), "set shrinks"},
		{"oldest tag has no directory", func(tag string, m *memTree) {
			if tag == "v1.0.0" {
				for p := range m.files {
					if strings.HasPrefix(p, "config/") {
						delete(m.files, p)
					}
				}
			}
		}, ""},
		{"older tag with an unreadable definition", with(func(m *memTree) {
			m.files["config/crd/z.yaml"] = []byte("kind: CustomResourceDefinition\n{{ template }}\n")
		}), "unreadable-shape"},
	}
	for _, c := range cases {
		wantNoGrow(t, c.name, growInput(growSource(c.mutate), true), c.reason)
	}
}

func TestGrowOnlyMonotoneTowardNewest(t *testing.T) {
	// v1.1.0 lacks d, v1.0.0 has it again: a non-monotone set is withheld.
	src := growSource(func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			delete(m.files, "config/crd/d.yaml")
		}
	})
	res := mustGenerate(t, growInput(src, true))
	if res.Report.MinFrom != "1.1" || len(res.Report.WindowGrown) != 1 || res.Report.WindowGrown[0].Tag != "v1.1.0" {
		t.Fatalf("v1.1.0 should grow and v1.0.0 be withheld: %+v", res.Report)
	}
	if res.FirstWithheld == nil || res.FirstWithheld.Tag != "v1.0.0" || !strings.Contains(res.FirstWithheld.Reason, "set shrinks") {
		t.Fatalf("withheld: %+v", res.FirstWithheld)
	}
}

func TestGrowOnlyNeedsCollapseAndExclusionsStop(t *testing.T) {
	in := growInput(growSource(nil), true)
	in.CollapseDirectories = false
	res, err := Generate(in)
	wantCollapseStop(t, "without collapse", res, err, StopBadInput)
	in = growInput(growSource(nil), true)
	in.Rules = &Rules{Schema: RulesSchema, Exclusions: []ExclusionRule{{Class: ClassExactFile, Path: "config/crd/d.yaml", Reason: "r", Evidence: "e"}}}
	res, err = Generate(in)
	wantCollapseStop(t, "exclusion", res, err, StopDirUnsupported)
}

func TestGrowOnlyExactInstallPathMissingIsGrowthOnlyForThatFile(t *testing.T) {
	paths := func(names ...string) *Rules {
		r := &Rules{Schema: RulesSchema}
		for _, n := range names {
			r.InstallPaths = append(r.InstallPaths, InstallPathRule{Path: n, Reason: "r", Evidence: "e"})
		}
		return r
	}
	src := growSource(func(tag string, m *memTree) {
		delete(m.files, "config/other/x.yaml")
		if tag == "v1.0.0" {
			delete(m.files, "config/crd/d.yaml")
		}
	})
	in := growInput(src, true)
	in.Rules = paths("config/crd/a.yaml", "config/crd/b.yaml", "config/crd/c.yaml", "config/crd/d.yaml")
	off := in
	off.WindowGrowOnly = false
	res, err := Generate(off)
	if err == nil && res.Report.MinFrom != "1.1" {
		t.Fatalf("off: %s", res.Report.MinFrom)
	}
	on := mustGenerate(t, in)
	if on.Report.MinFrom != "1.0" || len(on.Report.WindowGrown) != 1 {
		t.Fatalf("exact-file entry missing at the older tag did not grow: %+v", on.Report)
	}
	// A second stop at the older tag keeps the withhold.
	bad := growSource(func(tag string, m *memTree) {
		delete(m.files, "config/other/x.yaml")
		if tag == "v1.0.0" {
			delete(m.files, "config/crd/d.yaml")
			m.files["config/crd/z.yaml"] = []byte("kind: CustomResourceDefinition\n{{ t }}\n")
		}
	})
	in2 := growInput(bad, true)
	in2.Rules = in.Rules
	res2, err2 := Generate(in2)
	if err2 == nil && (res2.Report.MinFrom != "1.1" || len(res2.Report.WindowGrown) != 0) {
		t.Fatalf("unreadable shape was relaxed: %+v", res2.Report)
	}
}
