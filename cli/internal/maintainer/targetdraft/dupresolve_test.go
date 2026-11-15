// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

var dupTags = []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"}

const (
	dupA      = "config/crd/bases/dup.example.test_widgets.yaml"
	dupB      = "charts/dupfix/crds/widgets.yaml"
	dupGadget = "config/crd/bases/dup.example.test_gadgets.yaml"
)

type crdOpts struct {
	storageFlip bool   // v1 not the storage version, v2 is
	extraProp   string // an extra schema property
	conversion  bool
	scope       string
	pluralName  string
	label       string
	apiVersion  string
	spec        string // appended verbatim under spec (indented two spaces)
}

func mkCRD(kind string, o crdOpts) string {
	if o.scope == "" {
		o.scope = "Namespaced"
	}
	if o.apiVersion == "" {
		o.apiVersion = "apiextensions.k8s.io/v1"
	}
	if o.pluralName == "" {
		o.pluralName = strings.ToLower(kind) + "s"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: %s\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.dup.example.test\n", o.apiVersion, o.pluralName)
	if o.label != "" {
		fmt.Fprintf(&b, "  labels:\n    release: %s\n", o.label)
	}
	fmt.Fprintf(&b, "spec:\n  group: dup.example.test\n  names:\n    kind: %s\n    plural: %s\n  scope: %s\n", kind, o.pluralName, o.scope)
	if o.conversion {
		b.WriteString("  conversion:\n    strategy: Webhook\n    webhook:\n      conversionReviewVersions:\n      - v1\n")
	}
	st1, st2 := "true", "false"
	if o.storageFlip {
		st1, st2 = "false", "true"
	}
	fmt.Fprintf(&b, "  versions:\n  - name: v1\n    served: true\n    storage: %s\n    schema:\n      openAPIV3Schema:\n        type: object\n        properties:\n          spec:\n            type: object\n", st1)
	if o.extraProp != "" {
		fmt.Fprintf(&b, "            properties:\n              %s:\n                type: string\n", o.extraProp)
	}
	fmt.Fprintf(&b, "  - name: v2\n    served: true\n    storage: %s\n", st2)
	b.WriteString(o.spec)
	return b.String()
}

// dupSource builds the four tags: copy A and copy B of the Widget definition
// (equal by default) and a Gadget definition only in A's directory.
func dupSource(mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range dupTags {
		m := newMemTree()
		m.files[dupA] = []byte(mkCRD("Widget", crdOpts{}))
		m.files[dupB] = []byte(mkCRD("Widget", crdOpts{label: "chart"}))
		m.files[dupGadget] = []byte(mkCRD("Gadget", crdOpts{}))
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func dupInput(src Source, rules *Rules, derive bool) Input {
	return Input{Slug: "dupfix", Name: "Dupfix", Repo: "github.com/example/dupfix", Catalog: "cncf", Tags: dupTags, Source: src, Rules: rules, DeriveDuplicates: derive}
}

func stopList(err error) string {
	var se *StopError
	if !errors.As(err, &se) {
		return fmt.Sprint(err)
	}
	return se.Error()
}

func targetPaths(t *testing.T, a []byte) ([]string, int) {
	t.Helper()
	var d struct {
		Target struct {
			Paths   []struct{ Path string }
			Exclude []json.RawMessage
		}
	}
	if err := json.Unmarshal(a, &d); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range d.Target.Paths {
		out = append(out, p.Path)
	}
	return out, len(d.Target.Exclude)
}

func hasStopCode(err error, code string) bool {
	var se *StopError
	if !errors.As(err, &se) {
		return false
	}
	for _, s := range se.Stops {
		if s.Code == code {
			return true
		}
	}
	return false
}

// --- positive case -------------------------------------------------------

func TestDeriveDuplicatesPositive(t *testing.T) {
	_, err := Generate(dupInput(dupSource(nil), nil, false))
	wantStop(t, err, StopDuplicateCRD) // flag off: the plain stop

	res := mustGenerate(t, dupInput(dupSource(nil), nil, true))
	paths, excl := targetPaths(t, res.A)
	if want := []string{dupGadget, dupA}; fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("paths %v, want %v", paths, want)
	}
	if excl != 0 {
		t.Fatal("exclude must stay empty")
	}
	if _, bex := targetPaths(t, res.B); bex != 0 {
		t.Fatal("half B exclude must stay empty")
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			t.Fatalf("derived path %q is not an exact file", p)
		}
	}
	if len(res.Report.Tags) != len(dupTags) || len(res.Report.Dropped) != 0 {
		t.Fatalf("window %+v dropped %+v", res.Report.Tags, res.Report.Dropped)
	}
	if len(res.Report.DerivedSources) != 1 {
		t.Fatalf("derivedSources %+v", res.Report.DerivedSources)
	}
	ds := res.Report.DerivedSources[0]
	if ds.Key != "dup.example.test/Widget" || ds.Kept != dupA || fmt.Sprint(ds.Dropped) != "["+dupB+"]" || !strings.HasPrefix(ds.SpecDigest, "sha256:") || len(ds.Tags) != len(dupTags) {
		t.Fatalf("derived source %+v", ds)
	}
	found := false
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == dupB {
			found = true
		}
	}
	if !found {
		t.Fatalf("dropped copy not reported as a non-install copy: %+v", res.Report.NonInstallCopies)
	}
	if !strings.Contains(string(res.Changelog), "Duplicate definitions") {
		t.Fatal("changelog lacks the evidence sentence")
	}
	if res.Report.CRDCount != 2 {
		t.Fatalf("crd count %d", res.Report.CRDCount)
	}
}

func TestDeriveDeterministic(t *testing.T) {
	run := func() [][]byte {
		res := mustGenerate(t, dupInput(dupSource(nil), nil, true))
		rep, _ := marshal(res.Report)
		return [][]byte{res.A, res.B, res.TableRow, res.Changelog, rep}
	}
	first := run()
	for n := 0; n < 20; n++ {
		next := run()
		for i := range first {
			if !bytes.Equal(first[i], next[i]) {
				t.Fatalf("output %d differs between runs", i)
			}
		}
	}
}

// --- flag off is the old behaviour --------------------------------------

func TestFlagOffUnchangedOnExistingFixtures(t *testing.T) {
	for _, derive := range []bool{false, true} {
		in := knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json"))
		in.DeriveDuplicates = derive
		res := mustGenerate(t, in)
		wantCanonicalEqual(t, "half A", res.A, readFile(t, "testdata/knative/golden-a.json"))
		wantCanonicalEqual(t, "half B", res.B, readFile(t, "testdata/knative/golden-b.json"))
		if len(res.Report.DerivedSources) != 0 {
			t.Fatal("no derivation without duplicates")
		}
	}
	off := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
	inOn := knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json"))
	inOn.DeriveDuplicates = true
	on := mustGenerate(t, inOn)
	offRep, _ := marshal(off.Report)
	onRep, _ := marshal(on.Report)
	if !bytes.Equal(offRep, onRep) || !bytes.Equal(off.Changelog, on.Changelog) || !bytes.Equal(off.TableRow, on.TableRow) {
		t.Fatal("flag on without a duplicate stop must not change any output byte")
	}
}

func TestFlagOffDuplicateStopsPinned(t *testing.T) {
	_, err := Generate(dupInput(dupSource(nil), nil, false))
	want := "STOP duplicate-crd dup.example.test/Widget: " + dupB + " and " + dupA + " define it; pin one source; next: two files define the same group and kind; pin which one is the source"
	if got := stopList(err); got != want {
		t.Fatalf("plain stop text changed:\n%s\nwant\n%s", got, want)
	}
}

// --- seeded wrong targets S1-S14 ----------------------------------------

// seed describes one wrong-target seed: it must never yield the target of
// the equal case.
type seed struct {
	name   string
	mutate func(tag string, m *memTree)
	// wantCode is a stop the run must end in (non-strict), when non-empty.
	wantCode string
	// samePlain: the run with the flag on must give exactly the flag-off
	// result (no derivation was allowed).
	samePlain bool
	// shrinks: the run succeeds with older tags withheld; the equal-case
	// window (all tags) must not appear and --strict-window must stop.
	shrinks bool
}

func setAt(tags map[string]bool, f func(m *memTree)) func(string, *memTree) {
	return func(tag string, m *memTree) {
		if tags[tag] {
			f(m)
		}
	}
}

func seeds() []seed {
	only := func(tag string) map[string]bool { return map[string]bool{tag: true} }
	diffB := func(o crdOpts) func(m *memTree) {
		return func(m *memTree) { m.files[dupB] = []byte(mkCRD("Widget", o)) }
	}
	return []seed{
		{name: "S1 storage flag flipped in B at the newest tag", mutate: setAt(only("v1.3.0"), diffB(crdOpts{storageFlip: true})), wantCode: StopDuplicateCRDDiffers},
		{name: "S2 one schema property changed in B", mutate: setAt(only("v1.3.0"), diffB(crdOpts{extraProp: "extra"})), wantCode: StopDuplicateCRDDiffers},
		{name: "S3 conversion webhook only in B", mutate: setAt(only("v1.3.0"), diffB(crdOpts{conversion: true})), wantCode: StopDuplicateCRDDiffers},
		{name: "S4 B differs at the oldest window tag only", mutate: setAt(only("v1.0.0"), diffB(crdOpts{extraProp: "old"})), shrinks: true},
		{name: "S5 B differs at a middle tag", mutate: setAt(only("v1.1.0"), diffB(crdOpts{conversion: true})), shrinks: true},
		{name: "S6 A absent at one tag", mutate: setAt(only("v1.1.0"), func(m *memTree) { delete(m.files, dupA) }), shrinks: true},
		{name: "S6b A absent at the newest tag", mutate: setAt(only("v1.3.0"), func(m *memTree) { delete(m.files, dupA) }), wantCode: StopWindowTooShort},
		{name: "S7 dropped multi-definition file holds a CRD without a kept copy", mutate: func(_ string, m *memTree) {
			m.files[dupB] = []byte(mkCRD("Widget", crdOpts{}) + "---\n" + mkCRD("Orphan", crdOpts{}))
		}, wantCode: StopDuplicateCRDUnresolvable},
		{name: "S8 B unreadable at the oldest tag", mutate: setAt(only("v1.0.0"), func(m *memTree) { m.files[dupB] = []byte("kind: CustomResourceDefinition\nspec: {{ broken }}\n") }), samePlain: true},
		{name: "S9 B templated with a directive inside spec", mutate: func(_ string, m *memTree) {
			m.files[dupB] = []byte(mkCRD("Widget", crdOpts{spec: "  preserveUnknownFields: {{ .Values.keep }}\n"}))
		}, samePlain: true},
		{name: "S10 same kind twice in one directory with different content", mutate: func(_ string, m *memTree) {
			delete(m.files, dupB)
			m.files["config/crd/bases/second.yaml"] = []byte(mkCRD("Widget", crdOpts{extraProp: "other"}))
		}, wantCode: StopDuplicateCRDDiffers},
		{name: "S10b same kind twice in one file", mutate: func(_ string, m *memTree) {
			delete(m.files, dupB)
			m.files[dupA] = []byte(mkCRD("Widget", crdOpts{}) + "---\n" + mkCRD("Widget", crdOpts{}))
		}, wantCode: StopDuplicateCRDUnresolvable},
		{name: "S11 another stop code at one tag", mutate: setAt(only("v1.1.0"), func(m *memTree) {
			m.files["test/stray.yaml"] = []byte(mkCRD("Stray", crdOpts{}))
		}), samePlain: true},
		{name: "S13 B is a test-like path", mutate: func(_ string, m *memTree) {
			delete(m.files, dupB)
			m.files["test/copies/widgets.yaml"] = []byte(mkCRD("Widget", crdOpts{}))
		}, samePlain: true},
		{name: "S15 scope differs", mutate: setAt(only("v1.3.0"), diffB(crdOpts{scope: "Cluster"})), wantCode: StopDuplicateCRDDiffers},
		{name: "S16 apiVersion differs", mutate: setAt(only("v1.3.0"), diffB(crdOpts{apiVersion: "apiextensions.k8s.io/v1beta1"})), wantCode: StopDuplicateCRDDiffers},
		{name: "S17 names differ", mutate: setAt(only("v1.3.0"), diffB(crdOpts{pluralName: "gizmos"})), wantCode: StopDuplicateCRDDiffers},
	}
}

func equalCaseTargetA(t *testing.T) []byte {
	return mustGenerate(t, dupInput(dupSource(nil), nil, true)).A
}

func TestSeededWrongTargetsDuplicate(t *testing.T) {
	good := equalCaseTargetA(t)
	for _, sd := range seeds() {
		t.Run(sd.name, func(t *testing.T) {
			res, err := Generate(dupInput(dupSource(sd.mutate), nil, true))
			if res != nil && bytes.Equal(res.A, good) && len(res.Report.Dropped) == 0 {
				t.Fatal("the seed produced the target of the equal case")
			}
			switch {
			case sd.wantCode != "":
				if err == nil || !hasStopCode(err, sd.wantCode) {
					t.Fatalf("want stop %s, got %v", sd.wantCode, err)
				}
			case sd.samePlain:
				plain, perr := Generate(dupInput(dupSource(sd.mutate), nil, false))
				if res != nil || plain != nil {
					if res == nil || plain == nil || !bytes.Equal(res.A, plain.A) || !bytes.Equal(res.B, plain.B) {
						t.Fatalf("flag on differs from the plain run: %v / %v", err, perr)
					}
					if len(res.Report.DerivedSources) != 0 {
						t.Fatal("derivation ran where none is allowed")
					}
				} else if stopList(err) != stopList(perr) {
					t.Fatalf("original stops changed:\n%s\n%s", stopList(err), stopList(perr))
				}
			case sd.shrinks:
				if err != nil {
					t.Fatalf("want a shrunk window, got %v", err)
				}
				if len(res.Report.Dropped) == 0 || len(res.Report.Tags) >= len(dupTags) {
					t.Fatalf("window not shrunk: %+v", res.Report.Tags)
				}
				for _, ds := range res.Report.DerivedSources {
					if len(ds.Tags) > len(res.Report.Tags) {
						t.Fatalf("derived tags beyond the window: %+v", ds)
					}
				}
				in := dupInput(dupSource(sd.mutate), nil, true)
				in.StrictWindow = true
				_, serr := Generate(in)
				wantStop(t, serr, StopWindowShortened)
			}
		})
	}
}

func TestSeedS12HandRulesDisableDerivation(t *testing.T) {
	ip := `{"schema":"` + RulesSchema + `","installPaths":[{"path":"` + dupA + `","reason":"r","evidence":"e"},{"path":"` + dupGadget + `","reason":"r","evidence":"e"}]}`
	ex := `{"schema":"` + RulesSchema + `","exclusions":[{"class":"exact-file","path":"` + dupB + `","reason":"r","evidence":"e"}]}`
	for _, raw := range []string{ip, ex} {
		r1, err := ParseRules([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		r2, _ := ParseRules([]byte(raw))
		off, err1 := Generate(dupInput(dupSource(nil), r1, false))
		on, err2 := Generate(dupInput(dupSource(nil), r2, true))
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("%v vs %v", err1, err2)
		}
		if err1 == nil {
			if !bytes.Equal(off.A, on.A) || !bytes.Equal(off.B, on.B) || len(on.Report.DerivedSources) != 0 {
				t.Fatal("hand rules must keep the plain result")
			}
		} else if stopList(err1) != stopList(err2) {
			t.Fatal("original stops changed")
		}
	}
	// installPaths that still leave a duplicate: same stops as plain, no derivation.
	both := `{"schema":"` + RulesSchema + `","installPaths":[{"path":"config/crd/bases/","reason":"r","evidence":"e"},{"path":"charts/","reason":"r","evidence":"e"}]}`
	r1, _ := ParseRules([]byte(both))
	r2, _ := ParseRules([]byte(both))
	_, e1 := Generate(dupInput(dupSource(nil), r1, false))
	_, e2 := Generate(dupInput(dupSource(nil), r2, true))
	if e1 == nil || stopList(e1) != stopList(e2) {
		t.Fatalf("hand-ruled duplicate must keep the plain stops: %v / %v", e1, e2)
	}
}

// --- directory collapse interaction (S14) -------------------------------

func TestSeedS14DroppedCopyForbidsDirectoryCollapse(t *testing.T) {
	res := mustGenerate(t, dupInput(dupSource(nil), nil, true))
	ds := res.Report.DerivedSources[0].Dropped
	if !droppedInside("charts/dupfix/crds/", ds) || !droppedInside("charts/dupfix/crds", ds) || !droppedInside("charts/", ds) {
		t.Fatal("a directory containing a dropped copy must forbid collapse")
	}
	if droppedInside("charts/dupfix/crd/", ds) || droppedInside("config/crd/bases/", ds) {
		t.Fatal("a directory without a dropped copy must not be blocked")
	}
	paths, _ := targetPaths(t, res.A)
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			t.Fatalf("a derived target lists directory %q", p)
		}
	}
}

// --- wrong-target swap and comparator mutation ---------------------------

func TestWrongTargetSwapDiffers(t *testing.T) {
	x := mustGenerate(t, dupInput(dupSource(nil), nil, true))
	ySrc := dupSource(func(_ string, m *memTree) {
		delete(m.files, dupGadget)
		m.files["config/crd/bases/other.yaml"] = []byte(mkCRD("Other", crdOpts{}))
	})
	y := mustGenerate(t, dupInput(ySrc, nil, true))
	diffs, err := Diff(x.A, y.A)
	if err != nil || len(diffs) == 0 {
		t.Fatalf("the derived paths of one fixture must differ from the other: %v %v", diffs, err)
	}
}

// weaken replaces the comparator with one that ignores a top-level part.
func weaken(t *testing.T, ignore string) {
	old := crdsEqual
	crdsEqual = func(a, b crd) bool {
		if a.SpecDigest == "" || b.SpecDigest == "" {
			return false
		}
		for k, v := range a.SpecParts {
			if k != ignore && b.SpecParts[k] != v {
				return false
			}
		}
		for k, v := range b.SpecParts {
			if k != ignore && a.SpecParts[k] != v {
				return false
			}
		}
		return true
	}
	t.Cleanup(func() { crdsEqual = old })
}

func TestComparatorMutationIsCaught(t *testing.T) {
	cases := []struct {
		name, ignore, seed string
	}{
		{"storage and schema live in versions", "spec.versions", "S1 storage flag flipped in B at the newest tag"},
		{"schema", "spec.versions", "S2 one schema property changed in B"},
		{"conversion", "spec.conversion", "S3 conversion webhook only in B"},
		{"scope", "spec.scope", "S15 scope differs"},
		{"names", "spec.names", "S17 names differ"},
		{"apiVersion", "apiVersion", "S16 apiVersion differs"},
	}
	all := map[string]seed{}
	for _, sd := range seeds() {
		all[sd.name] = sd
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sd, ok := all[c.seed]
			if !ok {
				t.Fatalf("no seed %q", c.seed)
			}
			// Unmutated comparator: the seed stops.
			if _, err := Generate(dupInput(dupSource(sd.mutate), nil, true)); !hasStopCode(err, StopDuplicateCRDDiffers) {
				t.Fatalf("seed must stop with a difference, got %v", err)
			}
			// Weakened comparator: the seed would pass, so the seed test
			// above (which demands the stop) fails for a broken mechanism.
			weaken(t, c.ignore)
			if res, err := Generate(dupInput(dupSource(sd.mutate), nil, true)); err != nil || res == nil {
				t.Fatalf("with the comparator weakened the seed must slip through (proves it bites): %v", err)
			}
		})
	}
}

// A disabled comparator that says everything is equal must also be caught.
func TestEverythingEqualMutationIsCaught(t *testing.T) {
	old := crdsEqual
	crdsEqual = func(a, b crd) bool { return true }
	t.Cleanup(func() { crdsEqual = old })
	for _, sd := range seeds() {
		if sd.wantCode == StopDuplicateCRDDiffers {
			if _, err := Generate(dupInput(dupSource(sd.mutate), nil, true)); err != nil {
				t.Fatalf("%s: with every pair equal the seed must slip through: %v", sd.name, err)
			}
		}
	}
}

// --- canonical spec digest ----------------------------------------------

func digestOf(t *testing.T, doc string) string {
	t.Helper()
	cs, err := parseCRDs([]byte(doc))
	if err != nil || len(cs) != 1 {
		t.Fatalf("parse: %v %v", cs, err)
	}
	return cs[0].SpecDigest
}

func TestSpecDigestStructural(t *testing.T) {
	base := mkCRD("Widget", crdOpts{})
	if digestOf(t, base) == "" {
		t.Fatal("no digest")
	}
	if digestOf(t, base) != digestOf(t, mkCRD("Widget", crdOpts{label: "x"})) {
		t.Fatal("metadata must not matter")
	}
	// Key order does not matter.
	reordered := strings.Replace(base, "  group: dup.example.test\n  names:\n    kind: Widget\n    plural: widgets\n", "  names:\n    plural: widgets\n    kind: Widget\n  group: dup.example.test\n", 1)
	if reordered == base || digestOf(t, reordered) != digestOf(t, base) {
		t.Fatal("key order must not matter")
	}
	// No normalising of scalar types.
	a := mkCRD("Widget", crdOpts{spec: "  x: 1\n"})
	for _, alt := range []string{"1.0", `"1"`, "true"} {
		if digestOf(t, a) == digestOf(t, mkCRD("Widget", crdOpts{spec: "  x: " + alt + "\n"})) {
			t.Fatalf("1 and %s must differ", alt)
		}
	}
	// Different field, scope, apiVersion differ.
	for _, o := range []crdOpts{{scope: "Cluster"}, {conversion: true}, {extraProp: "p"}, {storageFlip: true}, {apiVersion: "apiextensions.k8s.io/v1beta1"}} {
		if digestOf(t, base) == digestOf(t, mkCRD("Widget", o)) {
			t.Fatalf("%+v must change the digest", o)
		}
	}
	// A parse that cannot be canonicalised is never equal.
	if d, _ := specDigest("v1", []any{"x"}); d != "" {
		t.Fatal("non-map spec must have no digest")
	}
	if d, _ := specDigest("v1", map[string]any{"a": map[any]any{1: 2}}); d != "" {
		t.Fatal("unsupported value must have no digest")
	}
	if crdsEqual(crd{}, crd{}) {
		t.Fatal("two empty digests are not equal")
	}
}

func TestSpecDigestKeepsOldDecodeBehaviour(t *testing.T) {
	// Errors of the typed decode are unchanged by the second decode.
	if _, err := parseCRDs([]byte("kind: CustomResourceDefinition\nspec:\n  group: a\n  names:\n    kind: B\n")); err == nil || !strings.Contains(err.Error(), "spec.versions") {
		t.Fatalf("%v", err)
	}
	if _, err := parseCRDs([]byte("kind: CustomResourceDefinition\nspec: 5\n")); err == nil {
		t.Fatal("a scalar spec is a partial shape")
	}
}

// --- rank table pin ------------------------------------------------------

func TestRankTablePinned(t *testing.T) {
	cases := map[string]int{
		"config/crd/bases/a.yaml":          rankPlainDir,
		"config/crds/a.yaml":               rankPlainDir,
		"deploy/crds/a.yaml":               rankPlainDir,
		"charts/x/crds/a.yaml":             rankChart,
		"helm/x/crds/a.yaml":               rankChart,
		"x/files/a.yaml":                   rankChart,
		"charts/x/templates/a.yaml":        rankTemplate,
		"bundle/manifests/a.yaml":          rankBundle,
		"config/olm/1.0/manifests/a.yaml":  rankBundle,
		"deploy/olm-catalog/1.0/a.yaml":    rankBundle,
		"charts/x/templates/bundle/a.yaml": rankBundle,
	}
	for p, want := range cases {
		if got := rankClass(p); got != want {
			t.Errorf("rankClass(%q)=%d want %d", p, got, want)
		}
	}
	if rankPlainDir >= rankChart || rankChart >= rankTemplate || rankTemplate >= rankBundle {
		t.Fatal("rank order changed")
	}
	mk := func(p string, multi bool) occurrence { return occurrence{path: p, multi: multi} }
	order := []occurrence{mk("z/single.yaml", false), mk("a/multi.yaml", true)}
	if !rankLess(order[0], order[1]) || rankLess(order[1], order[0]) {
		t.Fatal("single-definition files must outrank multi-definition files")
	}
	if !rankLess(mk("config/crd/bases/x.yaml", false), mk("charts/c/crds/x.yaml", false)) ||
		!rankLess(mk("charts/c/crds/x.yaml", false), mk("charts/c/templates/x.yaml", false)) ||
		!rankLess(mk("charts/c/templates/x.yaml", false), mk("bundle/manifests/x.yaml", false)) ||
		!rankLess(mk("a/x.yaml", false), mk("b/x.yaml", false)) {
		t.Fatal("rank table or path tie-break changed")
	}
}

// --- derived-mode unreadable file (test U) -------------------------------

func TestDerivedModeUnlistedUnreadableFileStops(t *testing.T) {
	fs := []*finding{
		{Path: dupA, CRDs: []crd{{Group: "dup.example.test", Kind: "Widget", Versions: []string{"v1:true:true"}}}},
		{Path: "other/broken.yaml", Unreadable: "template syntax"},
	}
	idx := customresources.DefaultIndex()
	rules := &Rules{Schema: RulesSchema, InstallPaths: []InstallPathRule{{Path: dupA, Reason: derivedReason, Evidence: "e"}}}
	r := classify("v1.0.0", "c", fs, rules, "dupfix", idx, nil)
	if len(r.stops) != 0 {
		t.Fatalf("hand rules keep the old behaviour: %+v", r.stops)
	}
	rules.deriveStrict = true
	r = classify("v1.0.0", "c", fs, rules, "dupfix", idx, nil)
	if len(r.stops) != 1 || r.stops[0].Code != StopUnreadableShape || r.stops[0].Subject != "other/broken.yaml" {
		t.Fatalf("derived mode must stop on an unlisted unreadable file: %+v", r.stops)
	}
}

// --- closure unit tests on the pure function ----------------------------

func mkInc(path string, cs ...crd) *inclusion { return &inclusion{Path: path, CRDs: cs} }

func unitCRD(kind, spec string) crd {
	return crd{Group: "g.example.test", Kind: kind, SpecDigest: spec, SpecParts: map[string]string{"spec.versions": spec}}
}

func TestResolveDuplicatesClosure(t *testing.T) {
	w := unitCRD("W", "sha256:aa")
	o := unitCRD("O", "sha256:bb")
	tf := func(tag string, files ...*inclusion) tagFiles {
		m := map[string]*inclusion{}
		for _, f := range files {
			m[f.Path] = f
		}
		return tagFiles{Tag: tag, Included: m}
	}
	// Equal everywhere: derived.
	d, stops := resolveDuplicates([]tagFiles{
		tf("v1.0.0", mkInc("a/w.yaml", w), mkInc("z/bundle/w.yaml", w)),
		tf("v1.1.0", mkInc("a/w.yaml", w), mkInc("z/bundle/w.yaml", w)),
	})
	if d == nil || len(stops[0])+len(stops[1]) != 0 || fmt.Sprint(d.Dropped) != "[z/bundle/w.yaml]" {
		t.Fatalf("%+v %+v", d, stops)
	}
	// Multi-definition file loses; its second definition has no kept copy.
	_, stops = resolveDuplicates([]tagFiles{
		tf("v1.0.0", mkInc("a/w.yaml", w), mkInc("b/all.yaml", w, o)),
		tf("v1.1.0", mkInc("a/w.yaml", w), mkInc("b/all.yaml", w, o)),
	})
	if len(stops[1]) == 0 || stops[1][0].Code != StopDuplicateCRDUnresolvable {
		t.Fatalf("%+v", stops)
	}
	// The same multi file kept for one key and dropped for another.
	w2 := unitCRD("W2", "sha256:cc")
	_, stops = resolveDuplicates([]tagFiles{
		tf("v1.0.0", mkInc("a/one.yaml", w, w2), mkInc("b/two.yaml", w), mkInc("d/four.yaml", w2, o)),
	})
	if len(stops[0]) == 0 {
		t.Fatal("a file that is both source and dropped copy must stop")
	}
	// An older tag where the kept copy does not hold the key.
	_, stops = resolveDuplicates([]tagFiles{
		tf("v1.0.0", mkInc("z/bundle/w.yaml", w)),
		tf("v1.1.0", mkInc("a/w.yaml", w), mkInc("z/bundle/w.yaml", w)),
	})
	if len(stops[0]) == 0 || stops[0][0].Code != StopDuplicateCRDNoCommonSource || len(stops[1]) != 0 {
		t.Fatalf("%+v", stops)
	}
	// Empty digest is never equal.
	e := unitCRD("W", "")
	_, stops = resolveDuplicates([]tagFiles{tf("v1.0.0", mkInc("a/w.yaml", e), mkInc("b/w.yaml", e))})
	if len(stops[0]) == 0 || stops[0][0].Code != StopDuplicateCRDDiffers {
		t.Fatalf("%+v", stops)
	}
	// Extra plain-pass file at an older tag is not silently read or ignored.
	_, stops = resolveDuplicates([]tagFiles{
		tf("v1.0.0", mkInc("a/w.yaml", w), mkInc("b/w.yaml", w), mkInc("c/extra.yaml", o)),
		tf("v1.1.0", mkInc("a/w.yaml", w), mkInc("b/w.yaml", w)),
	})
	if len(stops[0]) == 0 || len(stops[1]) != 0 {
		t.Fatalf("%+v", stops)
	}
}

// --- output allowlist ----------------------------------------------------

func TestDeriveCLIWritesOnlyTheDraftFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	open := func(string) Source { return dupSource(nil) }
	args := []string{"generate", "--dir", "x", "--slug", "dupfix", "--name", "Dupfix", "--repo", "github.com/example/dupfix", "--tags", strings.Join(dupTags, ","), "--out", out}
	var so, se bytes.Buffer
	if code := run(args, &so, &se, open); code != 1 || !strings.Contains(so.String(), "STOP duplicate-crd") {
		t.Fatalf("flag off: code %d: %s %s", code, so.String(), se.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("no output on a stop")
	}
	so.Reset()
	if code := run(append(args, "--derive-duplicate-sources"), &so, &se, open); code != 0 {
		t.Fatalf("code %d: %s %s", code, so.String(), se.String())
	}
	var got []string
	_ = filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(out, p)
			got = append(got, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(got)
	want := "[a/table-row.json a/target-dupfix.json b/changelog.md b/target-dupfix.json report.json]"
	if fmt.Sprint(got) != want {
		t.Fatalf("output set %v, want %s", got, want)
	}
	// A failing derivation writes nothing.
	out2 := filepath.Join(t.TempDir(), "out2")
	bad := func(string) Source {
		return dupSource(setAt(map[string]bool{"v1.3.0": true}, func(m *memTree) { m.files[dupB] = []byte(mkCRD("Widget", crdOpts{storageFlip: true})) }))
	}
	so.Reset()
	args2 := append([]string{}, args...)
	args2[len(args2)-1] = out2
	if code := run(append(args2, "--derive-duplicate-sources"), &so, &se, bad); code != 1 || !strings.Contains(so.String(), "STOP duplicate-crd-differs") {
		t.Fatalf("code %d: %s", code, so.String())
	}
	if _, err := os.Stat(out2); err == nil {
		t.Fatal("a failed derivation wrote output")
	}
}

// --- source guard --------------------------------------------------------

// The package must not write below the extractor package: no non-test file
// of the generator names a write into extract/crdversions.
func TestNoWriteIntoExtractor(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, _ := os.ReadFile(e.Name())
		s := string(b)
		if strings.Contains(s, "extract/crdversions/") && !strings.Contains(s, "internal/extract/crdversions\"") {
			t.Errorf("%s names a path below extract/crdversions", e.Name())
		}
	}
}

// --- directory collapse wiring (M1) --------------------------------------

func collapseInputFor(dir string, files []string, tags ...string) []collapseTag {
	var out []collapseTag
	for _, tg := range tags {
		ct := collapseTag{Tag: tg}
		for _, f := range files {
			p := dir + "/" + f
			ct.Entries = append(ct.Entries, Entry{Path: p})
			ct.Defs = append(ct.Defs, defFile{Path: p})
			ct.Included = append(ct.Included, includedFile{Path: p})
		}
		out = append(out, ct)
	}
	return out
}

func TestCollapseRefusesDirectoryWithDroppedCopy(t *testing.T) {
	in := collapseInputFor("config/crd/bases", []string{"a.yaml"}, "v1", "v2")
	// The dropped copy is invisible to the tag data on purpose, so only the
	// dropped-copy wiring can refuse the directory.
	if dirs, stops := collapseDirsDropping(in, nil); len(stops) != 0 || len(dirs) != 1 {
		t.Fatalf("control: %v %v", dirs, stops)
	}
	dirs, stops := collapseDirsDropping(in, []string{"config/crd/bases/copy.yaml"})
	if dirs != nil || len(stops) == 0 || stops[0].Code != StopDirUnsupported || !strings.Contains(stops[0].Detail, "dropped duplicate copy") {
		t.Fatalf("a dropped copy inside the directory must refuse the collapse: %v %v", dirs, stops)
	}
	// A dropped copy elsewhere does not block.
	if dirs, stops := collapseDirsDropping(in, []string{"charts/x/crds/copy.yaml"}); len(stops) != 0 || len(dirs) != 1 {
		t.Fatalf("%v %v", dirs, stops)
	}
}

func TestDeriveWithCollapse(t *testing.T) {
	in := dupInput(dupSource(nil), nil, true)
	in.CollapseDirectories = true
	res := mustGenerate(t, in)
	paths, _ := targetPaths(t, res.A)
	if fmt.Sprint(paths) != "[config/crd/bases]" && fmt.Sprint(paths) != "[config/crd/bases/]" {
		t.Fatalf("paths %v", paths)
	}
	if fmt.Sprint(res.DroppedCopies) != "["+dupB+"]" {
		t.Fatalf("dropped %v", res.DroppedCopies)
	}
	// An equal copy in the same directory as the kept one: the collapse is
	// refused by the dropped-copy check (not silently widened).
	in2 := dupInput(dupSource(func(_ string, m *memTree) {
		delete(m.files, dupB)
		m.files["config/crd/bases/zz_copy.yaml"] = []byte(mkCRD("Widget", crdOpts{}))
	}), nil, true)
	in2.CollapseDirectories = true
	res2, err := Generate(in2)
	if err == nil || res2 != nil {
		t.Fatalf("collapse must refuse: %v", err)
	}
	if !strings.Contains(stopList(err), "dropped duplicate copy") {
		t.Fatalf("refusal must come from the dropped-copy wiring: %s", stopList(err))
	}
	// Exact files without the collapse flag still work and drop the copy.
	in3 := dupInput(dupSource(func(_ string, m *memTree) {
		delete(m.files, dupB)
		m.files["config/crd/bases/zz_copy.yaml"] = []byte(mkCRD("Widget", crdOpts{}))
	}), nil, true)
	res3 := mustGenerate(t, in3)
	if p, _ := targetPaths(t, res3.A); strings.Contains(fmt.Sprint(p), "zz_copy") {
		t.Fatalf("dropped copy listed: %v", p)
	}
}
