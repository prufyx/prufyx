// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

var collapseTags = []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"}

func crdText(group, kind string) []byte {
	return []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + group + "\n  names:\n    kind: " + kind + "\n  versions:\n  - name: v1\n    served: true\n    storage: true\n")
}

// collapseBase is the tree every tag starts from: one directory, two CRDs.
func collapseBase() *memTree {
	m := newMemTree()
	m.files["config/crd/a.yaml"] = crdText("demo.example.invalid", "Alpha")
	m.files["config/crd/b.yaml"] = crdText("demo.example.invalid", "Beta")
	m.files["README.md"] = []byte("readme\n")
	return m
}

func collapseSource(mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range collapseTags {
		m := collapseBase()
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func collapseInputFor(src Source, collapse bool) Input {
	return Input{Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf", Tags: collapseTags, Source: src, CollapseDirectories: collapse}
}

const wantCollapsedA = `{
  "schema": "prufyx.io/crd-version-target/v1",
  "target": {
    "project": "demo",
    "name": "Demo",
    "repo": "github.com/example/demo",
    "component": "pkg:github/example/demo",
    "factProject": "demo",
    "tagPrefixes": ["v"],
    "minFrom": "1.0",
    "paths": [
      {"path": "config/crd", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}
    ],
    "exclude": []
  }
}
`

func wantCollapseStop(t *testing.T, label string, res *Result, err error, code string) {
	t.Helper()
	var se *StopError
	if !errors.As(err, &se) || res != nil {
		t.Fatalf("%s: want typed stop %s and no result, got res=%v err=%v", label, code, res != nil, err)
	}
	for _, s := range se.Stops {
		if s.Code == code {
			return
		}
	}
	t.Fatalf("%s: want stop %s, got %v", label, code, se.Stops)
}

func TestCollapsePositiveIsByteEqualAndDeterministic(t *testing.T) {
	res := mustGenerate(t, collapseInputFor(collapseSource(nil), true))
	wantCanonicalEqual(t, "A", res.A, []byte(wantCollapsedA))
	if res.Report.Representation != "directory" || len(res.Report.Directories) != 1 || strings.Join(res.Report.Directories[0].Files, ",") != "a.yaml,b.yaml" {
		t.Fatalf("report does not name the directory and its files: %+v", res.Report)
	}
	again := mustGenerate(t, collapseInputFor(collapseSource(nil), true))
	if !bytes.Equal(res.A, again.A) || !bytes.Equal(res.B, again.B) {
		t.Fatal("two runs differ")
	}
	r1, _ := marshal(res.Report)
	r2, _ := marshal(again.Report)
	if !bytes.Equal(r1, r2) {
		t.Fatal("two reports differ")
	}
	// Canonical round-trips the directory form.
	c, err := Canonical(res.A)
	if err != nil || !bytes.Equal(c, res.A) {
		t.Fatalf("Canonical does not round-trip the directory form: %v", err)
	}
}

func TestCollapseOffByDefaultKeepsExactFiles(t *testing.T) {
	res := mustGenerate(t, collapseInputFor(collapseSource(nil), false))
	if !strings.Contains(string(res.A), `{"path": "config/crd/a.yaml"}`) || strings.Contains(string(res.A), "directory") {
		t.Fatalf("default output changed:\n%s", res.A)
	}
	if res.Report.Representation != "" || res.Report.Directories != nil {
		t.Fatal("report names a representation without the option")
	}
}

// The facts digest is a function of the file set only: collapsing changes the
// representation, never the facts.
func TestCollapseKeepsFactsDigest(t *testing.T) {
	a := mustGenerate(t, collapseInputFor(collapseSource(nil), false))
	b := mustGenerate(t, collapseInputFor(collapseSource(nil), true))
	if a.Report.FactsDigest != b.Report.FactsDigest || !bytes.Equal(a.TableRow, b.TableRow) {
		t.Fatal("collapse changed the facts of the run")
	}
}

// loaderRead replays the directory read of the extractor (listFiles) with the
// match and guard the loader compiled from the emitted JSON: the file paths it
// reads, or the error that makes the inventory incomplete.
func loaderRead(spec crdversions.PathSpec, entries []Entry) ([]string, error) {
	var out []string
	for _, e := range entries {
		if path.Dir(e.Path) != spec.Path {
			continue
		}
		name := path.Base(e.Path)
		if !spec.Match.MatchString(name) {
			if spec.Guard.MatchString(name) {
				return nil, fmt.Errorf("%s looks like a CRD manifest but is not read", e.Path)
			}
			continue
		}
		if e.IsLink {
			return nil, fmt.Errorf("%s is a symbolic link", e.Path)
		}
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out, nil
}

func loadEmitted(t *testing.T, slug string, raw []byte) crdversions.Target {
	t.Helper()
	tg, err := crdversions.LoadTarget(crdversions.TargetFileName(slug), raw)
	if err != nil {
		t.Fatalf("the loader refuses the emitted target: %v\n%s", err, raw)
	}
	return tg
}

func exactSet(t *testing.T, src memSource) []string {
	t.Helper()
	res := mustGenerate(t, collapseInputFor(src, false))
	tg := loadEmitted(t, "demo", res.A)
	var out []string
	for _, p := range tg.Paths {
		out = append(out, p.Path)
	}
	sort.Strings(out)
	return out
}

// Representation neutrality: at every window tag the directory entry, read the
// way the loader reads it, selects exactly the files of the exact-file target.
func TestCollapseIsRepresentationNeutral(t *testing.T) {
	src := collapseSource(nil)
	res := mustGenerate(t, collapseInputFor(src, true))
	tg := loadEmitted(t, "demo", res.A)
	if len(tg.Paths) != 1 || !tg.Paths[0].Dir || tg.Paths[0].Recursive || tg.Paths[0].Optional {
		t.Fatalf("unexpected loaded paths %+v", tg.Paths)
	}
	// The loader's compiled patterns are the generator's literals.
	if tg.Paths[0].Match.String() != DefaultDirMatch || tg.Paths[0].Guard.String() != DefaultDirGuard {
		t.Fatal("loader patterns differ from the generator literals")
	}
	want := exactSet(t, src)
	for _, tag := range collapseTags {
		entries, _ := src.trees[tag].Entries()
		got, err := loaderRead(tg.Paths[0], entries)
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s: directory reads %v, exact files are %v", tag, got, want)
		}
	}
}

type negCase struct {
	name   string
	mutate func(tag string, m *memTree)
	code   string
	// neutral says the loader read of the default pair must differ from the
	// exact-file set (or fail), which is why collapsing would be wrong.
	neutral bool
}

func negCases() []negCase {
	return []negCase{
		{"non-crd yaml matched by the default match", func(tag string, m *memTree) {
			if tag == "v1.1.0" {
				m.files["config/crd/kustomization.yaml"] = []byte("resources: []\n")
			}
		}, StopDirMixed, true},
		{"crd file outside the default match", func(tag string, m *memTree) {
			m.files["config/crd/.hidden.yaml"] = crdText("demo.example.invalid", "Gamma")
		}, StopDirMatchNondefault, true},
		{"crd file with an upper-case extension", func(tag string, m *memTree) {
			m.files["config/crd/c.YAML"] = crdText("demo.example.invalid", "Gamma")
		}, StopDirMatchNondefault, true},
		{"guard-only file at one old tag", func(tag string, m *memTree) {
			if tag == "v1.0.0" {
				m.files["config/crd/crds.md"] = []byte("notes\n")
			}
		}, StopDirIncomplete, true},
		{"guard-only file at the newest tag", func(tag string, m *memTree) {
			if tag == "v1.3.0" {
				m.files["config/crd/crd-notes.txt"] = []byte("notes\n")
			}
		}, StopDirIncomplete, true},
		{"crd in a subdirectory", func(tag string, m *memTree) {
			m.files["config/crd/sub/c.yaml"] = crdText("demo.example.invalid", "Gamma")
		}, StopDirSubdir, true},
		{"symbolic link the loader would refuse", func(tag string, m *memTree) {
			m.links["config/crd/link.yaml"] = "a.yaml"
		}, StopDirIncomplete, true},
		{"crd file at the repository root", func(tag string, m *memTree) {
			m.files["root.yaml"] = crdText("demo.example.invalid", "Gamma")
		}, StopDirUnsupported, false},
	}
}

func TestCollapseTypedStopsFailClosed(t *testing.T) {
	for _, c := range negCases() {
		t.Run(c.name, func(t *testing.T) {
			src := collapseSource(c.mutate)
			res, err := Generate(collapseInputFor(src, true))
			wantCollapseStop(t, c.name, res, err, c.code)
			if !c.neutral {
				return
			}
			// Why collapsing is wrong: the exact-file run still succeeds (the
			// stop is the collapse's, not the scan's) and the default pair
			// reads another set or an incomplete inventory.
			ex, eerr := Generate(collapseInputFor(src, false))
			if eerr != nil {
				return // the exact run stops too: even stricter
			}
			spec := crdversions.PathSpec{Path: "config/crd", Dir: true, Match: dirMatchRE, Guard: dirGuardRE}
			want := map[string]bool{}
			for _, p := range loadEmitted(t, "demo", ex.A).Paths {
				want[p.Path] = true
			}
			differ := false
			for _, tag := range collapseTags {
				entries, _ := src.trees[tag].Entries()
				got, lerr := loaderRead(spec, entries)
				if lerr != nil || len(got) != len(want) {
					differ = true
					break
				}
				for _, g := range got {
					if !want[g] {
						differ = true
					}
				}
			}
			if !differ {
				t.Fatal("the stop was not needed: a directory entry would have read the exact file set")
			}
		})
	}
}

func TestCollapseUnsupportedInputsStop(t *testing.T) {
	src := collapseSource(nil)
	rules := map[string]*Rules{
		"exclusion": {Schema: RulesSchema, Exclusions: []ExclusionRule{{Class: ClassExactFile, Path: "x.yaml", Reason: "r", Evidence: "e"}}},
		"optional":  {Schema: RulesSchema, InstallPaths: []InstallPathRule{{Path: "config/crd/a.yaml", Optional: true}}},
		"ranged":    {Schema: RulesSchema, InstallPaths: []InstallPathRule{{Path: "config/crd/a.yaml", Role: "r", FromTag: "v1.0.0"}}},
		"filter":    {Schema: RulesSchema, InstallPaths: []InstallPathRule{{Path: "config/crd/"}}, PathFilter: []PathFilterRule{{Glob: "config/crd/a.yaml", ExpectFiles: 1}}},
	}
	for name, r := range rules {
		in := collapseInputFor(src, true)
		in.Rules = r
		res, err := Generate(in)
		wantCollapseStop(t, name, res, err, StopDirUnsupported)
	}
	in := collapseInputFor(src, true)
	in.RangeCheckTags = []string{"v1.0.1"}
	res, err := Generate(in)
	wantCollapseStop(t, "range-check-tags", res, err, StopDirUnsupported)
}

// A file missing at an old tag shrinks the window (existing behaviour); the
// collapse is then decided on the shrunk window and still reads the same set.
func TestCollapseOnShrunkWindowStillNeutral(t *testing.T) {
	src := collapseSource(func(tag string, m *memTree) {
		if tag == "v1.0.0" {
			delete(m.files, "config/crd/b.yaml")
		}
	})
	res := mustGenerate(t, collapseInputFor(src, true))
	if res.Report.MinFrom != "1.1" || len(res.Report.Dropped) == 0 {
		t.Fatalf("window did not shrink: %+v", res.Report)
	}
	tg := loadEmitted(t, "demo", res.A)
	for _, tag := range collapseTags[1:] {
		entries, _ := src.trees[tag].Entries()
		got, err := loaderRead(tg.Paths[0], entries)
		if err != nil || strings.Join(got, ",") != "config/crd/a.yaml,config/crd/b.yaml" {
			t.Fatalf("%s: %v %v", tag, got, err)
		}
	}
}

// collapseDirs, pure: a set that differs between tags is a stop.
func TestCollapseDirsSetDiffersBetweenTags(t *testing.T) {
	mk := func(tag string, names ...string) collapseTag {
		ct := collapseTag{Tag: tag}
		for _, n := range names {
			p := "d/" + n
			ct.Entries = append(ct.Entries, Entry{Path: p})
			ct.Defs = append(ct.Defs, defFile{Path: p})
			ct.Included = append(ct.Included, includedFile{Path: p})
		}
		return ct
	}
	dirs, stops := collapseDirs([]collapseTag{mk("t1", "a.yaml"), mk("t2", "a.yaml", "b.yaml")})
	if dirs != nil || len(stops) == 0 || stops[0].Code != StopDirSetDiffers {
		t.Fatalf("want dir-set-differs, got %v %v", dirs, stops)
	}
	// Equal sets collapse.
	dirs, stops = collapseDirs([]collapseTag{mk("t1", "a.yaml", "b.yaml"), mk("t2", "b.yaml", "a.yaml")})
	if len(stops) != 0 || len(dirs) != 1 || dirs[0].Dir != "d" || strings.Join(dirs[0].Files, ",") != "a.yaml,b.yaml" {
		t.Fatalf("want one directory, got %v %v", dirs, stops)
	}
	// An install file outside every directory the newest tag names.
	a := mk("t1", "a.yaml")
	b := mk("t2", "a.yaml")
	b.Included = append(b.Included, includedFile{Path: "z/x.yaml"})
	if dirs, stops = collapseDirs([]collapseTag{a, b}); dirs != nil || len(stops) == 0 {
		t.Fatalf("an extra install file must stop: %v %v", dirs, stops)
	}
	// Test-like and link install files are never collapsed.
	for _, f := range []includedFile{{Path: "d/test/x.yaml"}, {Path: "d/x.yaml", Link: true}, {Path: "x.yaml"}} {
		ct := collapseTag{Tag: "t", Included: []includedFile{f}}
		if dirs, stops = collapseDirs([]collapseTag{ct, ct}); dirs != nil || len(stops) == 0 || stops[0].Code != StopDirUnsupported {
			t.Fatalf("%v must be unsupported: %v %v", f, dirs, stops)
		}
	}
	if dirs, stops = collapseDirs(nil); dirs != nil || len(stops) == 0 {
		t.Fatal("no tags must stop")
	}
	// Zero install files: never (nil, nil), which would read as exact files.
	empty := collapseTag{Tag: "t"}
	if dirs, stops = collapseDirs([]collapseTag{empty, empty}); dirs != nil || len(stops) == 0 || stops[0].Code != StopDirUnsupported {
		t.Fatalf("zero directories must be a typed stop: %v %v", dirs, stops)
	}
	// An extra install file only at an OLDER tag.
	old := mk("t1", "a.yaml")
	old.Included = append(old.Included, includedFile{Path: "e/x.yaml"})
	newer := mk("t2", "a.yaml")
	if dirs, stops = collapseDirs([]collapseTag{old, newer}); dirs != nil || len(stops) == 0 || stops[0].Code != StopDirSetDiffers {
		t.Fatalf("an older tag's extra install file must be dir-set-differs: %v %v", dirs, stops)
	}
	// A vendored install file is never collapsed.
	v := collapseTag{Tag: "t", Included: []includedFile{{Path: "d/vendor/x.yaml"}}}
	if dirs, stops = collapseDirs([]collapseTag{v, v}); dirs != nil || len(stops) == 0 || stops[0].Code != StopDirUnsupported {
		t.Fatalf("d/vendor/x.yaml must be unsupported: %v %v", dirs, stops)
	}
}

// Map order never reaches the output: many files, many runs.
func TestCollapseDeterministicOverManyFiles(t *testing.T) {
	src := collapseSource(func(tag string, m *memTree) {
		for i := 0; i < 25; i++ {
			m.files[fmt.Sprintf("config/crd/f%02d.yaml", i)] = crdText("demo.example.invalid", fmt.Sprintf("K%02d", i))
		}
	})
	first := mustGenerate(t, collapseInputFor(src, true))
	for i := 0; i < 8; i++ {
		again := mustGenerate(t, collapseInputFor(src, true))
		if !bytes.Equal(first.A, again.A) || !bytes.Equal(first.B, again.B) {
			t.Fatal("output differs between runs")
		}
	}
}

func collapseArgs(out string, extra ...string) []string {
	return append([]string{"generate", "--dir", "x", "--slug", "demo", "--name", "Demo", "--repo", "github.com/example/demo", "--tags", strings.Join(collapseTags, ","), "--out", out, "--collapse-directories"}, extra...)
}

// Seeded wrong targets: each must differ from the generated directory target;
// the run must exit non-zero for every seed and zero for the true file.
func TestCollapseSeededWrongTargetsExitNonZero(t *testing.T) {
	src := collapseSource(nil)
	open := func(string) Source { return src }
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(wantCollapsedA), 0o644); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	if code := run(collapseArgs(filepath.Join(t.TempDir(), "ok"), "--compare-a", good), &so, &se, open); code != 0 {
		t.Fatalf("the true target must pass: %d %s %s", code, so.String(), se.String())
	}
	seeds := map[string]string{
		"swapped directory name": strings.Replace(wantCollapsedA, `"config/crd"`, `"config/crds"`, 1),
		"widened to the parent":  strings.Replace(wantCollapsedA, `"config/crd"`, `"config"`, 1),
		"guard dropped":          strings.Replace(wantCollapsedA, `, "guard": "(?i)crd"`, `, "guard": "(?i)nothing"`, 1),
		"match widened":          strings.Replace(wantCollapsedA, `^[^.][^/]*\\.ya?ml$`, `^[^/]*$`, 1),
		"directory flag dropped": strings.Replace(wantCollapsedA, `{"path": "config/crd", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}`, `{"path": "config/crd"}`, 1),
		"exact files instead":    strings.Replace(wantCollapsedA, `{"path": "config/crd", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}`, `{"path": "config/crd/a.yaml"},`+"\n"+`      {"path": "config/crd/b.yaml"}`, 1),
		"other project":          strings.Replace(wantCollapsedA, `"project": "demo"`, `"project": "other"`, 1),
		"minFrom off by one":     strings.Replace(wantCollapsedA, `"minFrom": "1.0"`, `"minFrom": "1.1"`, 1),
		"extra attest":           strings.Replace(wantCollapsedA, `"minFrom": "1.0",`, `"minFrom": "1.0",`+"\n"+`    "attest": true,`, 1),
		"second directory entry": strings.Replace(wantCollapsedA, `"guard": "(?i)crd"}`, `"guard": "(?i)crd"},`+"\n"+`      {"path": "other", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}`, 1),
	}
	names := make([]string, 0, len(seeds))
	for n := range seeds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if seeds[n] == wantCollapsedA {
			t.Fatalf("seed %q did not change the file", n)
		}
		f := filepath.Join(dir, strings.ReplaceAll(n, " ", "-")+".json")
		if err := os.WriteFile(f, []byte(seeds[n]), 0o644); err != nil {
			t.Fatal(err)
		}
		so.Reset()
		se.Reset()
		out := filepath.Join(t.TempDir(), "seed")
		if code := run(collapseArgs(out, "--compare-a", f), &so, &se, open); code == 0 {
			t.Fatalf("seed %q reproduced the target", n)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("seed %q left a draft behind", n)
		}
	}
	// Project X's decision on project Y's tree: another directory name.
	other := collapseSource(func(tag string, m *memTree) {
		m.files["deploy/crds/a.yaml"] = m.files["config/crd/a.yaml"]
		m.files["deploy/crds/b.yaml"] = m.files["config/crd/b.yaml"]
		delete(m.files, "config/crd/a.yaml")
		delete(m.files, "config/crd/b.yaml")
	})
	so.Reset()
	se.Reset()
	if code := run(collapseArgs(filepath.Join(t.TempDir(), "y"), "--compare-a", good), &so, &se, func(string) Source { return other }); code == 0 {
		t.Fatal("project X's target passed on project Y's tree")
	}
}

// A stop exits 1 and writes nothing.
func TestCollapseStopExitsOneAndWritesNothing(t *testing.T) {
	for _, c := range negCases() {
		src := collapseSource(c.mutate)
		out := filepath.Join(t.TempDir(), "out")
		var so, se bytes.Buffer
		code := run(collapseArgs(out), &so, &se, func(string) Source { return src })
		if code != 1 || !strings.Contains(so.String(), "STOP "+c.code) {
			t.Fatalf("%s: exit %d, want 1 with %s\n%s%s", c.name, code, c.code, so.String(), se.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s: a draft was written", c.name)
		}
	}
}

// The directory form of the shipped targets round-trips byte for byte, and
// the generator's literals are the ones the shipped files carry.
func TestCollapseGoldenAgainstShippedTargets(t *testing.T) {
	for _, slug := range []string{"argo-cd", "awx-operator"} {
		raw := readFile(t, filepath.Join("testdata", "collapse", "target-"+slug+".json"))
		c, err := Canonical(raw)
		if err != nil || !bytes.Equal(c, raw) {
			t.Fatalf("%s: shipped bytes do not round-trip: %v", slug, err)
		}
		tg := loadEmitted(t, slug, raw)
		if len(tg.Paths) != 1 || tg.Paths[0].Match.String() != DefaultDirMatch || tg.Paths[0].Guard.String() != DefaultDirGuard {
			t.Fatalf("%s: shipped pattern is not the default pair", slug)
		}
	}
	// Every shipped directory-only target the generator can express is
	// reproduced; the count pins that the check is not silently skipping.
	files, _ := filepath.Glob("../../extract/crdversions/target-*.json")
	dirOnly := 0
	for _, f := range files {
		raw := readFile(t, f)
		c, err := Canonical(raw)
		if err != nil || (bytes.Contains(raw, []byte(`"directory": true`)) && !bytes.Contains(raw, []byte(`"exclude": []`))) {
			continue // exclusions are never emitted with directories
		}
		if !bytes.Equal(c, raw) {
			t.Errorf("%s: directory form differs from the shipped bytes", f)
		}
		if bytes.Contains(raw, []byte(`"directory": true`)) {
			dirOnly++
		}
	}
	if dirOnly < 20 {
		t.Fatalf("only %d shipped directory targets reproduced", dirOnly)
	}
}

func TestMarshalRefusesMalformedPathEntries(t *testing.T) {
	base := targetDoc{Schema: "prufyx.io/crd-version-target/v1", Target: targetBody{Project: "p", Name: "P", Repo: "github.com/o/p", Component: "c", FactProject: "p", TagPrefixes: []string{"v"}, MinFrom: "1.0", Exclude: []exclOut{}}}
	for name, p := range map[string]pathOut{
		"directory without match": {Path: "d", Directory: true, Guard: "(?i)crd"},
		"directory without guard": {Path: "d", Directory: true, Match: "x"},
		"file with a match":       {Path: "d/a.yaml", Match: "x"},
		"file with a guard":       {Path: "d/a.yaml", Guard: "x"},
	} {
		d := base
		d.Target.Paths = []pathOut{p}
		if _, err := marshalTarget(d); err == nil {
			t.Errorf("%s: marshal accepted it", name)
		}
	}
}

// Diff names a changed directory pattern.
func TestDiffSeesDirectoryPatterns(t *testing.T) {
	other := strings.Replace(wantCollapsedA, `(?i)crd`, `(?i)xyz`, 1)
	d, err := Diff([]byte(wantCollapsedA), []byte(other))
	if err != nil || len(d) == 0 {
		t.Fatalf("diff must see a changed guard: %v %v", d, err)
	}
	if d, err = Diff([]byte(wantCollapsedA), []byte(wantCollapsedA)); err != nil || len(d) != 0 {
		t.Fatalf("equal files must not differ: %v %v", d, err)
	}
}

// A run, collapse included, leaves every file under crdversions as it was, and
// no non-test source of this package other than cli.go, backtest.go (its --out report) and source.go (the
// local git reader) writes files or runs commands. This is a smoke check; the
// real guarantee is the PR diff path allowlist (nothing under
// extract/crdversions changes).
func TestCollapseDoesNotTouchExtractor(t *testing.T) {
	root := filepath.Join("..", "..", "extract", "crdversions")
	before := treeDigest(t, root)
	if len(before) == 0 {
		t.Fatal("crdversions snapshot is empty")
	}
	src := collapseSource(nil)
	var so, se bytes.Buffer
	if code := run(collapseArgs(filepath.Join(t.TempDir(), "o")), &so, &se, func(string) Source { return src }); code != 0 {
		t.Fatalf("run: %d %s %s", code, so.String(), se.String())
	}
	after := treeDigest(t, root)
	if len(after) != len(before) {
		t.Fatal("files under crdversions appeared or vanished")
	}
	for p, h := range before {
		if after[p] != h {
			t.Fatalf("%s under crdversions changed", p)
		}
	}
	writers := regexp.MustCompile(`(os|ioutil)\.(WriteFile|Create|OpenFile|Rename|Remove|RemoveAll|Mkdir|MkdirAll|MkdirTemp|Chmod|Symlink|CreateTemp)\(|exec\.Command`)
	bindingAllowed := regexp.MustCompile(`os\.MkdirTemp\(|os\.RemoveAll\(|exec\.CommandContext\(`)
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "cli.go" || n == "source.go" || n == "backtest.go" {
			continue
		}
		src := readFile(t, n)
		if n == "binding.go" {
			// The upstream binding runs git (the only exec in the package) from
			// an empty temporary directory it creates and removes. Exactly
			// those three calls are allowed there; any other writer is not.
			src = bindingAllowed.ReplaceAll(src, nil)
		}
		if writers.Match(src) {
			t.Errorf("%s writes to the file system; only cli.go's atomic --out writer may", n)
		}
	}
	if strings.Contains(string(readFile(t, "cli.go")), "crdversions") {
		t.Error("cli.go refers to the extractor directory")
	}
}

func treeDigest(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		out[filepath.ToSlash(p)] = hex.EncodeToString(h[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
