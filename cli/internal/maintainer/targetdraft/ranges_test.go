// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Version-ranged installPaths tests: a cluster-api-like repository whose core
// definition directory moves at the 1.14 line. Real small git repositories,
// offline.

var (
	rgRunTags = []string{"v1.9.8", "v1.10.3", "v1.11.2", "v1.12.1", "v1.13.8", "v1.14.4"}
	// rgAllTags adds patch tags of lines the run reads through another tag.
	rgAllTags = []string{"v1.9.8", "v1.10.3", "v1.11.2", "v1.12.0", "v1.12.1", "v1.13.3", "v1.13.8", "v1.14.4"}
)

const (
	rgOld   = "config/crd/bases/"
	rgNew   = "core/config/crd/bases/"
	rgBoot  = "bootstrap/kubeadm/config/crd/bases/"
	rgPlane = "controlplane/kubeadm/config/crd/bases/"
)

// rgFiles is the content of one tag: the core directory moved at v1.14.4 (or
// earlier where mid says so).
func rgFiles(tag string, movedFrom map[string]bool) map[string]string {
	dir := rgOld
	if movedFrom[tag] {
		dir = rgNew
	}
	return map[string]string{
		dir + "alpha.yaml":       ipCRD("widgets.example.test", "Alpha"),
		dir + "beta.yaml":        ipCRD("widgets.example.test", "Beta"),
		rgBoot + "boot.yaml":     ipCRD("widgets.example.test", "Boot"),
		rgPlane + "plane.yaml":   ipCRD("widgets.example.test", "Plane"),
		"docs/README.md":         "not a definition",
		"hack/tools/Makefile.md": "not a definition",
	}
}

// rgRepo builds a git repository with one commit and one tag per entry of
// rgAllTags; mutate may change the files of one tag.
func rgRepo(t *testing.T, moved []string, mutate func(tag string, files map[string]string)) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	mv := map[string]bool{}
	for _, m := range moved {
		mv[m] = true
	}
	dir := t.TempDir()
	gitOut(t, dir, "init", "-q")
	for _, tag := range rgAllTags {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.Name() != ".git" {
				if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
		files := rgFiles(tag, mv)
		if mutate != nil {
			mutate(tag, files)
		}
		for p, b := range files {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(b), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		gitOut(t, dir, "add", "-A")
		gitOut(t, dir, "commit", "-q", "--allow-empty", "-m", tag)
		gitOut(t, dir, "tag", tag)
	}
	return dir
}

func rgEntry(p, role, from, to string) string {
	s := `{"path":"` + p + `","reason":"r","evidence":"e"`
	if role != "" {
		s += `,"role":"` + role + `"`
	}
	if from != "" {
		s += `,"fromTag":"` + from + `"`
	}
	if to != "" {
		s += `,"toTag":"` + to + `"`
	}
	return s + `}`
}

func rgJSON(entries ...string) string {
	return `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[` + strings.Join(entries, ",") + `]}`
}

// rgGood is the rules text for the real move: the old directory through
// v1.13.8, the new one from v1.14.4.
func rgGood() []string {
	return []string{
		rgEntry(rgOld, "core-crds", "", "v1.13.8"),
		rgEntry(rgNew, "core-crds", "v1.14.4", ""),
		rgEntry(rgBoot, "bootstrap-kubeadm", "v1.9.8", "v1.14.4"),
		rgEntry(rgPlane, "controlplane-kubeadm", "", "v1.14.4"),
	}
}

func rgInput(src Source, js string, check ...string) (Input, error) {
	r, err := ParseRules([]byte(js))
	if err != nil {
		return Input{}, err
	}
	return Input{Slug: "widgets", Name: "Widgets", Repo: "github.com/example/widgets", Catalog: "cncf", Tags: rgRunTags, Source: src, Rules: r, RangeCheckTags: check}, nil
}

func rgGen(t *testing.T, repo, js string, check ...string) (*Result, error) {
	t.Helper()
	in, err := rgInput(GitSource{Dir: repo}, js, check...)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	return Generate(in)
}

func hasCode(err error, code string) bool {
	for _, c := range stopCodes(err) {
		if c == code {
			return true
		}
	}
	return false
}

func TestRangesMoveAtAMiddleTagWritesOneDraftWithBothDirs(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	res, err := rgGen(t, repo, rgJSON(rgGood()...))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, p := range []string{rgOld + "alpha.yaml", rgOld + "beta.yaml", rgNew + "alpha.yaml", rgNew + "beta.yaml", rgBoot + "boot.yaml", rgPlane + "plane.yaml"} {
		if !bytes.Contains(res.A, []byte(`{"path": "`+p+`"}`)) {
			t.Errorf("half A misses %s:\n%s", p, res.A)
		}
	}
	if n := strings.Count(string(res.A), `{"path": `); n != 6 {
		t.Fatalf("half A lists %d paths, want 6", n)
	}
	// The target format is unchanged: the canonical re-encoding is the same.
	if c, err := Canonical(res.A); err != nil || !bytes.Equal(c, res.A) {
		t.Fatalf("target format changed: %v", err)
	}
	if len(res.Report.Tags) != 6 || len(res.Report.Dropped) != 0 || res.Report.MinFrom != "1.9" {
		t.Fatalf("window: %d tags, dropped %v, minFrom %s", len(res.Report.Tags), res.Report.Dropped, res.Report.MinFrom)
	}
	if res.Report.CRDCount != 4 {
		t.Fatalf("want 4 CRDs, got %d", res.Report.CRDCount)
	}
	// Per tag, the selected ranged entry of each role, sorted.
	if len(res.Report.RangedPaths) != 6*3 {
		t.Fatalf("ranged facts: %+v", res.Report.RangedPaths)
	}
	var core []string
	for _, f := range res.Report.RangedPaths {
		if f.Role == "core-crds" {
			core = append(core, f.Tag+"="+f.Path)
		}
	}
	want := []string{"v1.9.8=" + rgOld, "v1.10.3=" + rgOld, "v1.11.2=" + rgOld, "v1.12.1=" + rgOld, "v1.13.8=" + rgOld, "v1.14.4=" + rgNew}
	if strings.Join(core, "|") != strings.Join(want, "|") {
		t.Fatalf("core-crds selection %v, want %v", core, want)
	}
	// The group source URL is a path of the newest commit, never of the old
	// directory.
	if strings.Contains(string(res.TableRow), "/blob/"+res.Report.Tags[5].Commit+"/"+rgOld) {
		t.Fatalf("row source is a path that the newest tag does not have:\n%s", res.TableRow)
	}
}

func TestRangesBoundaryCheckProvesNeitherDirOnTheWrongSide(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	// All tags of every line: the generator reads every one with the same
	// presence and absence rule.
	res, err := rgGen(t, repo, rgJSON(rgGood()...), rgAllTags...)
	if err != nil {
		t.Fatalf("generate with --range-check-tags: %v", err)
	}
	if len(res.Report.RangeCheckedTags) != len(rgAllTags) {
		t.Fatalf("checked tags %v", res.Report.RangeCheckedTags)
	}
	plain, err := rgGen(t, repo, rgJSON(rgGood()...))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Report.FactsDigest == res.Report.FactsDigest {
		t.Fatal("the facts digest does not cover the range check tags")
	}
}

// SEEDED TEST: a boundary shifted by one tag in the rules must stop, and the
// run must write no draft.
func TestRangesSeededBoundaryShiftedByOneTagIsCaught(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	// The real move is v1.13.8 -> v1.14.4. Shifted one tag early: the new
	// directory is claimed from v1.13.8, the old one only through v1.12.1.
	early := []string{
		rgEntry(rgOld, "core-crds", "", "v1.12.1"),
		rgEntry(rgNew, "core-crds", "v1.13.8", ""),
		rgEntry(rgBoot, "bootstrap-kubeadm", "v1.9.8", "v1.14.4"),
		rgEntry(rgPlane, "controlplane-kubeadm", "", "v1.14.4"),
	}
	res, err := rgGen(t, repo, rgJSON(early...))
	if res != nil || err == nil {
		t.Fatal("a boundary shifted one tag early was accepted")
	}
	if !hasCode(err, StopRangeAbsentInRange) || !hasCode(err, StopRangePresentOutRange) {
		t.Fatalf("want absent-in-range and present-out-of-range, got %v: %v", stopCodes(err), err)
	}
	// One tag late: the old directory is claimed through v1.14.4.
	late := []string{
		rgEntry(rgOld, "core-crds", "", "v1.14.4"),
		rgEntry(rgNew, "core-crds", "v1.14.4", ""),
		rgEntry(rgBoot, "bootstrap-kubeadm", "v1.9.8", "v1.14.4"),
		rgEntry(rgPlane, "controlplane-kubeadm", "", "v1.14.4"),
	}
	if _, err := rgGen(t, repo, rgJSON(late...)); !hasCode(err, StopRangeOverlap) {
		t.Fatalf("overlapping late boundary: %v", stopCodes(err))
	}
	// Contiguous but wrong by one tag late: old through v1.14.4, new after
	// the window end is not expressible; a boundary at v1.13.8/v1.14.4 with
	// the new entry starting at the NEXT tag is a gap.
	lateGap := []string{
		rgEntry(rgOld, "core-crds", "", "v1.12.1"),
		rgEntry(rgNew, "core-crds", "v1.14.4", ""),
		rgEntry(rgBoot, "bootstrap-kubeadm", "v1.9.8", "v1.14.4"),
		rgEntry(rgPlane, "controlplane-kubeadm", "", "v1.14.4"),
	}
	if _, err := rgGen(t, repo, rgJSON(lateGap...)); !hasCode(err, StopRangeGap) {
		t.Fatalf("gap boundary: %v", stopCodes(err))
	}
}

func TestRangesDroppingAModuleIsCaughtByCompare(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	open := func(string) Source { return GitSource{Dir: repo} }
	tmp := t.TempDir()
	rulesFile := func(name string, entries []string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(rgJSON(entries...)), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	args := func(rules, out string, extra ...string) []string {
		return append([]string{"generate", "--dir", repo, "--slug", "widgets", "--name", "Widgets", "--repo", "github.com/example/widgets",
			"--tags", strings.Join(rgRunTags, ","), "--out", out, "--rules", rules}, extra...)
	}
	var so, se bytes.Buffer
	good := filepath.Join(tmp, "good")
	if code := run(args(rulesFile("good.json", rgGood()), good, "--range-check-tags", strings.Join(rgAllTags, ",")), &so, &se, open); code != 0 {
		t.Fatalf("good run exit %d: %s%s", code, so.String(), se.String())
	}
	// Drop the bootstrap module from the rules.
	dropped := []string{rgGood()[0], rgGood()[1], rgGood()[3]}
	so.Reset()
	se.Reset()
	bad := filepath.Join(tmp, "bad")
	code := run(args(rulesFile("bad.json", dropped), bad,
		"--compare-a", filepath.Join(good, "a", "target-widgets.json"),
		"--compare-b", filepath.Join(good, "b", "target-widgets.json"),
		"--compare-report", filepath.Join(good, "report.json")), &so, &se, open)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s%s", code, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "DIFF A: path missing from generated: "+rgBoot+"boot.yaml") || !strings.Contains(so.String(), "DIFF facts") {
		t.Fatalf("the dropped module was not named:\n%s", so.String())
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("a draft was written for the seeded wrong rules")
	}
	// The same rules, compared against themselves, are equal.
	so.Reset()
	again := filepath.Join(tmp, "again")
	if code := run(args(rulesFile("good.json", rgGood()), again,
		"--compare-a", filepath.Join(good, "a", "target-widgets.json"),
		"--compare-report", filepath.Join(good, "report.json"),
		"--range-check-tags", strings.Join(rgAllTags, ",")), &so, &se, open); code != 0 {
		t.Fatalf("equal compare exit %d: %s", code, so.String())
	}
}

func TestRangesRefusals(t *testing.T) {
	cases := []struct {
		name    string
		moved   []string
		mutate  func(tag string, f map[string]string)
		entries []string
		code    string
	}{
		{"gap between ranges", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "", "v1.11.2"), rgEntry(rgNew, "core-crds", "v1.14.4", ""),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopRangeGap},
		{"overlap", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "", "v1.13.8"), rgEntry(rgNew, "core-crds", "v1.13.8", ""),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopRangeOverlap},
		{"fromTag after toTag on the new entry", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "", "v1.13.8"), rgEntry(rgNew, "core-crds", "v1.14.4", "v1.13.8"),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopBadInput},
		{"starts after the oldest tag", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "v1.10.3", "v1.13.8"), rgEntry(rgNew, "core-crds", "v1.14.4", ""),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopRangeNotCovering},
		{"ends before the newest tag", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "", "v1.13.8"),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopRangeNotCovering},
		{"fromTag is not a tag of the window", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "", "v1.13.8"), rgEntry(rgNew, "core-crds", "v1.14.0", ""),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopBadInput},
		{"fromTag after toTag", []string{"v1.14.4"}, nil, []string{
			rgEntry(rgOld, "core-crds", "v1.13.8", "v1.9.8"), rgEntry(rgNew, "core-crds", "v1.14.4", ""),
			rgEntry(rgBoot, "b", "", "v1.14.4"), rgEntry(rgPlane, "p", "", "v1.14.4")}, StopBadInput},
		{"absent inside its range", []string{"v1.14.4"}, func(tag string, f map[string]string) {
			if tag == "v1.11.2" {
				delete(f, rgBoot+"boot.yaml")
				f[rgBoot+"README.md"] = "no definition"
			}
		}, rgGood(), StopRangeAbsentInRange},
		{"absent inside its range, newest tag", []string{"v1.14.4"}, func(tag string, f map[string]string) {
			if tag == "v1.14.4" {
				delete(f, rgNew+"alpha.yaml")
				delete(f, rgNew+"beta.yaml")
			}
		}, rgGood(), StopRangeAbsentInRange},
		{"present outside its range", []string{"v1.14.4"}, func(tag string, f map[string]string) {
			if tag == "v1.14.4" {
				f[rgOld+"alpha.yaml"] = ipCRD("widgets.example.test", "Alpha")
			}
		}, rgGood(), StopRangePresentOutRange},
		{"present outside its range, older tag", []string{"v1.14.4"}, func(tag string, f map[string]string) {
			if tag == "v1.10.3" {
				f[rgNew+"alpha.yaml"] = ipCRD("widgets.example.test", "Alpha")
			}
		}, rgGood(), StopRangePresentOutRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := rgRepo(t, c.moved, c.mutate)
			res, err := rgGen(t, repo, rgJSON(c.entries...))
			if res != nil || err == nil {
				t.Fatal("run succeeded, want a typed stop")
			}
			if !hasCode(err, c.code) {
				t.Fatalf("stops %v, want %s: %v", stopCodes(err), c.code, err)
			}
			for _, s := range err.(*StopError).Stops {
				if s.Next == "" || s.Next == "review the finding" {
					t.Errorf("stop %s has no next action", s.Code)
				}
			}
		})
	}
}

func TestRangesParseRefusals(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want string
	}{
		{"range with optional", rgJSON(`{"path":"a/b.yaml","reason":"r","evidence":"e","role":"x","fromTag":"v1.0.0","optional":true,"absentTags":["v1.0.0"]}`), "range-with-optional"},
		{"range with absentTags only", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"x","fromTag":"v1.0.0","absentTags":["v1.0.0"]}`), "range-with-optional"},
		{"range without a role", rgJSON(`{"path":"a/","reason":"r","evidence":"e","fromTag":"v1.0.0"}`), "need a role"},
		{"role without a range", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"x"}`), "needs fromTag and/or toTag"},
		{"bad role", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"X Y","fromTag":"v1.0.0"}`), "not a lower-case name"},
		{"bad tag", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"x","fromTag":"../v1"}`), "not a plain tag name"},
		{"mixed shapes", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"x","fromTag":"v1.0.0"}`, `{"path":"b/c.yaml","reason":"r","evidence":"e","role":"x","toTag":"v1.0.0"}`), "mixes directory and exact-file"},
		{"filter removes a ranged file", `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[{"path":"a/b.yaml","reason":"r","evidence":"e","role":"x","fromTag":"v1.0.0"}],"pathFilter":[{"glob":"a/*.yaml","reason":"r","evidence":"e","expectFiles":1}]}`, "never removes a ranged entry"},
		{"unknown member", rgJSON(`{"path":"a/","reason":"r","evidence":"e","role":"x","fromTag":"v1.0.0","range":"x"}`), "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseRules([]byte(c.js))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// A move inside a line is invisible to the one tag the run reads per line; the
// range check tags make it a stop. Documented behaviour.
func TestRangesMidLineMoveNeedsRangeCheckTags(t *testing.T) {
	// v1.13.3 already moved, v1.13.8 (the run tag of the line) has not.
	repo := rgRepo(t, []string{"v1.13.3", "v1.14.4"}, func(tag string, f map[string]string) {
		if tag == "v1.13.8" {
			f[rgOld+"alpha.yaml"] = ipCRD("widgets.example.test", "Alpha")
			f[rgOld+"beta.yaml"] = ipCRD("widgets.example.test", "Beta")
			delete(f, rgNew+"alpha.yaml")
			delete(f, rgNew+"beta.yaml")
		}
	})
	js := rgJSON(rgGood()...)
	if _, err := rgGen(t, repo, js); err != nil {
		t.Fatalf("without --range-check-tags the single-tag view must pass: %v", err)
	}
	res, err := rgGen(t, repo, js, rgAllTags...)
	if res != nil || err == nil {
		t.Fatal("the mid-line move was not caught with --range-check-tags")
	}
	if !hasCode(err, StopRangeAbsentInRange) || !hasCode(err, StopRangePresentOutRange) {
		t.Fatalf("stops %v: %v", stopCodes(err), err)
	}
	if !strings.Contains(err.Error(), "v1.13.3") {
		t.Fatalf("the stop does not name the tag: %v", err)
	}
}

func TestRangesCheckTagsFailClosed(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	js := rgJSON(rgGood()...)
	for name, tags := range map[string][]string{
		"unknown line":        {"v1.8.0"},
		"not a tag":           {"nope"},
		"a duplicate":         {"v1.13.3", "v1.13.3"},
		"another prefix":      {"x1.13.3"},
		"tag not in the repo": {"v1.13.9"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := rgGen(t, repo, js, tags...); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Range check tags without ranged entries are refused.
	plain := rgJSON(rgEntry(rgBoot, "", "", ""))
	if _, err := rgGen(t, repo, plain, "v1.13.3"); !hasCode(err, StopBadInput) {
		t.Fatalf("range check tags without ranges: %v", err)
	}
}

func TestRangesCheckTagsLocalOnlyEnvironment(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	in, err := rgInput(GitSource{Dir: repo, env: []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_TERMINAL_PROMPT=0"}}, rgJSON(rgGood()...), rgAllTags...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(in); !hasCode(err, StopRangeUnverifiable) {
		t.Fatalf("a run without the local-only environment must stop: %v", stopCodes(err))
	}
}

func TestRangesNeedAProbingReader(t *testing.T) {
	in := Input{Slug: "widgets", Name: "Widgets", Repo: "github.com/example/widgets", Tags: rgRunTags, Source: memSource{trees: map[string]*memTree{}}}
	r, err := ParseRules([]byte(rgJSON(rgGood()...)))
	if err != nil {
		t.Fatal(err)
	}
	in.Rules = r
	for _, tag := range rgRunTags {
		m := newMemTree()
		for p, b := range rgFiles(tag, map[string]bool{"v1.14.4": true}) {
			m.files[p] = []byte(b)
		}
		in.Source.(memSource).trees[tag] = m
	}
	if _, err := Generate(in); !hasCode(err, StopRangeUnverifiable) {
		t.Fatalf("a tree reader that cannot probe must stop: %v", stopCodes(err))
	}
}

func TestRangesDeterministicAndDigestOnlyWithRanges(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	a, err := rgGen(t, repo, rgJSON(rgGood()...), rgAllTags...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rgGen(t, repo, rgJSON(rgGood()...), rgAllTags...)
	if err != nil {
		t.Fatal(err)
	}
	ra, _ := marshal(a.Report)
	rb, _ := marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(a.TableRow, b.TableRow) || !bytes.Equal(a.Changelog, b.Changelog) || !bytes.Equal(ra, rb) {
		t.Fatal("two runs differ")
	}
	// The order of the check tags does not matter.
	rev := append([]string(nil), rgAllTags...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	c, err := rgGen(t, repo, rgJSON(rgGood()...), rev...)
	if err != nil || c.Report.FactsDigest != a.Report.FactsDigest {
		t.Fatalf("check tag order changed the result: %v", err)
	}
	// Same files read without ranges (only the unmoved part): no ranged facts.
	plain, err := rgGen(t, repo, rgJSON(rgEntry(rgBoot, "", "", ""), rgEntry(rgPlane, "", "", "")))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Report.RangedPaths != nil || plain.Report.RangeCheckedTags != nil {
		t.Fatalf("ranged facts without ranges: %+v", plain.Report)
	}
}

// Without ranges the same moved repository behaves as before: the move is a stop.
func TestRangesAbsentLeavesTheMoveAsBefore(t *testing.T) {
	repo := rgRepo(t, []string{"v1.14.4"}, nil)
	plain := rgJSON(rgEntry(rgOld, "", "", ""), rgEntry(rgNew, "", "", ""), rgEntry(rgBoot, "", "", ""), rgEntry(rgPlane, "", "", ""))
	// Both directories are mandatory at every tag, so the newest tag lacks the
	// old one: the existing stop, no ranged behaviour.
	if _, err := rgGen(t, repo, plain); !hasCode(err, StopInstallPathNothing) {
		t.Fatalf("want install-path-matches-nothing without ranges, got %v", stopCodes(err))
	}
}

// A pathFilter under a ranged directory applies only inside the range.
func TestRangesPathFilterAppliesOnlyInsideTheRange(t *testing.T) {
	const copyName = "policy.networking.k8s.io_a.yaml"
	mutate := func(tag string, f map[string]string) {
		if tag != "v1.14.4" {
			f[rgOld+copyName] = ipCRD("policy.networking.k8s.io", "AlphaPolicy")
		}
	}
	repo := rgRepo(t, []string{"v1.14.4"}, mutate)
	withFilter := func(expect string) string {
		js := rgJSON(rgGood()...)
		return strings.TrimSuffix(js, "}") + `,"pathFilter":[{"glob":"config/crd/bases/policy.networking.k8s.io_*.yaml","reason":"r","evidence":"e","expectFiles":` + expect + `}]}`
	}
	res, err := rgGen(t, repo, withFilter("1"))
	if err != nil {
		t.Fatalf("filter inside its range: %v", err)
	}
	if res.Report.FilteredCopyCount != 1 || len(res.Report.FilteredCopies[0].Tags) != 5 {
		t.Fatalf("filtered copies %+v", res.Report.FilteredCopies)
	}
	// expectFiles is exact at every tag inside the range; a tag that fails it
	// is withheld like any other stopped tag, here every older tag.
	if _, err := rgGen(t, repo, withFilter("2")); err == nil || !strings.Contains(err.Error(), StopPathFilterCount) {
		t.Fatalf("expectFiles is exact at every tag inside the range: %v", err)
	}
}

// A tag withheld by a per-tag rule shrinks the window from the old end; the
// ranged selection and the coverage checks still hold for the tags that stay,
// and a range stop never shrinks the window (it ends the run).
func TestRangesWithAShrunkWindow(t *testing.T) {
	const copyName = "policy.networking.k8s.io_a.yaml"
	mutate := func(tag string, f map[string]string) {
		if tag != "v1.14.4" && tag != "v1.9.8" {
			f[rgOld+copyName] = ipCRD("policy.networking.k8s.io", "AlphaPolicy")
		}
	}
	repo := rgRepo(t, []string{"v1.14.4"}, mutate)
	js := strings.TrimSuffix(rgJSON(rgGood()...), "}") + `,"pathFilter":[{"glob":"config/crd/bases/policy.networking.k8s.io_*.yaml","reason":"r","evidence":"e","expectFiles":1}]}`
	res, err := rgGen(t, repo, js)
	if err != nil {
		t.Fatalf("shrunk window: %v", err)
	}
	if len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != "v1.9.8" || len(res.Report.Tags) != 5 {
		t.Fatalf("window %d tags, dropped %+v", len(res.Report.Tags), res.Report.Dropped)
	}
	for _, f := range res.Report.RangedPaths {
		if f.Tag == "v1.9.8" {
			t.Fatalf("ranged fact for a dropped tag: %+v", f)
		}
	}
	// A boundary violation at the dropped tag still ends the run.
	repo2 := rgRepo(t, []string{"v1.14.4"}, func(tag string, f map[string]string) {
		mutate(tag, f)
		if tag == "v1.9.8" {
			f[rgNew+"alpha.yaml"] = ipCRD("policy.networking.k8s.io", "AlphaPolicy")
		}
	})
	if _, err := rgGen(t, repo2, js); err == nil || !hasCode(err, "range-path-present-out-of-range") {
		t.Fatalf("a stop at a dropped tag must end the run: %v", err)
	}
}

// Optional entries (verified absence) and ranges can sit in one rules file on
// different entries.
func TestRangesCombineWithAnOptionalEntryOnAnotherPath(t *testing.T) {
	const extra = "tools/extra.yaml"
	repo := rgRepo(t, []string{"v1.14.4"}, func(tag string, f map[string]string) {
		if tag == "v1.14.4" {
			f[extra] = ipCRD("widgets.example.test", "Extra")
		}
	})
	opt := `{"path":"` + extra + `","reason":"r","evidence":"e","optional":true,"absentTags":["v1.9.8","v1.10.3","v1.11.2","v1.12.1","v1.13.8"]}`
	res, err := rgGen(t, repo, rgJSON(append(rgGood(), opt)...))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.OptionalPaths) != 6 || len(res.Report.RangedPaths) != 18 {
		t.Fatalf("optional %d, ranged %d", len(res.Report.OptionalPaths), len(res.Report.RangedPaths))
	}
}
