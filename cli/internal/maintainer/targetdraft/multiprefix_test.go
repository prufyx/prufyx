// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Older line without a prefix, newer line with "v": the shipped shape of
// tagPrefixes ["v", ""].
var mpTags = []string{"5.18.0", "5.19.0", "v5.20.0", "v5.21.0"}

func mpSource(tags []string, mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range tags {
		m := collapseBase()
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func mpInput(tags []string, src Source, multi, collapse bool) Input {
	return Input{Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf", Tags: tags, Source: src, MultiPrefix: multi, CollapseDirectories: collapse}
}

const wantMultiA = `{
  "schema": "prufyx.io/crd-version-target/v1",
  "target": {
    "project": "demo",
    "name": "Demo",
    "repo": "github.com/example/demo",
    "component": "pkg:github/example/demo",
    "factProject": "demo",
    "tagPrefixes": ["v", ""],
    "minFrom": "5.18",
    "paths": [
      {"path": "config/crd", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}
    ],
    "exclude": []
  }
}
`

func mpStop(t *testing.T, label string, in Input, code string) {
	t.Helper()
	res, err := Generate(in)
	wantCollapseStop(t, label, res, err, code)
}

func TestMultiPrefixPositiveBytesAndReport(t *testing.T) {
	res := mustGenerate(t, mpInput(mpTags, mpSource(mpTags, nil), true, true))
	wantCanonicalEqual(t, "A", res.A, []byte(wantMultiA))
	tg := loadEmitted(t, "demo", res.A)
	if strings.Join(tg.TagPrefixes, "|") != "v|" {
		t.Fatalf("loader reads prefixes %q", tg.TagPrefixes)
	}
	if strings.Join(res.Report.TagPrefixes, "|") != "v|" || len(res.Report.PrefixWindows) != 2 {
		t.Fatalf("report: %+v", res.Report)
	}
	w := res.Report.PrefixWindows
	if w[0].Prefix != "v" || strings.Join(w[0].Tags, ",") != "v5.20.0,v5.21.0" || w[1].Prefix != "" || strings.Join(w[1].Tags, ",") != "5.18.0,5.19.0" {
		t.Fatalf("prefix windows: %+v", w)
	}
	if !strings.Contains(string(res.Changelog), "tag family `v` and ``") {
		t.Fatalf("changelog: %s", res.Changelog)
	}
	// B has the same prefixes; deterministic.
	if !bytes.Contains(res.B, []byte(`"tagPrefixes": ["v", ""]`)) {
		t.Fatal("half B lost a prefix")
	}
	again := mustGenerate(t, mpInput(mpTags, mpSource(mpTags, nil), true, true))
	r1, _ := marshal(res.Report)
	r2, _ := marshal(again.Report)
	if !bytes.Equal(res.A, again.A) || !bytes.Equal(res.B, again.B) || !bytes.Equal(r1, r2) {
		t.Fatal("two runs differ")
	}
	// Tag order on the command line is irrelevant.
	rev := []string{"v5.21.0", "5.19.0", "v5.20.0", "5.18.0"}
	third := mustGenerate(t, mpInput(rev, mpSource(rev, nil), true, true))
	if !bytes.Equal(res.A, third.A) {
		t.Fatal("tag order changed the target")
	}
}

// The list is ordered by the newest tag's prefix: with the prefix on the older
// line the order flips (a mutation that hard-codes "v" first fails here).
func TestMultiPrefixOrderFollowsNewestTag(t *testing.T) {
	tags := []string{"v1.1.0", "v1.2.0", "1.3.0", "1.4.0"}
	res := mustGenerate(t, mpInput(tags, mpSource(tags, nil), true, false))
	if !bytes.Contains(res.A, []byte(`"tagPrefixes": ["", "v"]`)) {
		t.Fatalf("order: %s", res.A)
	}
	if loadEmitted(t, "demo", res.A).MinFrom != [2]int{1, 1} {
		t.Fatal("minFrom")
	}
}

func TestMultiPrefixOffByDefault(t *testing.T) {
	// Two prefixes without the flag are still the old stop.
	in := mpInput(mpTags, mpSource(mpTags, nil), false, false)
	mpStop(t, "flag off", in, StopTagPrefixMixed)
	// One prefix: the flag changes no byte.
	tags := collapseTags
	off := mustGenerate(t, mpInput(tags, collapseSource(nil), false, true))
	wantCanonicalEqual(t, "off", off.A, []byte(wantCollapsedA))
	if off.Report.TagPrefixes != nil || off.Report.PrefixWindows != nil {
		t.Fatal("report grew multi-prefix fields with the flag off")
	}
	rep, _ := marshal(off.Report)
	if bytes.Contains(rep, []byte("prefixWindows")) || bytes.Contains(rep, []byte(`"tagPrefixes"`)) {
		t.Fatalf("flag off report names multi-prefix fields: %s", rep)
	}
	// One prefix with the flag on is a stop, never a silent single prefix.
	mpStop(t, "one prefix, flag on", mpInput(tags, collapseSource(nil), true, false), StopMultiPrefixAmbiguous)
}

func TestMultiPrefixTypedStops(t *testing.T) {
	src := func(tags []string) Source { return mpSource(tags, nil) }
	cases := []struct {
		label string
		tags  []string
		code  string
	}{
		{"three prefixes", []string{"1.1.0", "1.2.0", "v1.3.0", "v1.4.0", "chart-1.5.0", "chart-1.6.0"}, StopMultiPrefixAmbiguous},
		{"overlapping prefixes", []string{"chart-1.1.0", "chart-1.2.0", "chart-a-1.3.0", "chart-a-1.4.0"}, StopMultiPrefixAmbiguous},
		{"one prefix has one tag", []string{"1.1.0", "v1.2.0", "v1.3.0"}, StopMultiPrefixShort},
		{"interleaved lines", []string{"1.1.0", "v1.2.0", "1.3.0", "v1.4.0"}, StopMultiPrefixAmbiguous},
		{"switch back and forth", []string{"v1.1.0", "v1.2.0", "1.3.0", "1.4.0", "v1.5.0", "v1.6.0"}, StopMultiPrefixAmbiguous},
		{"unsupported prefix", []string{"1.1.0", "1.2.0", "x_1.3.0", "x_1.4.0"}, StopTagPrefixUnsupported},
		{"tag outside the extractor grammar", []string{"1.1.0", "1.2.0", "v1.12345.0", "v1.12346.0"}, StopMultiPrefixAmbiguous},
		{"same line under two prefixes", []string{"1.1.0", "v1.1.0", "1.2.0", "v1.2.0"}, StopTagLineDuplicate},
		{"grammar", []string{"1.1.0", "1.2.0", "v1.3", "v1.4.0"}, StopTagGrammar},
	}
	for _, c := range cases {
		mpStop(t, c.label, mpInput(c.tags, src(c.tags), true, false), c.code)
	}
}

// The tag-list check alone (before any tree is read) refuses a prefix with one
// tag and a list that is not two prefixes.
func TestParseTagsMultiDirect(t *testing.T) {
	if _, _, st := parseTagsMulti([]string{"1.1.0", "v1.2.0", "v1.3.0"}); len(st) != 1 || st[0].Code != StopMultiPrefixShort {
		t.Fatalf("one tag: %v", st)
	}
	if _, _, st := parseTagsMulti([]string{"1.1.0", "1.2.0"}); len(st) != 1 || st[0].Code != StopMultiPrefixAmbiguous {
		t.Fatalf("one prefix: %v", st)
	}
	tags, pre, st := parseTagsMulti(mpTags)
	if len(st) != 0 || len(tags) != 4 || strings.Join(pre, "|") != "v|" {
		t.Fatalf("good list: %v %v %v", tags, pre, st)
	}
}

// Two release lines with different API groups are never merged.
func TestMultiPrefixDifferentGroupsStop(t *testing.T) {
	src := mpSource(mpTags, func(tag string, m *memTree) {
		if !strings.HasPrefix(tag, "v") {
			m.files["config/crd/a.yaml"] = crdText("other.example.invalid", "Alpha")
			m.files["config/crd/b.yaml"] = crdText("other.example.invalid", "Beta")
		}
	})
	mpStop(t, "groups differ", mpInput(mpTags, src, true, false), StopMultiPrefixGroups)
	mpStop(t, "groups differ, collapse", mpInput(mpTags, src, true, true), StopMultiPrefixGroups)
	// Control: the same trees with one prefix per run are a valid single run.
	only := []string{"5.18.0", "5.19.0"}
	mustGenerate(t, mpInput(only, mpSource(only, func(tag string, m *memTree) {
		m.files["config/crd/a.yaml"] = crdText("other.example.invalid", "Alpha")
		m.files["config/crd/b.yaml"] = crdText("other.example.invalid", "Beta")
	}), false, false))
}

// An older prefix whose tags read another file set is withheld by the window;
// the prefix then has fewer than two tags in its window: a stop, not a silent
// single-prefix target that still lists both prefixes.
func TestMultiPrefixWindowShrinkStops(t *testing.T) {
	src := mpSource(mpTags, func(tag string, m *memTree) {
		if tag == "5.19.0" {
			delete(m.files, "config/crd/b.yaml")
		}
	})
	mpStop(t, "older prefix shrunk to one tag", mpInput(mpTags, src, true, false), StopMultiPrefixShort)
	// Even a shrink that spares the other prefix is a stop for the shrunk one.
	src = mpSource(mpTags, func(tag string, m *memTree) {
		if tag == "5.18.0" || tag == "5.19.0" {
			m.files["config/crd/c.yaml"] = crdText("demo.example.invalid", "Gamma")
		}
	})
	mpStop(t, "whole older prefix withheld", mpInput(mpTags, src, true, false), StopMultiPrefixShort)
	// A stop writes nothing: through the CLI the exit is 1 and --out stays absent.
	out := filepath.Join(t.TempDir(), "o")
	var so, se bytes.Buffer
	args := []string{"generate", "--dir", "x", "--slug", "demo", "--name", "Demo", "--repo", "github.com/example/demo", "--tags", strings.Join(mpTags, ","), "--out", out, "--multi-prefix"}
	if code := run(args, &so, &se, func(string) Source { return src }); code != 1 || !strings.Contains(so.String(), "STOP multi-prefix-window-short") {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a stop left a draft")
	}
}

// Exclusions are never inferred: a multi-prefix run over a tree needing one
// still stops on the same pin as a single run.
func TestMultiPrefixKeepsExclusionStops(t *testing.T) {
	src := mpSource(mpTags, func(tag string, m *memTree) {
		m.files["docs/crd.yaml"] = crdText("demo.example.invalid", "Doc")
	})
	res, err := Generate(mpInput(mpTags, src, true, false))
	if res != nil || err == nil {
		t.Fatal("an unpinned doc CRD passed in a multi-prefix run")
	}
	var stopCodes []string
	if se, ok := err.(*StopError); ok {
		for _, s := range se.Stops {
			stopCodes = append(stopCodes, s.Code)
		}
	}
	sort.Strings(stopCodes)
	if len(stopCodes) == 0 || stopCodes[0] == StopMultiPrefixAmbiguous {
		t.Fatalf("stops: %v", stopCodes)
	}
}

// Seeded wrong targets through the CLI compare: swap, drop, extra, merge into
// one prefix, order-changed list.
func TestMultiPrefixSeededWrongTargetsExitNonZero(t *testing.T) {
	src := mpSource(mpTags, nil)
	open := func(string) Source { return src }
	dir := t.TempDir()
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "demo", "--name", "Demo", "--repo", "github.com/example/demo", "--tags", strings.Join(mpTags, ","), "--out", out, "--multi-prefix", "--collapse-directories"}, extra...)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(wantMultiA), 0o644); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	if code := run(args(filepath.Join(t.TempDir(), "ok"), "--compare-a", good), &so, &se, open); code != 0 {
		t.Fatalf("the true target must pass: %d %s %s", code, so.String(), se.String())
	}
	seeds := map[string]string{
		"swap prefixes":       strings.Replace(wantMultiA, `["v", ""]`, `["", "v"]`, 1),
		"merge into v":        strings.Replace(wantMultiA, `["v", ""]`, `["v"]`, 1),
		"merge into none":     strings.Replace(wantMultiA, `["v", ""]`, `[""]`, 1),
		"drop a prefix":       strings.Replace(wantMultiA, `["v", ""]`, `["v"]`, 1),
		"extra prefix":        strings.Replace(wantMultiA, `["v", ""]`, `["v", "", "knative-v"]`, 1),
		"other second prefix": strings.Replace(wantMultiA, `["v", ""]`, `["v", "knative-v"]`, 1),
		"minFrom of one line": strings.Replace(wantMultiA, `"minFrom": "5.18"`, `"minFrom": "5.20"`, 1),
	}
	names := make([]string, 0, len(seeds))
	for n := range seeds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if seeds[n] == wantMultiA {
			t.Fatalf("seed %q did not change the file", n)
		}
		f := filepath.Join(dir, strings.ReplaceAll(n, " ", "-")+".json")
		if err := os.WriteFile(f, []byte(seeds[n]), 0o644); err != nil {
			t.Fatal(err)
		}
		so.Reset()
		se.Reset()
		out := filepath.Join(t.TempDir(), "seed")
		if code := run(args(out, "--compare-a", f), &so, &se, open); code == 0 {
			t.Fatalf("seed %q reproduced the target", n)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("seed %q left a draft behind", n)
		}
	}
	// The multi-prefix target on a tree of one prefix only: not a match.
	one := mpSource(collapseTags, nil)
	so.Reset()
	args1 := []string{"generate", "--dir", "x", "--slug", "demo", "--name", "Demo", "--repo", "github.com/example/demo", "--tags", strings.Join(collapseTags, ","), "--out", filepath.Join(t.TempDir(), "p"), "--multi-prefix", "--compare-a", good}
	if code := run(args1, &so, &se, func(string) Source { return one }); code == 0 {
		t.Fatal("a multi-prefix target passed on a single-prefix tree")
	}
}

// Every shipped target that lists two prefixes round-trips byte for byte
// through the emitter's canonical form (the loader's own parse), so the
// emitted bytes are the shipped form.
func TestMultiPrefixShippedFormRoundTrips(t *testing.T) {
	files, _ := filepath.Glob("../../extract/crdversions/target-*.json")
	n := 0
	for _, f := range files {
		raw := readFile(t, f)
		if !bytes.Contains(raw, []byte(`"tagPrefixes": ["v", ""]`)) {
			continue
		}
		slug := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "target-"), ".json")
		tg := loadEmitted(t, slug, raw)
		if len(tg.TagPrefixes) != 2 || tg.TagPrefixes[0] != "v" || tg.TagPrefixes[1] != "" {
			t.Errorf("%s: loader reads %q", slug, tg.TagPrefixes)
		}
		c, err := Canonical(raw)
		if err != nil {
			t.Errorf("%s: %v", slug, err)
			continue
		}
		if !bytes.Equal(c, raw) {
			t.Errorf("%s: emitted form differs from the shipped bytes", slug)
		}
		n++
	}
	if n < 7 {
		t.Fatalf("only %d shipped multi-prefix targets checked", n)
	}
	if !crdversions.ValidTagPrefix("v") || !crdversions.ValidTagPrefix("") {
		t.Fatal("loader refuses v or the empty prefix")
	}
}

// The backtest reproduces a multi-prefix entry and rejects the multi-prefix
// seeds; a multi-prefix seed on a single-prefix entry cannot run (exit 2).
func TestBacktestMultiPrefixSeeds(t *testing.T) {
	f := newBT(t)
	mpOpen := func(dir string) Source {
		if filepath.Base(dir) == "multi" {
			return mpSource(mpTags, func(tag string, m *memTree) {
				delete(m.files, "config/crd/b.yaml")
				m.files["config/crd/a.yaml"] = crdText("demo.example.invalid", "Alpha")
			})
		}
		return btOpen(dir)
	}
	if err := os.Mkdir(filepath.Join(f.mirrors, "multi"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Generate(Input{Slug: "multi", Name: "multi", Repo: "github.com/example/multi", Tags: mpTags, Source: mpOpen("multi"), MultiPrefix: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "expected-multi.json"), res.A, 0o644); err != nil {
		t.Fatal(err)
	}
	e := btEntryMap("multi", "multi")
	e["tags"] = mpTags
	e["multiPrefix"] = true
	f.addEntry(e, 3)
	f.m["seeds"] = []any{
		map[string]any{"entry": "multi", "kind": "swap-prefixes"},
		map[string]any{"entry": "multi", "kind": "drop-prefix"},
		map[string]any{"entry": "multi", "kind": "extra-prefix"},
		map[string]any{"entry": "multi", "kind": "swap", "other": "alpha"},
		map[string]any{"entry": "multi", "kind": "min-from"},
	}
	code, so, se := f.run(t, mpOpen)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, so, se)
	}
	for _, want := range []string{"multi reproduced ", "multi/swap-prefixes failed", "multi/drop-prefix failed", "multi/extra-prefix failed", "seeds=5/5-failed"} {
		if !strings.Contains(so, want) {
			t.Errorf("missing %q in %s", want, so)
		}
	}
	// Without the entry flag the same tags stop: never a silent single prefix.
	e["multiPrefix"] = false
	code, so, _ = f.run(t, mpOpen)
	if !strings.Contains(so, "multi typed-stop stops=tag-prefix-mixed") || code == 0 {
		t.Fatalf("flag off: exit %d %s", code, so)
	}
	// A multi-prefix seed on a single-prefix entry cannot run.
	g := newBT(t)
	g.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "swap-prefixes"}}
	if code, so, _ := g.run(t, btOpen); code != 2 || !strings.Contains(so, "not-run") {
		t.Fatalf("seed on one prefix: exit %d %s", code, so)
	}
	// Unknown seed kind still refused by the manifest.
	g.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "merge-prefixes"}}
	if code, _, _ := g.run(t, btOpen); code != 2 {
		t.Fatalf("unknown kind: exit %d", code)
	}
}

// The mirror also holds the other spelling of a window release: stop.
func TestMultiPrefixOtherSpellingStops(t *testing.T) {
	for _, extra := range []string{"5.20.0", "v5.19.0"} {
		src := mpSource(append(append([]string(nil), mpTags...), extra), nil)
		mpStop(t, "other spelling "+extra, mpInput(mpTags, src, true, false), StopMultiPrefixAmbiguous)
	}
	// An unrelated extra tag is fine.
	src := mpSource(append(append([]string(nil), mpTags...), "v9.9.9"), nil)
	mustGenerate(t, mpInput(mpTags, src, true, false))
	// Flag off, nothing is probed: a single-prefix run is unchanged.
	mustGenerate(t, mpInput(collapseTags, mpSource(append(append([]string(nil), collapseTags...), "1.3.0"), nil), false, false))
}

// Kinds that differ across the lines are a report warning, not a stop.
func TestMultiPrefixKindDifferenceWarns(t *testing.T) {
	// The kind sits in an existing file: a new file would change the file set
	// at the v tags and shrink the window.
	src := mpSource(mpTags, func(tag string, m *memTree) {
		if strings.HasPrefix(tag, "v") {
			m.files["config/crd/b.yaml"] = append(crdText("demo.example.invalid", "Beta"), append([]byte("---\n"), crdText("demo.example.invalid", "Gamma")...)...)
		}
	})
	res := mustGenerate(t, mpInput(mpTags, src, true, false))
	if len(res.Report.PrefixKindDifferences) != 1 || !strings.Contains(res.Report.PrefixKindDifferences[0], `demo.example.invalid/Gamma: only in prefix "v"`) {
		t.Fatalf("differences: %v", res.Report.PrefixKindDifferences)
	}
	same := mustGenerate(t, mpInput(mpTags, mpSource(mpTags, nil), true, false))
	if len(same.Report.PrefixKindDifferences) != 0 {
		t.Fatal("equal kinds warned")
	}
}

// Numeric (not text) order across the switch, a major rollover and a
// pre-release tag.
func TestMultiPrefixNumericOrderAndPreRelease(t *testing.T) {
	tags := []string{"1.9.0", "1.10.0", "v1.11.0", "v1.12.0"}
	res := mustGenerate(t, mpInput(tags, mpSource(tags, nil), true, false))
	if !bytes.Contains(res.A, []byte(`"tagPrefixes": ["v", ""]`)) || !bytes.Contains(res.A, []byte(`"minFrom": "1.9"`)) {
		t.Fatalf("1.9/1.10: %s", res.A)
	}
	tags = []string{"1.8.0", "1.9.0", "v2.0.0", "v2.1.0"}
	res = mustGenerate(t, mpInput(tags, mpSource(tags, nil), true, false))
	if !bytes.Contains(res.A, []byte(`"minFrom": "1.8"`)) || strings.Join(res.Report.PrefixWindows[0].Tags, ",") != "v2.0.0,v2.1.0" {
		t.Fatalf("major rollover: %s", res.A)
	}
	// Text order would put v1.9.0 after v1.10.0 and read the lines interleaved.
	tags = []string{"v1.9.0", "v1.10.0", "1.11.0", "1.12.0"}
	res = mustGenerate(t, mpInput(tags, mpSource(tags, nil), true, false))
	if !bytes.Contains(res.A, []byte(`"tagPrefixes": ["", "v"]`)) {
		t.Fatalf("1.10 after 1.9: %s", res.A)
	}
	pre := []string{"1.1.0", "1.2.0", "v1.3.0", "v1.4.0-rc1"}
	mpStop(t, "pre-release", mpInput(pre, mpSource(pre, nil), true, false), StopTagGrammar)
}
