// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var btTags = []string{"v1.1.0", "v1.2.0", "v1.3.0"}

func btTree(kind string) *memTree {
	m := newMemTree()
	if kind != "" {
		m.files["config/crd/w.yaml"] = ipDocs(ipCRD("widgets.example.test", kind))
	}
	m.files["README.md"] = []byte("x")
	return m
}

// btOpen serves a one-file tree per mirror directory name; "empty" has no
// definition at all.
func btOpen(dir string) Source {
	kind := map[string]string{"alpha": "Alpha", "beta": "Beta", "gamma": "Gamma", "empty": ""}[filepath.Base(dir)]
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range btTags {
		s.trees[tag] = btTree(kind)
	}
	return s
}

type btFixture struct {
	dir, mirrors, manifest string
	m                      map[string]any
}

func btEntryMap(slug, mirror string) map[string]any {
	return map[string]any{"slug": slug, "name": slug, "repo": "github.com/example/" + slug, "tags": btTags,
		"mirror": mirror, "expected": "expected-" + slug + ".json", "half": "A"}
}

// newBT writes a manifest dir and mirror dirs; expected files are generated
// from the same trees, so alpha and beta reproduce.
func newBT(t *testing.T) *btFixture {
	t.Helper()
	f := &btFixture{dir: t.TempDir(), mirrors: t.TempDir()}
	for _, d := range []string{"alpha", "beta", "empty"} {
		if err := os.Mkdir(filepath.Join(f.mirrors, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"alpha", "beta"} {
		res, err := Generate(Input{Slug: p, Name: p, Repo: "github.com/example/" + p, Tags: btTags, Source: btOpen(p)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.dir, "expected-"+p+".json"), res.A, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.m = map[string]any{"schema": BacktestSchema, "count": 2,
		"entries": []any{btEntryMap("alpha", "alpha"), btEntryMap("beta", "beta")},
		"seeds": []any{map[string]any{"entry": "alpha", "kind": "swap", "other": "beta"},
			map[string]any{"entry": "alpha", "kind": "path"}, map[string]any{"entry": "beta", "kind": "min-from"},
			map[string]any{"entry": "beta", "kind": "attest"}}}
	return f
}

func (f *btFixture) write(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.m)
	if err != nil {
		t.Fatal(err)
	}
	f.manifest = filepath.Join(f.dir, "manifest.json")
	if err := os.WriteFile(f.manifest, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *btFixture) run(t *testing.T, open func(string) Source) (int, string, string) {
	t.Helper()
	f.write(t)
	var so, se bytes.Buffer
	code := runBacktest([]string{"--manifest", f.manifest, "--mirrors", f.mirrors, "--out", filepath.Join(t.TempDir(), "o")}, &so, &se, open)
	return code, so.String(), se.String()
}

func (f *btFixture) addEntry(e map[string]any, n int) {
	f.m["entries"] = append(f.m["entries"].([]any), e)
	f.m["count"] = n
}

func TestBacktestReproducedAndSeedsFail(t *testing.T) {
	f := newBT(t)
	code, so, se := f.run(t, btOpen)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, so, se)
	}
	for _, want := range []string{"alpha reproduced\n", "beta reproduced\n", "strict=2/2 reachable=2/2", "seeds=4/4-failed"} {
		if !strings.Contains(so, want) {
			t.Errorf("missing %q in %s", want, so)
		}
	}
}

func TestBacktestClasses(t *testing.T) {
	f := newBT(t)
	// differs(field): a reviewed file with another minFrom.
	raw := readFileT(t, filepath.Join(f.dir, "expected-beta.json"))
	if err := os.WriteFile(filepath.Join(f.dir, "expected-beta.json"), bytes.Replace(raw, []byte(`"minFrom": "1.1"`), []byte(`"minFrom": "1.2"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	// format-gap: a reviewed file with a directory entry.
	gap := bytes.Replace(readFileT(t, filepath.Join(f.dir, "expected-alpha.json")), []byte(`"paths": [`), []byte(`"paths": [{"directory":"config/crd","match":"x","guard":"y"},`), 1)
	if err := os.WriteFile(filepath.Join(f.dir, "expected-gap.json"), gap, 0o644); err != nil {
		t.Fatal(err)
	}
	g := btEntryMap("gap", "alpha")
	f.addEntry(g, 3)
	// typed stop: no definition in the tree.
	e := btEntryMap("nothing", "empty")
	e["expected"] = "expected-alpha.json"
	// mirror missing.
	mm := btEntryMap("lost", "absent")
	mm["expected"] = "expected-alpha.json"
	f.addEntry(e, 4)
	f.addEntry(mm, 5)
	f.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "path"}}
	code, so, se := f.run(t, btOpen)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, so, se)
	}
	for _, want := range []string{"beta differs cause=window fields=minFrom\n", "gap differs cause=format-gap fields=paths.directory,paths.guard,paths.match\n",
		"nothing typed-stop stops=no-crd-source\n", "lost typed-stop stops=mirror-missing\n", "strict=1/5 reachable=1/4", "stops=2 differs=2 errors=0"} {
		if !strings.Contains(so, want) {
			t.Errorf("missing %q in\n%s", want, so)
		}
	}
}

func readFileT(t *testing.T, p string) []byte { return readFile(t, p) }

func TestBacktestCircularWhenRulesHaveExclusions(t *testing.T) {
	m := &btManifest{Schema: BacktestSchema, Count: 1, Entries: []btEntry{{Slug: "knative", Name: "Knative", Repo: "github.com/knative/serving", Catalog: "cncf",
		Tags: knativeTags, Mirror: "knative", Rules: "knative/rules.json", Expected: "knative/golden-b.json", Half: "B"}},
		Seeds: []btSeed{{Entry: "knative", Kind: "path"}}}
	mirrors := t.TempDir()
	if err := os.Mkdir(filepath.Join(mirrors, "knative"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep := Backtest(m, "d", "testdata", mirrors, func(string) Source { return knativeSource(t, nil) })
	if rep.Results[0].Class != ClassReproducedCircular || rep.Reproduced != 0 || rep.Circular != 1 {
		t.Fatalf("%+v", rep)
	}
	// Circular entries are not strict; seeds on them still run.
	if rep.SeedsFailed != 1 {
		t.Fatalf("%+v", rep.SeedResults)
	}
}

func TestBacktestCommittedManifest(t *testing.T) {
	mirrors := t.TempDir()
	if err := os.Mkdir(filepath.Join(mirrors, "knative"), 0o755); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	open := func(string) Source { return knativeSource(t, nil) }
	if code := runBacktest([]string{"--manifest", "testdata/backtest-manifest.json", "--mirrors", mirrors, "--out", filepath.Join(t.TempDir(), "o")}, &so, &se, open); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "strict=0/1") || !strings.Contains(so.String(), "seeds=4/4-failed") {
		t.Fatal(so.String())
	}
}

func TestBacktestSeedThatReproducesIsRejected(t *testing.T) {
	x := readFile(t, "testdata/knative/golden-a.json")
	runs := map[string]btRun{
		"a": {res: BacktestResult{Class: ClassReproduced}, gen: x, expected: x},
		"b": {res: BacktestResult{Class: ClassReproduced}, expected: x},
	}
	sr := runSeed(btSeed{Entry: "a", Kind: "swap", Other: "b"}, runs)
	if sr.Outcome != "passed" {
		t.Fatalf("%+v", sr)
	}
	var se bytes.Buffer
	rep := BacktestReport{SeedResults: []SeedResult{sr}}
	if code := backtestExit(rep, &se); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestBacktestSeedNotRunIsHarnessFailure(t *testing.T) {
	f := newBT(t)
	e := btEntryMap("nothing", "empty")
	e["expected"] = "expected-alpha.json"
	f.addEntry(e, 3)
	f.m["seeds"] = []any{map[string]any{"entry": "nothing", "kind": "path"}}
	if code, so, _ := f.run(t, btOpen); code != 2 || !strings.Contains(so, "not-run") {
		t.Fatalf("exit %d: %s", code, so)
	}
	// A seed that cannot be built (no exclusion to drop) did not run either.
	f = newBT(t)
	f.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "drop-exclusion"}}
	if code, _, _ := f.run(t, btOpen); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestBacktestUnknownStopCodeIsHarnessError(t *testing.T) {
	old := generate
	defer func() { generate = old }()
	generate = func(Input) (*Result, error) {
		return nil, &StopError{Stops: []Stop{{Code: "invented-code", Next: "x"}}}
	}
	f := newBT(t)
	code, so, _ := f.run(t, btOpen)
	if code != 2 || !strings.Contains(so, "harness-error error=unknown stop code") {
		t.Fatalf("exit %d: %s", code, so)
	}
	generate = func(Input) (*Result, error) { return nil, errors.New("boom") }
	if code, _, _ := f.run(t, btOpen); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestBacktestManifestIsStrict(t *testing.T) {
	bad := map[string]func(f *btFixture){
		"count mismatch":   func(f *btFixture) { f.m["count"] = 3 },
		"unknown field":    func(f *btFixture) { f.m["extra"] = 1 },
		"wrong schema":     func(f *btFixture) { f.m["schema"] = "x" },
		"no seeds":         func(f *btFixture) { f.m["seeds"] = []any{} },
		"unknown seed":     func(f *btFixture) { f.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "other"}} },
		"seed unknown ent": func(f *btFixture) { f.m["seeds"] = []any{map[string]any{"entry": "zzz", "kind": "path"}} },
		"duplicate slug":   func(f *btFixture) { f.addEntry(btEntryMap("alpha", "alpha"), 3) },
		"bad half":         func(f *btFixture) { f.m["entries"].([]any)[0].(map[string]any)["half"] = "C" },
		"mirror path":      func(f *btFixture) { f.m["entries"].([]any)[0].(map[string]any)["mirror"] = "../x" },
	}
	for name, mut := range bad {
		f := newBT(t)
		mut(f)
		if code, _, _ := f.run(t, btOpen); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	// An expected path that escapes the manifest directory is a harness error.
	f := newBT(t)
	f.m["entries"].([]any)[0].(map[string]any)["expected"] = "../expected-alpha.json"
	if code, so, _ := f.run(t, btOpen); code != 2 || !strings.Contains(so, "harness-error") {
		t.Fatalf("exit %d: %s", code, so)
	}
}

func TestBacktestNondeterminismIsHarnessFailure(t *testing.T) {
	f := newBT(t)
	f.m["count"] = 1
	f.m["entries"] = f.m["entries"].([]any)[:1]
	f.m["seeds"] = []any{map[string]any{"entry": "alpha", "kind": "path"}}
	calls := 0
	open := func(dir string) Source {
		calls++
		if calls > 1 {
			return btOpen("empty")
		}
		return btOpen(dir)
	}
	if code, _, se := f.run(t, open); code != 2 || !strings.Contains(se, "not deterministic") {
		t.Fatalf("exit %d: %s", code, se)
	}
}

func TestBacktestUsageAndOutput(t *testing.T) {
	for _, args := range [][]string{{"backtest"}, {"backtest", "--manifest", "m", "--mirrors", "d"}, {"backtest", "--manifest", "m", "--mirrors", "d", "--out", "o", "x"}, {"backtest", "--network", "--manifest", "m"}} {
		var so, se bytes.Buffer
		if code := Run(args, &so, &se); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	f := newBT(t)
	f.write(t)
	out := filepath.Join(t.TempDir(), "o")
	var so, se bytes.Buffer
	args := []string{"backtest", "--manifest", f.manifest, "--mirrors", f.mirrors, "--out", out}
	if code := run(args, &so, &se, btOpen); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if _, err := os.Stat(filepath.Join(out, "backtest.json")); err != nil {
		t.Fatal(err)
	}
	// A non-empty --out is refused.
	if code := run(args, &so, &se, btOpen); code != 2 {
		t.Fatalf("non-empty out: exit %d", code)
	}
}

func TestBacktestSeedCompareErrorIsNotRun(t *testing.T) {
	good := readFile(t, "testdata/knative/golden-a.json")
	// The wrong target cannot be decoded, so the comparison errors: not a rejection.
	runs := map[string]btRun{
		"a": {res: BacktestResult{Class: ClassReproduced}, gen: good, expected: good},
		"b": {res: BacktestResult{Class: ClassReproduced}, expected: []byte("not json")},
	}
	sr := runSeed(btSeed{Entry: "a", Kind: "swap", Other: "b"}, runs)
	if sr.Outcome != "not-run" {
		t.Fatalf("%+v", sr)
	}
	var se bytes.Buffer
	if code := backtestExit(BacktestReport{SeedResults: []SeedResult{sr}}, &se); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestBacktestDigestIndependentOfCheckoutPath(t *testing.T) {
	digest := func() string {
		f := newBT(t)
		// A missing reviewed file puts an error text into the report.
		e := btEntryMap("missing", "alpha")
		e["expected"] = "no-such-file.json"
		f.addEntry(e, 3)
		code, so, _ := f.run(t, btOpen)
		if code != 2 || !strings.Contains(so, "no-such-file.json: not found") {
			t.Fatalf("exit %d: %s", code, so)
		}
		if strings.Contains(so, f.dir) {
			t.Fatalf("absolute path in output: %s", so)
		}
		i := strings.Index(so, "digest=")
		return so[i:]
	}
	if a, b := digest(), digest(); a != b {
		t.Fatalf("digest differs between checkouts: %s vs %s", a, b)
	}
}

// dirBT runs one collapse-shaped entry: the tree is two CRDs in config/crd.
// expected is written to the manifest directory.
func dirBT(t *testing.T, mutate func(e *btEntry), expected []byte, rulesJSON string) (BacktestReport, BacktestResult) {
	t.Helper()
	base, mirrors := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(mirrors, "demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "exp.json"), expected, 0o644); err != nil {
		t.Fatal(err)
	}
	e := btEntry{Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf", Tags: collapseTags, Mirror: "demo", Expected: "exp.json", Half: "A"}
	if rulesJSON != "" {
		if err := os.WriteFile(filepath.Join(base, "rules.json"), []byte(rulesJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		e.Rules = "rules.json"
	}
	mutate(&e)
	m := &btManifest{Schema: BacktestSchema, Count: 1, Entries: []btEntry{e}, Seeds: []btSeed{{Entry: "demo", Kind: "path"}}}
	rep := Backtest(m, "d", base, mirrors, func(string) Source { return collapseSource(nil) })
	return rep, rep.Results[0]
}

func genCollapsed(t *testing.T, collapse bool) []byte {
	t.Helper()
	res, err := Generate(collapseInputFor(collapseSource(nil), collapse))
	if err != nil {
		t.Fatal(err)
	}
	return res.A
}

func TestBacktestDirectoryEntryIsComparedByBytes(t *testing.T) {
	want := genCollapsed(t, true)
	if !bytes.Contains(want, []byte(`"directory": true`)) && !bytes.Contains(want, []byte(`"directory":true`)) {
		t.Fatalf("fixture has no directory entry: %s", want)
	}
	rep, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories = true }, want, "")
	if r.Class != ClassReproduced || rep.Reproduced != 1 || rep.SeedsFailed != 1 {
		t.Fatalf("%+v %+v", r, rep)
	}
}

func TestBacktestExactFilesAgainstShippedDirectoryIsDiffers(t *testing.T) {
	// The generator runs without collapse: it emits exact files.
	rep, r := dirBT(t, func(e *btEntry) {}, genCollapsed(t, true), "")
	if r.Class != ClassDiffers || r.Cause == CauseFormatGap || rep.Reproduced != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestBacktestDirectoryWithNonDefaultMatchOrGuardStaysFormatGap(t *testing.T) {
	good := genCollapsed(t, true)
	for name, from := range map[string]string{
		"match": DefaultDirMatch, "guard": DefaultDirGuard,
	} {
		esc, _ := json.Marshal(from)
		bad := bytes.Replace(good, esc, []byte(`"x"`), 1)
		if bytes.Equal(bad, good) {
			t.Fatalf("%s: fixture not changed", name)
		}
		_, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories = true }, bad, "")
		if r.Class != ClassDiffers || r.Cause != CauseFormatGap {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// An extra key on a directory entry is also a gap.
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["target"].(map[string]any)["paths"].([]any)
	paths[0].(map[string]any)["recursive"] = true
	extra, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories = true }, extra, ""); r.Class != ClassDiffers || r.Cause != CauseFormatGap || !strings.Contains(strings.Join(r.Fields, ","), "paths.recursive") {
		t.Errorf("%+v", r)
	}
}

func TestBacktestOptionsReachTheGenerator(t *testing.T) {
	var got Input
	old := generate
	defer func() { generate = old }()
	generate = func(in Input) (*Result, error) {
		got = in
		return old(in)
	}
	dirBT(t, func(e *btEntry) { e.CollapseDirectories, e.DeriveDuplicateSources, e.MultiPrefix = true, true, true }, genCollapsed(t, true), "")
	if !got.CollapseDirectories || !got.DeriveDuplicates || !got.MultiPrefix {
		t.Fatalf("%+v", got)
	}
	got = Input{}
	dirBT(t, func(e *btEntry) {}, genCollapsed(t, false), "")
	if got.CollapseDirectories || got.DeriveDuplicates || got.MultiPrefix {
		t.Fatalf("defaults must stay off: %+v", got)
	}
}

func TestBacktestOracleIsLabelledAndNotStrict(t *testing.T) {
	var got Input
	old := generate
	defer func() { generate = old }()
	generate = func(in Input) (*Result, error) {
		got = in
		return old(in)
	}
	rep, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories, e.OraclePaths = true, true }, genCollapsed(t, true), "")
	if r.Class != ClassReproducedOracle || !r.Oracle || rep.Reproduced != 0 || rep.OracleRepro != 1 || rep.SeedsFailed != 1 {
		t.Fatalf("%+v %+v", r, rep)
	}
	if got.Rules == nil || len(got.Rules.InstallPaths) != 1 || got.Rules.InstallPaths[0].Path != "config/crd/" {
		t.Fatalf("%+v", got.Rules)
	}
	// Without the flag the entry is inferred, not oracle.
	if _, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories = true }, genCollapsed(t, true), ""); r.Oracle || r.Class != ClassReproduced {
		t.Fatalf("%+v", r)
	}
}

func TestBacktestOracleNegatives(t *testing.T) {
	// A reviewed target that differs elsewhere is not an oracle reproduction.
	bad := bytes.Replace(genCollapsed(t, true), []byte(`"minFrom": "1.0"`), []byte(`"minFrom": "1.1"`), 1)
	if _, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories, e.OraclePaths = true, true }, bad, ""); r.Class != ClassDiffers || !r.Oracle {
		t.Errorf("%+v", r)
	}
	// Rules that already carry installPaths are refused, never merged.
	rules := `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[],"installPaths":[{"path":"config/crd/","reason":"r","evidence":"e"}]}`
	if _, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories, e.OraclePaths = true, true }, genCollapsed(t, true), rules); r.Class != ClassHarnessError {
		t.Errorf("%+v", r)
	}
	// A reviewed target without paths cannot feed an oracle.
	empty := []byte(`{"schema":"prufyx.io/crd-version-target/v1","target":{"project":"demo","paths":[]}}`)
	if _, r := dirBT(t, func(e *btEntry) { e.OraclePaths = true }, empty, ""); r.Class != ClassHarnessError {
		t.Errorf("%+v", r)
	}
}

func TestBacktestOracleRefusesInstallSurfaceRules(t *testing.T) {
	rules := `{"schema":"` + RulesSchema + `","installSurface":[{"path":"config/crd/a.yaml","reason":"r"}],"exclusions":[]}`
	if _, r := dirBT(t, func(e *btEntry) { e.CollapseDirectories, e.OraclePaths = true, true }, genCollapsed(t, true), rules); r.Class != ClassHarnessError || !strings.Contains(r.Error, "installSurface") {
		t.Errorf("%+v", r)
	}
}

func TestBacktestOracleWithExclusionsIsOracleNotCircular(t *testing.T) {
	rules := `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"third_party/x/other.yaml","reason":"third-party bundle","evidence":"pinned"}]}`
	src := func() memSource {
		return collapseSource(func(_ string, m *memTree) {
			m.files["third_party/x/other.yaml"] = crdText("other.example.invalid", "Other")
		})
	}
	r0, err := ParseRules([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	in := collapseInputFor(src(), false)
	in.Rules = r0
	res, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	base, mirrors := t.TempDir(), t.TempDir()
	for _, d := range []string{"demo"} {
		if err := os.Mkdir(filepath.Join(mirrors, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for n, c := range map[string]string{"exp.json": string(res.A), "rules.json": rules} {
		if err := os.WriteFile(filepath.Join(base, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(oracle bool) btEntry {
		return btEntry{Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf", Tags: collapseTags, Mirror: "demo",
			Rules: "rules.json", Expected: "exp.json", Half: "A", OraclePaths: oracle}
	}
	run := func(oracle bool) BacktestReport {
		m := &btManifest{Schema: BacktestSchema, Count: 1, Entries: []btEntry{entry(oracle)}, Seeds: []btSeed{{Entry: "demo", Kind: "path"}}}
		return Backtest(m, "d", base, mirrors, func(string) Source { return src() })
	}
	// Control: without the oracle the exclusions make the entry circular.
	if rep := run(false); rep.Results[0].Class != ClassReproducedCircular || rep.Circular != 1 {
		t.Fatalf("control: %+v", rep.Results)
	}
	rep := run(true)
	if rep.Results[0].Class != ClassReproducedOracle || rep.Reproduced != 0 || rep.Circular != 0 || rep.OracleRepro != 1 {
		t.Fatalf("%+v", rep.Results)
	}
}

func TestBacktestSummaryLineCountsOracle(t *testing.T) {
	f := newBT(t)
	f.m["entries"].([]any)[0].(map[string]any)["oraclePaths"] = true
	code, so, se := f.run(t, btOpen)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, so, se)
	}
	for _, want := range []string{"alpha reproduced-oracle\n", "beta reproduced\n", "strict=1/2 reachable=1/2 circular=0 oracle=1 "} {
		if !strings.Contains(so, want) {
			t.Errorf("missing %q in %s", want, so)
		}
	}
}
