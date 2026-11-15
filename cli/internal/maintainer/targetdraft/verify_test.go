// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fxDir = "cli/knowledge/target-recipes/demo/"

type fixture struct {
	t      *testing.T
	files  map[string][]byte // name inside the recipe directory
	recipe Recipe
	bundle []byte
	env    verifyEnv
	base   map[string][]byte // full relative path -> bytes, base tree
	paths  []string          // override of the changed list, full paths
	rawOut []byte            // override of the raw list
}

func (f *fixture) recipeBytes() []byte {
	b, err := json.MarshalIndent(f.recipe, "", " ")
	if err != nil {
		f.t.Fatal(err)
	}
	return append(b, '\n')
}

// newFixture builds a clean pure-regeneration PR for a synthetic project.
func newFixture(t *testing.T, mutate func(tag string, m *memTree)) *fixture {
	t.Helper()
	mk := func(s Source) Input { return collapseInputFor(s, true) }
	raw, _ := recordBundle(t, collapseSource(mutate), mk)
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, mk(FactSource{B: b}))
	rep, _ := marshal(res.Report)
	f := &fixture{t: t, bundle: raw, env: defaultVerifyEnv(), base: map[string][]byte{}, files: map[string][]byte{
		"facts.bundle": raw, "target-demo.json": res.A, "report.json": rep, "table-row.json": res.TableRow, "changelog.md": res.Changelog,
	}}
	f.recipe = Recipe{Schema: RecipeSchema, Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf",
		Tags: collapseTags, RangeCheckTags: []string{}, CollapseDirectories: true, Half: "A", Exclude: []string{},
		FactBundleDigest: sha256Of(raw)}
	for _, tag := range b.Tags() {
		c, _ := b.Commit(tag)
		f.recipe.Commits = append(f.recipe.Commits, recipeCommit{Tag: tag, Commit: c})
	}
	return f
}

func (f *fixture) setBundle(raw []byte, fixDigest bool) {
	f.files["facts.bundle"] = raw
	if fixDigest {
		f.recipe.FactBundleDigest = sha256Of(raw)
	}
}

func changedRaw(paths []string, status, oldMode, newMode string) []byte {
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, ":%s %s %s %s %s\x00%s\x00", oldMode, newMode, strings.Repeat("0", 40), strings.Repeat("1", 40), status, p)
	}
	return b.Bytes()
}

func (f *fixture) names() []string {
	var n []string
	for k := range f.files {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func writeTree(t *testing.T, root string, files map[string][]byte) {
	for p, b := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// dirs writes head and base and returns the input.
func (f *fixture) input() (VerifyInput, string, string) {
	f.t.Helper()
	files := map[string][]byte{}
	if _, ok := f.files["recipe.json"]; !ok {
		f.files["recipe.json"] = f.recipeBytes()
	}
	for n, b := range f.files {
		files[fxDir+n] = b
	}
	head, base := f.t.TempDir(), f.t.TempDir()
	writeTree(f.t, head, files)
	writeTree(f.t, base, f.base)
	var full []string
	for _, n := range f.names() {
		full = append(full, fxDir+n)
	}
	if f.paths != nil {
		full = f.paths
	}
	raw := changedRaw(full, "A", "000000", "100644")
	if f.rawOut != nil {
		raw = f.rawOut
	}
	return VerifyInput{BaseDir: base, HeadDir: head, ChangedRaw: raw}, head, base
}

func (f *fixture) verify() (*VerifyResult, *VerifyFailure) {
	in, _, _ := f.input()
	return verifyPR(in, f.env)
}

func wantFail(t *testing.T, f *fixture, code string) *VerifyFailure {
	t.Helper()
	res, fl := f.verify()
	if fl == nil {
		t.Fatalf("accepted (want %s): %+v", code, res)
	}
	if fl.Code != code {
		t.Fatalf("code %s (%s), want %s", fl.Code, fl.Detail, code)
	}
	return fl
}

func TestVerifyPRPassesCleanRegeneration(t *testing.T) {
	f := newFixture(t, nil)
	res, fl := f.verify()
	if fl != nil {
		t.Fatalf("%v", fl)
	}
	if res.AutoMerge || res.RecipeChange != "new" || res.Slug != "demo" || res.Half != "A" {
		t.Fatalf("%+v", res)
	}
	if len(res.Reasons) == 0 || !strings.Contains(res.Reasons[0], "upstream binding: not verified") {
		t.Fatalf("report must name the missing upstream binding: %v", res.Reasons)
	}
}

func TestVerifyPRHalfBIsComparedToHalfB(t *testing.T) {
	f := newFixture(t, nil)
	f.recipe.Half = "B"
	wantFail(t, f, "target-differs") // the claimed file is half A
	res := mustGenerate(t, collapseInputFor(FactSource{B: mustBundle(t, f.bundle)}, true))
	f.files["target-demo.json"] = res.B
	if bytes.Equal(res.A, res.B) {
		t.Skip("halves are equal here")
	}
	if _, fl := f.verify(); fl != nil {
		t.Fatal(fl)
	}
}

func mustBundle(t *testing.T, raw []byte) *Bundle {
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyPRRecipeChangeIsNeverAutoMergeable(t *testing.T) {
	f := newFixture(t, nil)
	f.base[fxDir+"recipe.json"] = f.recipeBytes()
	res, fl := f.verify()
	if fl != nil || res.RecipeChange != "unchanged" || res.AutoMerge {
		t.Fatalf("%v %+v", fl, res)
	}
	if len(res.Reasons) != 1 {
		t.Fatalf("an unchanged recipe is still held back only by the missing binding: %v", res.Reasons)
	}
	// Base recipe differs from head: changed, never eligible, with the reason.
	f.base[fxDir+"recipe.json"] = append(f.recipeBytes(), ' ')
	res, fl = f.verify()
	if fl != nil || res.RecipeChange != "changed" || res.AutoMerge || len(res.Reasons) != 2 || !strings.Contains(res.Reasons[1], "changed") {
		t.Fatalf("%v %+v", fl, res)
	}
	// A base with rules.json where the head has none is a changed recipe too.
	f.base[fxDir+"recipe.json"] = f.recipeBytes()
	f.base[fxDir+"rules.json"] = []byte("{}")
	res, fl = f.verify()
	if fl != nil || res.RecipeChange != "changed" || res.AutoMerge {
		t.Fatalf("%v %+v", fl, res)
	}
}

func TestVerifyPRTamperedOutputs(t *testing.T) {
	for name, tc := range map[string]struct {
		file, code string
		edit       func([]byte) []byte
	}{
		"target trailing space": {"target-demo.json", "target-differs", func(b []byte) []byte { return append(b, ' ') }},
		"target minFrom": {"target-demo.json", "target-differs", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"minFrom": "1.0"`), []byte(`"minFrom": "1.1"`), 1)
		}},
		"target key order": {"target-demo.json", "target-differs", func(b []byte) []byte { return bytes.Replace(b, []byte(`"name": "Demo",`+"\n"), nil, 1) }},
		"report":           {"report.json", "report-differs", func(b []byte) []byte { return append(b, '\n') }},
		"table row":        {"table-row.json", "table-row-differs", func(b []byte) []byte { return append(b, '\n') }},
		"changelog":        {"changelog.md", "changelog-differs", func(b []byte) []byte { return append(b, 'x') }},
		"target not json":  {"target-demo.json", "target-invalid", func([]byte) []byte { return []byte("{") }},
		"target unknown field": {"target-demo.json", "target-invalid", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"exclude": []`), []byte(`"exclude": [], "mutate": true`), 1)
		}},
		"target extra exclusion": {"target-demo.json", "exclusion-present", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"exclude": []`), []byte(`"exclude": [{"path":"x","repo":"r","reason":"a","evidence":"b"}]`), 1)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.files[tc.file] = tc.edit(append([]byte(nil), f.files[tc.file]...))
			wantFail(t, f, tc.code)
		})
	}
}

func TestVerifyPRBundleAttacks(t *testing.T) {
	flipBlob := func(d *bundleDoc) {
		i := objIndex(d, "blob")
		body, _ := base64.StdEncoding.DecodeString(d.Objects[i].Data)
		d.Objects[i].Data = base64.StdEncoding.EncodeToString(append(body, '#'))
	}
	// Tampered blob, digest not updated: caught by the digest.
	f := newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, flipBlob), false)
	wantFail(t, f, "bundle-digest")
	// The attacker also updates the digest: caught by the object hash.
	f = newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, flipBlob), true)
	wantFail(t, f, "bundle-invalid")
	// Tampered tree with the digest updated.
	f = newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, func(d *bundleDoc) {
		i := objIndex(d, "tree")
		body, _ := base64.StdEncoding.DecodeString(d.Objects[i].Data)
		body[len(body)-1] ^= 1
		d.Objects[i].Data = base64.StdEncoding.EncodeToString(body)
	}), true)
	wantFail(t, f, "bundle-invalid")
	// Commit that names another tree (rehashed, tag and recipe updated).
	f = newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, func(d *bundleDoc) {
		old := d.Tags[2].Commit
		var nid string
		for i, o := range d.Objects {
			if o.ID != old {
				continue
			}
			body, _ := base64.StdEncoding.DecodeString(o.Data)
			body = append([]byte("tree "+strings.Repeat("a", 40)), body[45:]...)
			nid = objectID("commit", body)
			d.Objects[i] = bundleObj{ID: nid, Kind: "commit", Data: base64.StdEncoding.EncodeToString(body)}
		}
		d.Tags[2].Commit = nid
		f.recipe.Commits[2].Commit = nid
		sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].ID < d.Objects[j].ID })
	}), true)
	wantFail(t, f, "bundle-invalid")
	// A wrong claimed commit in the recipe.
	f = newFixture(t, nil)
	f.recipe.Commits[0].Commit = strings.Repeat("c", 40)
	wantFail(t, f, "bundle-commit")
	// A tag in the bundle the recipe does not name (and the reverse).
	f = newFixture(t, nil)
	f.recipe.Tags = f.recipe.Tags[:3]
	f.recipe.Commits = f.recipe.Commits[:3]
	wantFail(t, f, "bundle-tags")
	// An extra object.
	f = newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, func(d *bundleDoc) {
		body := []byte("extra\n")
		d.Objects = append(d.Objects, bundleObj{ID: objectID("blob", body), Kind: "blob", Data: base64.StdEncoding.EncodeToString(body)})
		sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].ID < d.Objects[j].ID })
	}), true)
	wantFail(t, f, "bundle-invalid")
	// A read blob dropped: the bundle verifies, the replay needs it: an error, never empty.
	f = newFixture(t, nil)
	f.setBundle(rebundle(t, f.bundle, func(d *bundleDoc) {
		i := objIndex(d, "blob")
		d.Objects = append(d.Objects[:i], d.Objects[i+1:]...)
	}), true)
	wantFail(t, f, "typed-stop")
	// Oversize bundle file.
	f = newFixture(t, nil)
	f.setBundle(bytes.Repeat([]byte(" "), MaxBundleBytes+1), true)
	wantFail(t, f, "file-unreadable")
}

func TestVerifyPRRecipeAttacks(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(f *fixture)
		code string
	}{
		"unknown field": {func(f *fixture) {
			f.files["recipe.json"] = bytes.Replace(f.recipeBytes(), []byte(`"slug"`), []byte(`"extra": 1, "slug"`), 1)
		}, "recipe-invalid"},
		"exclude not empty":  {func(f *fixture) { f.recipe.Exclude = []string{"x"} }, "recipe-invalid"},
		"bad schema":         {func(f *fixture) { f.recipe.Schema = "x" }, "recipe-invalid"},
		"bad half":           {func(f *fixture) { f.recipe.Half = "C" }, "recipe-invalid"},
		"rules other name":   {func(f *fixture) { f.recipe.Rules = "../rules.json" }, "recipe-invalid"},
		"rules named absent": {func(f *fixture) { f.recipe.Rules = "rules.json" }, "recipe-invalid"},
		"rules file unnamed": {func(f *fixture) { f.files["rules.json"] = []byte("{}") }, "recipe-invalid"},
		"too many tags": {func(f *fixture) {
			for i := 0; i < 13; i++ {
				f.recipe.RangeCheckTags = append(f.recipe.RangeCheckTags, fmt.Sprintf("v9.%d.0", i))
			}
		}, "recipe-invalid"},
		"bad digest":     {func(f *fixture) { f.recipe.FactBundleDigest = "x" }, "recipe-invalid"},
		"digest differs": {func(f *fixture) { f.recipe.FactBundleDigest = strings.Repeat("0", 64) }, "bundle-digest"},
		"slug mismatch":  {func(f *fixture) { f.recipe.Slug = "other" }, "recipe-slug-mismatch"},
		"recipe oversize": {func(f *fixture) {
			f.files["recipe.json"] = bytes.Repeat([]byte(" "), MaxRecipeBytes+1)
		}, "file-unreadable"},
		"recipe missing tag commit": {func(f *fixture) { f.recipe.Commits = f.recipe.Commits[1:] }, "recipe-invalid"},
		"duplicate tag":             {func(f *fixture) { f.recipe.Tags = append(f.recipe.Tags, f.recipe.Tags[0]) }, "recipe-invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			tc.edit(f)
			wantFail(t, f, tc.code)
		})
	}
}

func TestVerifyPRExclusionsAndStopsAreNeverAccepted(t *testing.T) {
	// Rules that carry an exclusion (the reviewed knative rules).
	f := newFixture(t, nil)
	f.recipe.Rules = "rules.json"
	f.files["rules.json"] = readFile(t, "testdata/knative/rules.json")
	wantFail(t, f, "exclusion-present")
	// Rules that do not parse.
	f = newFixture(t, nil)
	f.recipe.Rules = "rules.json"
	f.files["rules.json"] = []byte(`{"schema":"x"}`)
	wantFail(t, f, "rules-invalid")
	// A typed stop at regeneration time: a community row without the pinned
	// upstream block cannot be generated.
	f = newFixture(t, nil)
	f.recipe.Catalog = "community"
	if _, fl := f.verify(); fl == nil || fl.Code != "typed-stop" || !strings.Contains(fl.Detail, StopCommunityUpstream) {
		t.Fatalf("want a typed stop, got %v", fl)
	}
}

func TestVerifyPRChangedPathAllowlist(t *testing.T) {
	ok := []string{fxDir + "recipe.json", fxDir + "facts.bundle", fxDir + "target-demo.json", fxDir + "report.json", fxDir + "table-row.json", fxDir + "changelog.md"}
	with := func(extra ...string) []string { return append(append([]string(nil), ok...), extra...) }
	for name, paths := range map[string][]string{
		"workflow":        with(".github/workflows/x.yml"),
		"codeowners":      with(".github/CODEOWNERS"),
		"other target":    with("cli/internal/extract/crdversions/target-demo.json"),
		"trust":           with("cli/knowledge/trust/root.json"),
		"verifier itself": with("cli/internal/maintainer/targetdraft/verify.go"),
		"dot dot":         with(RecipesRoot + "demo/../../x"),
		"dot dot slug":    with(RecipesRoot + "../demo/recipe.json"),
		"nested":          with(fxDir + "sub/recipe.json"),
		"unknown file":    with(fxDir + "notes.md"),
		"case variant":    with(fxDir + "Recipe.json"),
		"other slug":      with(RecipesRoot + "other/recipe.json"),
		"bad slug":        with(RecipesRoot + "Demo/recipe.json"),
		"root dir file":   with(RecipesRoot + "recipe.json"),
		"duplicate path":  with(ok[0]),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.paths = paths
			if _, fl := f.verify(); fl == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, tc := range map[string]struct{ status, oldMode, newMode string }{
		"delete":      {"D", "100644", "000000"},
		"rename":      {"R100", "100644", "100644"},
		"copy":        {"C100", "100644", "100644"},
		"mode change": {"M", "100644", "100755"},
		"executable":  {"A", "000000", "100755"},
		"symlink":     {"A", "000000", "120000"},
		"submodule":   {"A", "000000", "160000"},
		"type change": {"T", "100644", "120000"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rawOut = changedRaw(ok[:1], tc.status, tc.oldMode, tc.newMode)
			wantFail(t, f, "path-status")
		})
	}
	for name, raw := range map[string][]byte{
		"empty":         {},
		"no terminator": []byte(":000000 100644 " + strings.Repeat("0", 40) + " " + strings.Repeat("1", 40) + " A"),
		"short record":  []byte(":000000 100644 A\x00" + ok[0] + "\x00"),
		"abbreviated":   []byte(":000000 100644 abc def A\x00" + ok[0] + "\x00"),
		"garbage":       []byte("x\x00y\x00"),
	} {
		t.Run("raw "+name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rawOut = raw
			if _, fl := f.verify(); fl == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Two slugs in one PR.
	f := newFixture(t, nil)
	f.paths = with(RecipesRoot + "other/recipe.json")
	wantFail(t, f, "multiple-slugs")
	// A modified (not only added) path is fine.
	f = newFixture(t, nil)
	f.rawOut = changedRaw(ok, "M", "100644", "100644")
	if _, fl := f.verify(); fl != nil {
		t.Fatal(fl)
	}
}

func TestVerifyPRHeadTreeShape(t *testing.T) {
	// A file in the head recipe directory that is not an allowed name.
	f := newFixture(t, nil)
	f.files["notes.md"] = []byte("x")
	f.paths = []string{fxDir + "recipe.json"}
	wantFail(t, f, "path-not-allowed")
	// A required file missing.
	f = newFixture(t, nil)
	delete(f.files, "changelog.md")
	wantFail(t, f, "file-missing")
	// A symbolic link where a file belongs.
	f = newFixture(t, nil)
	in, head, _ := f.input()
	p := filepath.Join(head, fxDir, "changelog.md")
	os.Remove(p)
	if err := os.Symlink("report.json", p); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "path-not-allowed" {
		t.Fatalf("%v", fl)
	}
}

func TestVerifyPRSeedsGateTheResult(t *testing.T) {
	// A vacuous comparison reproduces the wrong target: exit 1 class.
	f := newFixture(t, nil)
	f.env.compare = func(g, r []byte) ([]string, error) { return nil, nil }
	fl := wantFail(t, f, "seed-reproduced")
	if fl.Harness {
		t.Fatal("a reproduced seed is an assertion failure (exit 1)")
	}
	// A seed whose comparison cannot run: harness failure (exit 2), never a pass.
	f = newFixture(t, nil)
	calls := 0
	f.env.compare = func(g, r []byte) ([]string, error) {
		calls++
		return nil, errors.New("boom")
	}
	fl = wantFail(t, f, "seed-cannot-run")
	if !fl.Harness || calls == 0 {
		t.Fatal("a seed that cannot run is a harness failure")
	}
	// Seed builders refuse a target with nothing to flip.
	if _, err := seedExpected(btSeed{Kind: "path"}, []byte(`{"schema":"prufyx.io/crd-version-target/v1","target":{"project":"d","name":"D","repo":"r","component":"c","factProject":"d","tagPrefixes":["v"],"minFrom":"1.0","paths":[],"exclude":[]}}`), nil); err == nil {
		t.Fatal("no path to flip must be an error")
	}
}

func TestVerifyPRNonDeterministicGeneratorFails(t *testing.T) {
	f := newFixture(t, nil)
	n := 0
	f.env.generate = func(in Input) (*Result, error) {
		r, err := Generate(in)
		n++
		if err == nil && n == 2 {
			r.Changelog = append(append([]byte(nil), r.Changelog...), 'x')
		}
		return r, err
	}
	wantFail(t, f, "non-deterministic")
	f = newFixture(t, nil)
	f.env.generate = func(Input) (*Result, error) { panic("boom") }
	wantFail(t, f, "generator-panic")
}

func TestRunVerifyPRExitCodesAndDeterminism(t *testing.T) {
	f := newFixture(t, nil)
	in, head, base := f.input()
	list := filepath.Join(t.TempDir(), "changed.raw")
	if err := os.WriteFile(list, in.ChangedRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb, nil)
		return code, out.String() + errb.String()
	}
	code, out1 := run("verify-pr", "--base", base, "--head", head, "--changed-paths", list)
	if code != 0 || !strings.Contains(out1, "upstream binding: not verified") || !strings.Contains(out1, "auto-merge: not eligible") {
		t.Fatalf("%d %s", code, out1)
	}
	if strings.Contains(out1, "eligible: yes") || strings.Contains(strings.ReplaceAll(out1, "not eligible", ""), "eligible") {
		t.Fatalf("an eligible verdict must never be printed: %s", out1)
	}
	if code2, out2 := run("verify-pr", "--base", base, "--head", head, "--changed-paths", list); code2 != 0 || out2 != out1 {
		t.Fatal("two runs must print the same bytes")
	}
	// Assertion failure: exit 1 with the typed reason.
	if err := os.WriteFile(filepath.Join(head, fxDir, "changelog.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := run("verify-pr", "--base", base, "--head", head, "--changed-paths", list); code != 1 || !strings.Contains(out, "FAIL changelog-differs") || !strings.Contains(out, "upstream binding: not verified") {
		t.Fatalf("%d %s", code, out)
	}
	// Harness and usage problems: exit 2.
	for _, args := range [][]string{
		{"verify-pr"},
		{"verify-pr", "--base", base, "--head", head},
		{"verify-pr", "--base", base, "--head", head, "--changed-paths", filepath.Join(t.TempDir(), "absent")},
		{"verify-pr", "--base", base, "--head", head, "--changed-paths", list, "--extra"},
		{"verify-pr", "--base", base, "--head", head, "--changed-paths", list, "stray"},
	} {
		if code, out := run(args...); code != 2 {
			t.Fatalf("%v: %d %s", args, code, out)
		}
	}
}
