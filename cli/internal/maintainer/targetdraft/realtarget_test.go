// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// upstreamFor answers ls-remote for the fixture's window, lightweight tags.
func (f *fixture) upstreamFor() *fakeRunner {
	var lines []string
	for _, c := range f.recipe.Commits {
		lines = append(lines, c.Commit+"\trefs/tags/"+c.Tag)
	}
	return &fakeRunner{results: []ExecResult{okRun(lsOut(lines...))}}
}

// bound runs verifyPR with the binding on, the recipe unchanged against base.
func (f *fixture) unchangedRecipe() {
	f.files["recipe.json"] = f.recipeBytes()
	f.base[fxDir+"recipe.json"] = f.recipeBytes()
	f.paths = f.withoutPaths("recipe.json")
}

func (f *fixture) verifyBound(run LsRemoteRunner) (*VerifyResult, *VerifyFailure) {
	in, _, _ := f.input()
	in.Upstream, in.BaseSHA, in.HeadSHA = run, hx('2'), bHead
	in.Sleep = func(time.Duration) {}
	return verifyPR(in, f.env)
}

func TestVerifyPRBindingVerifiedAndEligibleOnlyWhenRecipeUnchanged(t *testing.T) {
	// Unchanged recipe plus verified binding: eligible class, never merged.
	f := newFixture(t, nil)
	f.unchangedRecipe()
	run := f.upstreamFor()
	res, fl := f.verifyBound(run)
	if fl != nil {
		t.Fatal(fl)
	}
	if !res.BindingVerified || !res.Eligible || res.AutoMerge || res.Binding == nil || res.Binding.HeadSHA != bHead || res.HeadSHA != bHead || res.BaseSHA != hx('2') {
		t.Fatalf("%+v", res)
	}
	if res.RecipeChange != "unchanged" || len(res.Binding.Tags) != len(f.recipe.Commits) || len(run.calls) != 1 {
		t.Fatalf("%+v %d", res, len(run.calls))
	}
	// A new recipe (first onboarding) is valid and bound but a human class.
	f = newFixture(t, nil)
	res, fl = f.verifyBound(f.upstreamFor())
	if fl != nil || !res.BindingVerified || res.Eligible || res.AutoMerge || res.RecipeChange != "new" {
		t.Fatalf("%v %+v", fl, res)
	}
	// A changed recipe likewise.
	f = newFixture(t, nil)
	f.base[fxDir+"recipe.json"] = append(f.recipeBytes(), ' ')
	res, fl = f.verifyBound(f.upstreamFor())
	if fl != nil || !res.BindingVerified || res.Eligible || res.RecipeChange != "changed" {
		t.Fatalf("%v %+v", fl, res)
	}
	// Binding off: never bound, never eligible, no exec.
	f = newFixture(t, nil)
	f.unchangedRecipe()
	in, _, _ := f.input()
	res, fl = verifyPR(in, f.env)
	if fl != nil || res.BindingVerified || res.Eligible || res.Binding != nil {
		t.Fatalf("%v %+v", fl, res)
	}
	// A moved tag upstream is a typed failure, not a pass.
	f = newFixture(t, nil)
	f.unchangedRecipe()
	moved := f.upstreamFor()
	moved.results = []ExecResult{okRun(strings.Replace(string(moved.results[0].Stdout), f.recipe.Commits[0].Commit, hx('9'), 1))}
	if _, fl = f.verifyBound(moved); fl == nil || fl.Code != "binding-mismatch" || fl.Harness {
		t.Fatalf("%v", fl)
	}
	// Unreachable upstream: harness class, never a pass.
	f = newFixture(t, nil)
	f.unchangedRecipe()
	down := &fakeRunner{results: []ExecResult{errRun(128, "returned error: 503")}}
	if _, fl = f.verifyBound(down); fl == nil || fl.Code != "binding-unavailable" || !fl.Harness || len(down.calls) != 3 {
		t.Fatalf("%v", fl)
	}
}

func TestVerifyPRBindingNeedsShasAndRunsLast(t *testing.T) {
	f := newFixture(t, nil)
	in, _, _ := f.input()
	run := f.upstreamFor()
	in.Upstream = run
	for name, shas := range map[string][2]string{"none": {"", ""}, "no head": {hx('2'), ""}, "no base": {"", bHead}, "upper": {hx('2'), strings.Repeat("A", 40)}} {
		in.BaseSHA, in.HeadSHA = shas[0], shas[1]
		if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "binding-input" || !fl.Harness {
			t.Fatalf("%s: %v", name, fl)
		}
	}
	if len(run.calls) != 0 {
		t.Fatal("no exec without both ids")
	}
	// A PR that fails a local check never reaches the network.
	f = newFixture(t, nil)
	f.files["changelog.md"] = []byte("x")
	run = f.upstreamFor()
	if _, fl := f.verifyBound(run); fl == nil || fl.Code != "changelog-differs" {
		t.Fatalf("%v", fl)
	}
	if len(run.calls) != 0 {
		t.Fatal("the binding runs only after every local check passed")
	}
}

func TestVerifyPRRealTargetAssertions(t *testing.T) {
	// The real target is missing from head.
	f := newFixture(t, nil)
	delete(f.files, "target-demo.json")
	f.files["recipe.json"] = f.recipeBytes()
	f.paths = f.withoutPaths("target-demo.json")
	wantFail(t, f, "file-missing")
	// One byte off, whitespace, key order.
	for name, mut := range map[string]func([]byte) []byte{
		"byte":  func(b []byte) []byte { return append(b, '\n') },
		"space": func(b []byte) []byte { return bytes.Replace(b, []byte(`"name": "Demo"`), []byte(`"name":  "Demo"`), 1) },
		"order": func(b []byte) []byte { return bytes.Replace(b, []byte(`"name": "Demo",`+"\n"), nil, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.files["target-demo.json"] = mut(f.files["target-demo.json"])
			if _, fl := f.verify(); fl == nil || (fl.Code != "target-differs" && fl.Code != "target-invalid") {
				t.Fatalf("%v", fl)
			}
		})
	}
	// The in-recipe copy equals the verified half and the real target is
	// wrong: still red (the copy is not the source of truth).
	f = newFixture(t, nil)
	in, head, _ := f.input()
	good := f.files["target-demo.json"]
	if err := os.WriteFile(filepath.Join(head, realDemo), append(append([]byte(nil), good...), ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(head, fxDir, "target-demo.json"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "path-not-allowed" {
		t.Fatalf("%v", fl)
	}
	// The in-recipe copy alone is refused even when the real target is right.
	f = newFixture(t, nil)
	in, head, _ = f.input()
	if err := os.WriteFile(filepath.Join(head, fxDir, "target-demo.json"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "path-not-allowed" {
		t.Fatalf("%v", fl)
	}
	// A symlink where the real target belongs.
	f = newFixture(t, nil)
	in, head, _ = f.input()
	p := filepath.Join(head, realDemo)
	os.Remove(p)
	if err := os.Symlink("../../../knowledge/x", p); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil {
		t.Fatal("accepted a symlinked real target")
	}
	// The real target is executable.
	f = newFixture(t, nil)
	in, head, _ = f.input()
	if err := os.Chmod(filepath.Join(head, realDemo), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "exec-bit" {
		t.Fatalf("%v", fl)
	}
	// A recipe-dir file is executable and the caller's list omits it.
	f = newFixture(t, nil)
	in, head, _ = f.input()
	if err := os.Chmod(filepath.Join(head, fxDir, "changelog.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "exec-bit" {
		t.Fatalf("%v", fl)
	}
	// Changed list and exports disagree on the real target: omitted, or named
	// while identical to base.
	f = newFixture(t, nil)
	f.paths = f.withoutPaths("target-demo.json")
	wantFail(t, f, "changed-list-inconsistent")
	f = newFixture(t, nil)
	f.base[realDemo] = f.files["target-demo.json"]
	wantFail(t, f, "changed-list-inconsistent")
	// Same bytes in base but executable there: a mode change the list hides.
	f = newFixture(t, nil)
	f.base[realDemo] = f.files["target-demo.json"]
	f.paths = f.withoutPaths("target-demo.json")
	in, _, base := f.input()
	if err := os.Chmod(filepath.Join(base, realDemo), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "changed-list-inconsistent" {
		t.Fatalf("%v", fl)
	}
	// Same bytes and unlisted: a regeneration that changed nothing passes.
	f = newFixture(t, nil)
	f.base[realDemo] = f.files["target-demo.json"]
	f.paths = f.withoutPaths("target-demo.json")
	if _, fl := f.verify(); fl != nil {
		t.Fatal(fl)
	}
	// Modified real target (M) passes when it is the verified half.
	f = newFixture(t, nil)
	f.base[realDemo] = append(append([]byte(nil), f.files["target-demo.json"]...), ' ')
	in, _, _ = f.input()
	in.ChangedRaw = changedRaw(f.names2(), "M", "100644", "100644")
	if res, fl := verifyPR(in, f.env); fl != nil || res == nil {
		t.Fatal(fl)
	}
}

// names2 lists full paths of all fixture files.
func (f *fixture) names2() []string {
	var out []string
	for _, n := range f.names() {
		out = append(out, full(n))
	}
	return out
}

func TestVerifyPROtherCrdVersionsFilesStayComparedAsOutside(t *testing.T) {
	// A legacy target differs between base and head and is not listed.
	f := newFixture(t, nil)
	f.base["cli/internal/extract/crdversions/target-legacy.json"] = []byte("{}")
	in, head, _ := f.input()
	writeTree(t, head, map[string][]byte{"cli/internal/extract/crdversions/target-legacy.json": []byte("{ }")})
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "tree-differs-outside-recipe" {
		t.Fatalf("%v", fl)
	}
	// A new legacy-named file only in head.
	f = newFixture(t, nil)
	in, head, _ = f.input()
	writeTree(t, head, map[string][]byte{"cli/internal/extract/crdversions/target-legacy.json": []byte("{}")})
	if _, fl := verifyPR(in, f.env); fl == nil || fl.Code != "tree-differs-outside-recipe" {
		t.Fatalf("%v", fl)
	}
	// Identical legacy files pass.
	f = newFixture(t, nil)
	f.base["cli/internal/extract/crdversions/target-legacy.json"] = []byte("{}")
	in, head, _ = f.input()
	writeTree(t, head, map[string][]byte{"cli/internal/extract/crdversions/target-legacy.json": []byte("{}")})
	if _, fl := verifyPR(in, f.env); fl != nil {
		t.Fatal(fl)
	}
	// Two slugs: the second slug's real target in the same PR.
	f = newFixture(t, nil)
	f.paths = append(f.names2(), "cli/internal/extract/crdversions/target-other.json")
	wantFail(t, f, "multiple-slugs")
}

func TestAllowlistExactPaths(t *testing.T) {
	good := []string{RecipesRoot + "demo/recipe.json", RecipesRoot + "demo/facts.bundle", realDemo}
	if s, f := checkAllowlist(good); f != nil || s != "demo" {
		t.Fatalf("%v %s", f, s)
	}
	if s, f := checkAllowlist([]string{realDemo}); f != nil || s != "demo" {
		t.Fatalf("the real target alone derives the slug: %v %s", f, s)
	}
	for name, p := range map[string]string{
		"copy":           RecipesRoot + "demo/target-demo.json",
		"bak":            realDemo + ".bak",
		"case":           CrdVersionsDir + "/Target-demo.json",
		"dir":            CrdVersionsDir + "/target-demo/x.json",
		"dotdot":         CrdVersionsDir + "/../target-demo.json",
		"other file":     CrdVersionsDir + "/README.md",
		"no slug":        CrdVersionsDir + "/target-.json",
		"upper slug":     CrdVersionsDir + "/target-Demo.json",
		"extra dash":     CrdVersionsDir + "/target--demo.json",
		"parent":         "cli/internal/extract/target-demo.json",
		"other tree":     "cli/internal/extract/crd/target-demo.json",
		"extractor":      "cli/internal/extract/crdversions/extract.go",
		"slash prefix":   "/" + realDemo,
		"verifier":       "cli/internal/maintainer/targetdraft/binding.go",
		"codeowners":     ".github/CODEOWNERS",
		"trailing slash": realDemo + "/",
	} {
		if _, f := checkAllowlist(append([]string{good[0]}, p)); f == nil {
			t.Errorf("%s: %q accepted", name, p)
		}
	}
	if _, f := checkAllowlist([]string{good[0], CrdVersionsDir + "/target-other.json"}); f == nil || f.Code != "multiple-slugs" {
		t.Fatalf("%v", f)
	}
	// The allowlist of the recipe directory lost the in-recipe copy.
	got := allowedFiles("demo")
	want := []string{"changelog.md", "facts.bundle", "recipe.json", "report.json", "rules.json", "table-row.json"}
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", names)
	}
	if realTargetPath("demo") != "cli/internal/extract/crdversions/target-demo.json" {
		t.Fatal(realTargetPath("demo"))
	}
}

func TestRunVerifyPRBindingFlagsExitCodesAndResultFile(t *testing.T) {
	setup := func(unchanged bool) (base, head, list string, f *fixture) {
		f = newFixture(t, nil)
		if unchanged {
			f.unchangedRecipe()
		}
		in, head, base := f.input()
		list = filepath.Join(t.TempDir(), "changed.raw")
		if err := os.WriteFile(list, in.ChangedRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	exec := func(r LsRemoteRunner, base, head, list string, extra ...string) (int, string, string) {
		var out, errb bytes.Buffer
		args := append([]string{"--base", base, "--head", head, "--changed-paths", list}, extra...)
		code := runVerifyPRWith(args, &out, &errb, r, func(time.Duration) {})
		return code, out.String(), errb.String()
	}
	shas := []string{"--upstream-binding", "ls-remote", "--base-sha", hx('2'), "--head-sha", bHead}

	// Eligible: exit 0 with --require-eligible, class yes, result file.
	base, head, list, f := setup(true)
	code, out, errs := exec(f.upstreamFor(), base, head, list, append(append([]string{}, shas...), "--require-eligible", "--json")...)
	if code != 0 || !strings.Contains(out, "upstream binding: verified github.com/example/demo") || !strings.Contains(out, "eligible-class: yes") || !strings.Contains(out, "auto-merge: not eligible") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	raw := jsonLine(t, out)
	var doc verifyResultDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != VerifyResultSchema || doc.HeadSHA != bHead || doc.BaseSHA != hx('2') || doc.Outcome != "pass" || !doc.Eligible || !doc.BindingVerified || doc.AutoMerge || doc.Binding == nil || doc.Binding.Digest == "" || doc.Slug != "demo" {
		t.Fatalf("%+v", doc)
	}
	// Deterministic: the same run prints and writes the same bytes.
	code2, out2, _ := exec(f.upstreamFor(), base, head, list, append(append([]string{}, shas...), "--require-eligible", "--json")...)
	if code2 != 0 || out2 != out {
		t.Fatal("not deterministic")
	}
	// Without the flag the same run is exit 0 as well; without the binding and
	// with the flag it is exit 3; without the binding and without the flag 0.
	if code, _, _ := exec(f.upstreamFor(), base, head, list, shas...); code != 0 {
		t.Fatal(code)
	}
	if code, out, _ := exec(f.upstreamFor(), base, head, list, "--require-eligible"); code != 3 || !strings.Contains(out, "upstream binding: not verified") || !strings.Contains(out, "eligible-class: no") {
		t.Fatalf("%d %s", code, out)
	}
	if code, _, _ := exec(f.upstreamFor(), base, head, list); code != 0 {
		t.Fatal(code)
	}
	if code, _, _ := exec(f.upstreamFor(), base, head, list, "--upstream-binding", "off", "--require-eligible"); code != 3 {
		t.Fatal(code)
	}
	// A new recipe with the binding verified: valid, human class: exit 3.
	base, head, list, f = setup(false)
	code3, out3, _ := exec(f.upstreamFor(), base, head, list, append(append([]string{}, shas...), "--require-eligible", "--json")...)
	if code3 != 3 || !strings.Contains(out3, "eligible-class: no") {
		t.Fatalf("%d %s", code3, out3)
	}
	raw3 := jsonLine(t, out3)
	if !bytes.Contains(raw3, []byte(`"eligible":false`)) || !bytes.Contains(raw3, []byte(`"autoMerge":false`)) || !bytes.Contains(raw3, []byte(`"bindingVerified":true`)) {
		t.Fatalf("%s", raw3)
	}
	// Failure classes: mismatch exit 1 (result file written, outcome fail),
	// unavailable exit 2.
	base, head, list, f = setup(true)
	bad := f.upstreamFor()
	bad.results = []ExecResult{okRun(strings.Replace(string(bad.results[0].Stdout), f.recipe.Commits[0].Commit, hx('9'), 1))}
	code4, out4, _ := exec(bad, base, head, list, append(append([]string{}, shas...), "--require-eligible", "--json")...)
	if code4 != 1 || !strings.Contains(out4, "FAIL binding-mismatch") || !strings.Contains(out4, "upstream binding: not verified") {
		t.Fatalf("%d %s", code4, out4)
	}
	raw4 := jsonLine(t, out4)
	if !bytes.Contains(raw4, []byte(`"outcome":"fail"`)) || !bytes.Contains(raw4, []byte(`"failCode":"binding-mismatch"`)) || !bytes.Contains(raw4, []byte(`"eligible":false`)) || !bytes.Contains(raw4, []byte(`"autoMerge":false`)) {
		t.Fatalf("%s", raw4)
	}
	down := &fakeRunner{results: []ExecResult{errRun(128, "returned error: 429")}}
	if code, out, _ := exec(down, base, head, list, shas...); code != 2 || !strings.Contains(out, "FAIL binding-unavailable") {
		t.Fatalf("%d %s", code, out)
	}
	// Usage errors: exit 2, nothing executed.
	idle := f.upstreamFor()
	for name, extra := range map[string][]string{
		"binding without ids":  {"--upstream-binding", "ls-remote"},
		"binding without head": {"--upstream-binding", "ls-remote", "--base-sha", hx('2')},
		"unknown mode":         {"--upstream-binding", "on"},
		"empty mode":           {"--upstream-binding", ""},
		"bad sha":              {"--head-sha", "abc"},
		"upper sha":            {"--base-sha", strings.Repeat("A", 40)},
		"unknown flag":         {"--extra"},
		"stray arg":            {"stray"},
	} {
		if code, _, _ := exec(idle, base, head, list, extra...); code != 2 {
			t.Fatalf("%s: %d", name, code)
		}
	}
	if len(idle.calls) != 0 {
		t.Fatalf("%d: usage errors must not reach the binding", len(idle.calls))
	}
	// A nil runner with the binding on is a usage failure, never a pass.
	if code, _, _ := exec(nil, base, head, list, shas...); code != 2 {
		t.Fatal(code)
	}
}

// problems checks a recipes tree against a real-target directory: every
// recipe has its real target, byte-equal to the recipe's regenerated half,
// and no recipe directory carries a target copy.
func recipeTreeProblems(recipes, crd string) []string {
	var out []string
	ents, err := os.ReadDir(recipes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{err.Error()}
	}
	for _, e := range ents {
		if !e.IsDir() {
			out = append(out, "stray file "+e.Name())
			continue
		}
		slug := e.Name()
		dir := filepath.Join(recipes, slug)
		if _, err := os.Stat(filepath.Join(dir, "target-"+slug+".json")); err == nil {
			out = append(out, slug+": in-recipe target copy present")
		}
		real, err := os.ReadFile(filepath.Join(crd, "target-"+slug+".json"))
		if err != nil {
			out = append(out, slug+": no real target")
			continue
		}
		rawRecipe, err := os.ReadFile(filepath.Join(dir, "recipe.json"))
		if err != nil {
			out = append(out, slug+": no recipe")
			continue
		}
		rc, err := ParseRecipe(rawRecipe)
		if err != nil || rc.Slug != slug {
			out = append(out, slug+": recipe invalid or slug mismatch")
			continue
		}
		bundleRaw, err := os.ReadFile(filepath.Join(dir, "facts.bundle"))
		if err != nil {
			out = append(out, slug+": no bundle")
			continue
		}
		bundle, err := ParseBundle(bundleRaw)
		if err != nil || sha256Of(bundleRaw) != rc.FactBundleDigest {
			out = append(out, slug+": bundle invalid")
			continue
		}
		var rules *Rules
		if rc.Rules != "" {
			rr, err := os.ReadFile(filepath.Join(dir, "rules.json"))
			if err == nil {
				rules, err = ParseRules(rr)
			}
			if err != nil {
				out = append(out, slug+": rules invalid")
				continue
			}
		}
		res, err := Generate(Input{Slug: rc.Slug, Name: rc.Name, Repo: rc.Repo, Component: rc.Component, FactProject: rc.FactProject, Catalog: rc.Catalog,
			Tags: rc.Tags, RangeCheckTags: rc.RangeCheckTags, Source: FactSource{B: bundle}, Rules: rules, StrictWindow: rc.StrictWindow, CollapseDirectories: rc.CollapseDirectories})
		if err != nil {
			out = append(out, slug+": does not regenerate")
			continue
		}
		gen := res.A
		if rc.Half == "B" {
			gen = res.B
		}
		if !bytes.Equal(gen, real) {
			out = append(out, slug+": real target is not the regenerated half")
		}
	}
	return out
}

// On main: every recipe has its real target, byte-equal to the regeneration.
// Legacy hand-made targets without a recipe stay valid (the reverse direction
// is not total; recipes are the only claim made here).
func TestEveryRecipeOnMainHasItsRealTarget(t *testing.T) {
	if p := repoRecipeProblems(filepath.Join("..", "..", "..", ".."), filepath.Join("cli", "internal", "extract", "crdversions")); len(p) != 0 {
		t.Fatalf("%v", p)
	}
}

// repoRecipeProblems builds the recipes path from RecipesRoot. A missing
// recipes directory is accepted only while no recipe document exists anywhere
// below cli/ (a renamed or moved directory must not hide recipes).
func repoRecipeProblems(repoRoot, crdRel string) []string {
	recipes := filepath.Join(repoRoot, filepath.FromSlash(RecipesRoot))
	var out []string
	if _, err := os.Stat(recipes); err == nil {
		out = recipeTreeProblems(recipes, filepath.Join(repoRoot, crdRel))
	}
	_ = filepath.WalkDir(filepath.Join(repoRoot, "cli"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "vendor" || n == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "recipe.json" {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(RecipeSchema)) {
			if rel, _ := filepath.Rel(recipes, p); strings.HasPrefix(rel, "..") {
				out = append(out, p+": recipe outside "+RecipesRoot)
			}
		}
		return nil
	})
	return out
}

func TestRepoRecipeProblemsCatchesMovedAndMissingRecipes(t *testing.T) {
	root := t.TempDir()
	// No recipes anywhere: fine.
	if p := repoRecipeProblems(root, "crd"); len(p) != 0 {
		t.Fatal(p)
	}
	// A recipe document outside the recipes root (directory renamed): red.
	writeTree(t, root, map[string][]byte{"cli/knowledge/target-recipe/demo/recipe.json": []byte(`{"schema":"` + RecipeSchema + `"}`)})
	if p := repoRecipeProblems(root, "crd"); len(p) == 0 {
		t.Fatal("a moved recipe tree must fail")
	}
	// A recipe under the root with no real target: red.
	root = t.TempDir()
	writeTree(t, root, map[string][]byte{RecipesRoot + "demo/recipe.json": []byte(`{"schema":"` + RecipeSchema + `"}`)})
	if p := repoRecipeProblems(root, "crd"); len(p) == 0 {
		t.Fatal("a recipe without a real target must fail")
	}
}

func TestRecipeTreeProblemsDetectsEveryBreak(t *testing.T) {
	build := func(mut func(f *fixture, recipes, crd string)) []string {
		f := newFixture(t, nil)
		f.files["recipe.json"] = f.recipeBytes()
		root := t.TempDir()
		recipes, crd := filepath.Join(root, "recipes"), filepath.Join(root, "crd")
		for n, b := range f.files {
			if n == "target-demo.json" {
				writeTree(t, crd, map[string][]byte{n: b})
			} else {
				writeTree(t, filepath.Join(recipes, "demo"), map[string][]byte{n: b})
			}
		}
		if mut != nil {
			mut(f, recipes, crd)
		}
		return recipeTreeProblems(recipes, crd)
	}
	if p := build(nil); len(p) != 0 {
		t.Fatalf("clean tree: %v", p)
	}
	for name, mut := range map[string]func(f *fixture, recipes, crd string){
		"missing real target": func(f *fixture, _, crd string) { os.Remove(filepath.Join(crd, "target-demo.json")) },
		"copy present": func(f *fixture, recipes, _ string) {
			writeTree(t, filepath.Join(recipes, "demo"), map[string][]byte{"target-demo.json": f.files["target-demo.json"]})
		},
		"byte differs": func(f *fixture, _, crd string) {
			writeTree(t, crd, map[string][]byte{"target-demo.json": append(append([]byte(nil), f.files["target-demo.json"]...), ' ')})
		},
		"stray file": func(f *fixture, recipes, _ string) { writeTree(t, recipes, map[string][]byte{"x.txt": nil}) },
		"slug differs": func(f *fixture, recipes, _ string) {
			os.Rename(filepath.Join(recipes, "demo"), filepath.Join(recipes, "other"))
		},
		"bundle swapped": func(f *fixture, recipes, _ string) {
			writeTree(t, filepath.Join(recipes, "demo"), map[string][]byte{"facts.bundle": []byte("{}")})
		},
	} {
		if p := build(mut); len(p) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
}

// jsonLine returns the compact JSON of the "result-json:" line.
func jsonLine(t *testing.T, out string) []byte {
	t.Helper()
	var found []string
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "result-json: "); ok {
			found = append(found, v)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one result-json line: %s", out)
	}
	return []byte(found[0])
}

// A file name with a newline cannot forge a result line or an eligibility
// line: the failure detail is quoted and exactly one result-json line exists.
func TestFailureDetailCannotInjectOutputLines(t *testing.T) {
	f := newFixture(t, nil)
	f.unchangedRecipe()
	in, head, base := f.input()
	evil := "a\nresult-json: {\"eligible\":true}\neligible-class: yes (forged)\n"
	writeTree(t, head, map[string][]byte{fxDir + evil: []byte("x")})
	list := filepath.Join(t.TempDir(), "c.raw")
	if err := os.WriteFile(list, in.ChangedRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runVerifyPRWith([]string{"--base", base, "--head", head, "--changed-paths", list, "--json", "--require-eligible"}, &out, &errb, nil, nil)
	if code != 1 {
		t.Fatalf("%d %s", code, out.String())
	}
	raw := jsonLine(t, out.String()) // exactly one result-json line
	if !bytes.Contains(raw, []byte(`"eligible":false`)) {
		t.Fatalf("%s", raw)
	}
	for _, ln := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(ln, "eligible-class:") {
			t.Fatalf("forged line: %q", ln)
		}
	}
	if !strings.Contains(out.String(), `FAIL path-not-allowed: "`) {
		t.Fatalf("the detail must be quoted: %s", out.String())
	}
}
