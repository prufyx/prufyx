// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"go/ast"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/docstables"
	"github.com/prufyx/prufyx/cli/internal/maintainer/targetdraft"
)

// ---- the compiled admission path sets (layout) ----

// The compiled sets are exactly these files: written out here, independently
// of the layout code. A change of the list is a change of what an admitted
// onboarding may touch.
func TestDefaultOnboardingAdmissionIsExact(t *testing.T) {
	t.Parallel()
	cfg := DefaultLayout().OnboardingAdmission
	if cfg.Enabled {
		t.Fatal("the compiled layout turned the admission on")
	}
	wantStatic := []string{
		"cli/internal/customresources/table.json",
		"cli/internal/cncfcheck/data/rules.json",
		"cli/internal/cncfcheck/data/corpus-attestation.json",
		"cli/docs/generated/community-support-inventory.json",
		"cli/docs/generated/community-support-inventory.md",
		"cli/" + docstables.CRDTargetsPath,
		"cli/" + docstables.CustomResourcesPath,
		"README.md",
		"cli/docs/CNCF-SOURCE-PREVIEW.md",
	}
	if !reflect.DeepEqual(cfg.StaticPaths, wantStatic) {
		t.Fatalf("static paths %v", cfg.StaticPaths)
	}
	wantProject := []string{
		"cli/knowledge/target-recipes/{slug}/recipe.json",
		"cli/knowledge/target-recipes/{slug}/rules.json",
		"cli/knowledge/target-recipes/{slug}/facts.bundle",
		"cli/knowledge/target-recipes/{slug}/report.json",
		"cli/knowledge/target-recipes/{slug}/table-row.json",
		"cli/knowledge/target-recipes/{slug}/changelog.md",
	}
	if !reflect.DeepEqual(cfg.ProjectPaths, wantProject) {
		t.Fatalf("project paths %v", cfg.ProjectPaths)
	}
	if cfg.TargetPath != "cli/internal/extract/crdversions/target-{slug}.json" {
		t.Fatalf("target path %q", cfg.TargetPath)
	}
	// The same names as the gate's layout and the verifier's constants.
	l := DefaultLayout()
	if recipesRoot != targetdraft.RecipesRoot || l.Onboarding.TargetsDir != targetdraft.CrdVersionsDir {
		t.Fatal("the layout and the verifier name other directories")
	}
	if strings.ReplaceAll(cfg.TargetPath, "{slug}", "x") != targetPath(l.Onboarding, "x") {
		t.Fatal("the target path template is not the gate's target path")
	}
	if cfg.StaticPaths[0] != l.Onboarding.TablePath || cfg.StaticPaths[1] != cncfRulesPath || cfg.StaticPaths[2] != cncfAttestPath {
		t.Fatal("the static paths are not the gate's own table, pack and attestation")
	}
}

// Every entry is one exact, clean, non-trust file: no pattern, no directory
// prefix, no trailing slash, no duplicate, and "{slug}" only where a project
// name goes.
func TestDefaultOnboardingAdmissionHasNoPatterns(t *testing.T) {
	t.Parallel()
	l := DefaultLayout()
	cfg := l.OnboardingAdmission
	all := append(append(append([]string(nil), cfg.StaticPaths...), cfg.ProjectPaths...), cfg.TargetPath)
	seen := map[string]bool{}
	for _, e := range all {
		if seen[e] {
			t.Errorf("duplicate %s", e)
		}
		seen[e] = true
		concrete := strings.ReplaceAll(e, "{slug}", "some-slug")
		if strings.ContainsAny(concrete, "*?[]{}") || strings.Count(e, "{slug}") > 1 || strings.HasSuffix(e, "/") || !admitCleanPath(concrete) {
			t.Errorf("not one exact clean file: %s", e)
		}
		if l.trustPath(concrete) || admitForbiddenPath(concrete) {
			t.Errorf("trust or forbidden path: %s", e)
		}
	}
	for _, e := range cfg.StaticPaths {
		if strings.Contains(e, "{slug}") {
			t.Errorf("a static path names a project: %s", e)
		}
	}
	for _, e := range cfg.ProjectPaths {
		if strings.Count(e, "{slug}") != 1 || strings.HasSuffix(e, "/") {
			t.Errorf("project path %s", e)
		}
	}
}

// The verifier's own policy check accepts the compiled static set as its
// Optional list (the table is its table path), and refuses one entry below the
// recipe directory: the two checks read one list.
func TestDefaultOnboardingAdmissionIsAValidVerifierPolicy(t *testing.T) {
	t.Parallel()
	l := DefaultLayout()
	in := &OnboardingAdmissionInput{Config: l.OnboardingAdmission, TrustPaths: l.TrustPaths, Batch: AdmissionBatch{Path: l.Onboarding.Dir + "/ob-20261003-1.json"}}
	policy := seamPolicy(in, l.Onboarding.TablePath)
	reasons := func(p targetdraft.OnboardingPolicy) []string {
		// No trees: the run fails at its input stage, after the policy check.
		return targetdraft.VerifyOnboarding(targetdraft.OnboardingVerifyInput{Slugs: []string{"x"}, Policy: p}).Reasons
	}
	if containsStr(reasons(policy), targetdraft.OnbReasonPolicy) {
		t.Fatalf("the verifier refuses the compiled policy: %v", reasons(policy))
	}
	if len(policy.Optional) != len(l.OnboardingAdmission.StaticPaths)-1 {
		t.Fatalf("optional %v", policy.Optional)
	}
	bad := policy
	bad.Optional = append(append([]string(nil), policy.Optional...), recipesRoot+"x/recipe.json")
	if !containsStr(reasons(bad), targetdraft.OnbReasonPolicy) {
		t.Fatal("the verifier accepts a recipe file as an optional static path")
	}
}

// ---- the recipe allowance ----

func TestRecipeSlugOnlyOneCleanSlug(t *testing.T) {
	t.Parallel()
	one := func(slug string) OnboardingRecord {
		return OnboardingRecord{Projects: []OnboardingProject{{Slug: slug}}}
	}
	for _, ok := range []string{"a", "alpha", "alpha-beta", "a1-b2", strings.Repeat("a", 63)} {
		if got, good := recipeSlug(one(ok)); !good || got != ok {
			t.Errorf("slug %q refused", ok)
		}
	}
	for _, bad := range []string{"", "Alpha", "alpha\n", "alpha\x00", "al pha", "alpha/beta", "..", "a..b", "-a", "a-", "a--b", "alpha.", "alpha_beta", "ALPHA", "α", strings.Repeat("a", 64), "alpha\r", " alpha"} {
		if _, good := recipeSlug(one(bad)); good {
			t.Errorf("slug %q accepted", bad)
		}
	}
	if _, good := recipeSlug(OnboardingRecord{}); good {
		t.Error("an empty batch has a slug")
	}
	if _, good := recipeSlug(OnboardingRecord{Projects: []OnboardingProject{{Slug: "a"}, {Slug: "b"}}}); good {
		t.Error("a second slug is accepted")
	}
}

func TestRecipePathsAreTheVerifiersSixFixedNames(t *testing.T) {
	t.Parallel()
	got := recipePaths("alpha")
	want := []string{"recipe.json", "rules.json", "facts.bundle", "report.json", "table-row.json", "changelog.md"}
	for i := range want {
		want[i] = "cli/knowledge/target-recipes/alpha/" + want[i]
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths %v", got)
	}
}

// allowanceRepo is a repository with a base and a head commit and the
// admission options pointing at it, both locks on.
type allowanceRepo struct {
	t     *testing.T
	repo  string
	base  string
	head  string
	opts  Options
	files map[string]string
}

// newAllowanceRepo commits baseFiles, then headFiles on top (a name mapped to
// "" is absent from that side; a name ending "#x" is committed executable, "#l"
// as a symbolic link to "elsewhere").
func newAllowanceRepo(t *testing.T, baseFiles, headFiles map[string]string) *allowanceRepo {
	t.Helper()
	build := func(files map[string]string) Tree {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "keep.txt"), []byte("keep\n"))
		for name, content := range files {
			mode := "f"
			if n, m, ok := strings.Cut(name, "#"); ok {
				name, mode = n, m
			}
			p := filepath.Join(root, filepath.FromSlash(name))
			writeFile(t, p, []byte(content))
			switch mode {
			case "x":
				if err := os.Chmod(p, 0o755); err != nil {
					t.Fatal(err)
				}
			case "l":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("elsewhere", p); err != nil {
					t.Fatal(err)
				}
			}
		}
		return Tree{Root: root}
	}
	a := &allowanceRepo{t: t, repo: t.TempDir()}
	gitIn(t, a.repo, "init", "--bare", "-q")
	baseTree, headTree := build(baseFiles), build(headFiles)
	a.base = admissionCommit(t, a.repo, baseTree, "")
	a.head = admissionCommit(t, a.repo, headTree, a.base)
	gitIn(t, a.repo, "update-ref", admissionBaseRef, a.base)
	gitIn(t, a.repo, "update-ref", admissionHeadRef, a.head)
	paused := false
	g := &OnboardingGitContext{GitDir: a.repo, BaseCommit: a.base, HeadCommit: a.head, DailyCommits: []DailyCommit{}, Paused: &paused, ObservedAt: gateNow}
	a.opts = Options{Base: baseTree, Head: headTree, Layout: DefaultLayout(), OnboardingGit: g, HeadSHA: a.head, OnboardingAdmissionInProcess: true, AdmissionEvent: AdmissionEventPullRequestTarget}
	a.opts.Layout.OnboardingAdmission.Enabled = true
	return a
}

func recipeBatch(slug string) OnboardingRecord {
	return OnboardingRecord{Projects: []OnboardingProject{{Slug: slug}}}
}

func recipeFilesOf(slug string, content string) map[string]string {
	out := map[string]string{}
	for _, p := range recipePaths(slug) {
		out[p] = content
	}
	return out
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPaths(p []string) []string {
	out := append([]string(nil), p...)
	sort.Strings(out)
	return out
}

func TestRecipeAllowancePlainFiles(t *testing.T) {
	t.Parallel()
	head := recipeFilesOf("alpha", "new\n")
	head["cli/internal/customresources/table.json"] = "{}\n"
	a := newAllowanceRepo(t, nil, head)
	got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha"))
	if !reflect.DeepEqual(keysOf(got), sortedPaths(recipePaths("alpha"))) {
		t.Fatalf("allowance %v", keysOf(got))
	}
	// Only the files the change carries.
	part := map[string]string{recipePaths("alpha")[0]: "x\n", recipePaths("alpha")[5]: "y\n"}
	a = newAllowanceRepo(t, nil, part)
	got = onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha"))
	if !reflect.DeepEqual(keysOf(got), sortedPaths([]string{recipePaths("alpha")[0], recipePaths("alpha")[5]})) {
		t.Fatalf("partial allowance %v", keysOf(got))
	}
}

// Only a new project: a recipe directory the base already has, in whole or in
// part, and any modification, get no allowance at all.
func TestRecipeAllowanceOnlyForANewProject(t *testing.T) {
	t.Parallel()
	name := recipePaths("alpha")[0]
	for label, base := range map[string]map[string]string{
		"a modified recipe file":      {name: "old\n"},
		"another file of the slug":    {"cli/knowledge/target-recipes/alpha/extra.json": "old\n"},
		"a subdirectory of the slug":  {"cli/knowledge/target-recipes/alpha/sub/x.json": "old\n"},
		"all six already in the base": recipeFilesOf("alpha", "old\n"),
	} {
		a := newAllowanceRepo(t, base, recipeFilesOf("alpha", "new\n"))
		if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
	// Another project's directory in the base does not matter.
	a := newAllowanceRepo(t, recipeFilesOf("beta", "old\n"), withEntries(recipeFilesOf("beta", "old\n"), recipeFilesOf("alpha", "new\n")))
	if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); len(got) != 6 {
		t.Fatalf("control: %v", keysOf(got))
	}
}

func withEntries(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// The base probe folds case like the admission: a directory or file of the
// slug under another casing (or with a trailing dot or space) removes the
// allowance; an unrelated entry does not.
func TestRecipeAllowanceBaseProbeFoldsCase(t *testing.T) {
	t.Parallel()
	for label, base := range map[string]map[string]string{
		"case variant directory": {"cli/knowledge/target-recipes/Alpha/x.json": "old\n"},
		"upper case directory":   {"cli/knowledge/target-recipes/ALPHA/x.json": "old\n"},
		"case variant file":      {"cli/knowledge/target-recipes/Alpha": "old\n"},
		"trailing dot directory": {"cli/knowledge/target-recipes/alpha./x.json": "old\n"},
		"trailing space file":    {"cli/knowledge/target-recipes/alpha ": "old\n"},
		"trailing dot case file": {"cli/knowledge/target-recipes/Alpha.": "old\n"},
		"recipes root is a file": {"cli/knowledge/target-recipes": "old\n"},
	} {
		a := newAllowanceRepo(t, base, recipeFilesOf("alpha", "new\n"))
		if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
	for label, base := range map[string]map[string]string{
		"unrelated directory": {"cli/knowledge/target-recipes/beta/x.json": "old\n"},
		"longer name":         {"cli/knowledge/target-recipes/alpha-two/x.json": "old\n"},
	} {
		a := newAllowanceRepo(t, base, withEntries(base, recipeFilesOf("alpha", "new\n")))
		if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); len(got) != 6 {
			t.Errorf("%s: control %v", label, keysOf(got))
		}
	}
}

// A context that is already past its deadline (the seam's bound can only be
// shorter, never longer) removes the allowance.
func TestRecipeAllowanceTimeoutIsNoAllowance(t *testing.T) {
	t.Parallel()
	a := newAllowanceRepo(t, nil, recipeFilesOf("alpha", "new\n"))
	if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); len(got) != 6 {
		t.Fatalf("control: %v", keysOf(got))
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := onboardingRecipeAllowance(ctx, a.opts, recipeBatch("alpha")); got != nil {
		t.Fatalf("allowed %v after the deadline", keysOf(got))
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if got := onboardingRecipeAllowance(ctx2, a.opts, recipeBatch("alpha")); got != nil {
		t.Fatalf("allowed %v on a cancelled context", keysOf(got))
	}
}

// The seam's bound is the one the allowance uses, and the diff hook is
// assigned only in test files.
func TestRecipeDiffHookAssignedOnlyInTests(t *testing.T) {
	t.Parallel()
	if seamTimeout <= 0 {
		t.Fatal("no bound")
	}
	n := 0
	for name, f := range seamSources(t) {
		ast.Inspect(f, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.AssignStmt:
				for _, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == "recipeDiffHook" {
						t.Errorf("%s assigns recipeDiffHook", name)
					}
				}
			case *ast.UnaryExpr:
				if id, ok := v.X.(*ast.Ident); ok && v.Op == token.AND && id.Name == "recipeDiffHook" {
					t.Errorf("%s takes the address of recipeDiffHook", name)
				}
			case *ast.Ident:
				if v.Name == "recipeDiffHook" {
					n++
				}
			}
			return true
		})
	}
	if n == 0 {
		t.Fatal("the hook is no longer read: the scan is vacuous")
	}
}

// Nothing but the six fixed names of the batch's slug: another slug, another
// name, a subdirectory, a case variant and a name that only looks like one are
// not allowed, and the allowed ones stay allowed beside them.
func TestRecipeAllowanceOnlyTheExactFiles(t *testing.T) {
	t.Parallel()
	head := recipeFilesOf("alpha", "new\n")
	for _, extra := range []string{
		"cli/knowledge/target-recipes/alpha/extra.json",
		"cli/knowledge/target-recipes/alpha/recipe.json.bak",
		"cli/knowledge/target-recipes/alpha/Recipe.json",
		"cli/knowledge/target-recipes/alpha/sub/recipe.json",
		"cli/knowledge/target-recipes/alpha/sub/deeper/rules.json",
		"cli/knowledge/target-recipes/beta/recipe.json",
		"cli/knowledge/target-recipes/Alpha/recipe.json",
		"cli/knowledge/target-recipes/alpha-2/recipe.json",
		"cli/knowledge/target-recipes/recipe.json",
	} {
		h := map[string]string{}
		for k, v := range head {
			h[k] = v
		}
		h[extra] = "x\n"
		a := newAllowanceRepo(t, nil, h)
		got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha"))
		if got[extra] {
			t.Errorf("%s is allowed", extra)
		}
		if len(got) != 6 {
			t.Errorf("%s: the six fixed files are not all allowed beside it: %v", extra, keysOf(got))
		}
	}
	// The head's directory is never the source of the slug: a change that
	// carries only another project's recipe directory allows nothing for a
	// batch that names this one, and the other way round.
	a := newAllowanceRepo(t, nil, recipeFilesOf("beta", "new\n"))
	if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); got != nil {
		t.Fatalf("the head's slug allowed files: %v", keysOf(got))
	}
	if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("beta")); len(got) != 6 {
		t.Fatalf("the batch's slug allowed %v", keysOf(got))
	}
}

// A link, an executable or a removed file anywhere in the diff removes the
// allowance altogether: the shared parser admits only plain added or
// modified files.
func TestRecipeAllowanceRefusesNonPlainEntries(t *testing.T) {
	t.Parallel()
	name := recipePaths("alpha")[0]
	cases := map[string]struct {
		base, head map[string]string
	}{
		"recipe file is a link":        {nil, withEntry(recipeFilesOf("alpha", "n\n"), name+"#l", "x\n", name)},
		"recipe file is executable":    {nil, withEntry(recipeFilesOf("alpha", "n\n"), name+"#x", "x\n", name)},
		"another file is executable":   {nil, withEntry(recipeFilesOf("alpha", "n\n"), "cli/tool.sh#x", "#!/bin/sh\n", "")},
		"another file is a link":       {nil, withEntry(recipeFilesOf("alpha", "n\n"), "cli/link#l", "x\n", "")},
		"a file is removed":            {map[string]string{"cli/old.json": "{}\n"}, recipeFilesOf("alpha", "n\n")},
		"a recipe file is removed":     {map[string]string{name: "old\n"}, withoutEntry(recipeFilesOf("alpha", "n\n"), name)},
		"a base executable is changed": {map[string]string{"cli/tool.sh#x": "#!/bin/sh\n"}, withEntry(recipeFilesOf("alpha", "n\n"), "cli/tool.sh", "#!/bin/sh\necho\n", "")},
	}
	for label, c := range cases {
		a := newAllowanceRepo(t, c.base, c.head)
		if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
	// The same repository without the non-plain entry is allowed (the cases
	// above are refused for that entry and no other reason).
	a := newAllowanceRepo(t, nil, recipeFilesOf("alpha", "n\n"))
	if got := onboardingRecipeAllowance(context.Background(), a.opts, recipeBatch("alpha")); len(got) != 6 {
		t.Fatalf("control: %v", keysOf(got))
	}
}

// withEntry adds one entry; drop names an entry of the map the new one replaces.
func withEntry(m map[string]string, name, content, drop string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != drop {
			out[k] = v
		}
	}
	out[name] = content
	return out
}

func withoutEntry(m map[string]string, name string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != name {
			out[k] = v
		}
	}
	return out
}

// Each lock and each context fact removes the allowance on its own, even for a
// change that is otherwise fully allowed.
func TestRecipeAllowanceNeedsEveryCondition(t *testing.T) {
	t.Parallel()
	a := newAllowanceRepo(t, nil, recipeFilesOf("alpha", "n\n"))
	rec := recipeBatch("alpha")
	if got := onboardingRecipeAllowance(context.Background(), a.opts, rec); len(got) != 6 {
		t.Fatalf("control: %v", keysOf(got))
	}
	for label, mutate := range map[string]func(*Options){
		"compiled lock off": func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false },
		"run-time lock off": func(o *Options) { o.OnboardingAdmissionInProcess = false },
		"both locks off":    func(o *Options) { o.Layout.OnboardingAdmission.Enabled, o.OnboardingAdmissionInProcess = false, false },
		"other event":       func(o *Options) { o.AdmissionEvent = "pull_request" },
		"no event":          func(o *Options) { o.AdmissionEvent = "" },
		"no git context":    func(o *Options) { o.OnboardingGit = nil },
		"head sha differs":  func(o *Options) { o.HeadSHA = a.base },
		"empty head sha":    func(o *Options) { o.HeadSHA = "" },
		"no git directory": func(o *Options) {
			g := *o.OnboardingGit
			g.GitDir = filepath.Join(t.TempDir(), "none")
			o.OnboardingGit = &g
		},
		"base equals head": func(o *Options) { g := *o.OnboardingGit; g.BaseCommit = g.HeadCommit; o.OnboardingGit = &g },
		"short commit id":  func(o *Options) { g := *o.OnboardingGit; g.BaseCommit = g.BaseCommit[:39]; o.OnboardingGit = &g },
		"upper case head id": func(o *Options) {
			g := *o.OnboardingGit
			g.HeadCommit = strings.ToUpper(g.HeadCommit)
			o.OnboardingGit = &g
		},
	} {
		o := a.opts
		mutate(&o)
		if got := onboardingRecipeAllowance(context.Background(), o, rec); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
	// The checked trees are not the git objects.
	for label, mutate := range map[string]func(*Options){
		"head tree differs": func(o *Options) { o.Head = Tree{Root: t.TempDir()} },
		"base tree differs": func(o *Options) { o.Base = Tree{Root: t.TempDir()} },
	} {
		o := a.opts
		mutate(&o)
		if got := onboardingRecipeAllowance(context.Background(), o, rec); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
	// A reference that moved after the commits were authenticated.
	other := admissionCommit(t, a.repo, Tree{Root: t.TempDir()}, "")
	gitIn(t, a.repo, "update-ref", admissionHeadRef, other)
	if got := onboardingRecipeAllowance(context.Background(), a.opts, rec); got != nil {
		t.Errorf("a moved head reference: allowed %v", keysOf(got))
	}
	// A second project, an empty batch, a bad slug.
	b := newAllowanceRepo(t, nil, recipeFilesOf("alpha", "n\n"))
	for label, r := range map[string]OnboardingRecord{
		"two projects": {Projects: []OnboardingProject{{Slug: "alpha"}, {Slug: "beta"}}},
		"no project":   {},
		"bad slug":     recipeBatch("Alpha"),
		"newline slug": recipeBatch("alpha\n"),
	} {
		if got := onboardingRecipeAllowance(context.Background(), b.opts, r); got != nil {
			t.Errorf("%s: allowed %v", label, keysOf(got))
		}
	}
}

// A reference that moves between the diff and the end of the step removes the
// allowance (the second reference check). Not parallel: it sets the hook.
func TestRecipeAllowanceRefMovedAfterTheDiff(t *testing.T) {
	a := newAllowanceRepo(t, nil, recipeFilesOf("alpha", "n\n"))
	rec := recipeBatch("alpha")
	if got := onboardingRecipeAllowance(context.Background(), a.opts, rec); len(got) != 6 {
		t.Fatalf("control: %v", keysOf(got))
	}
	other := admissionCommit(t, a.repo, Tree{Root: t.TempDir()}, "")
	moved := false
	recipeDiffHook = func(g *OnboardingGitContext) {
		if g.GitDir == a.repo {
			moved = true
			gitIn(t, a.repo, "update-ref", admissionHeadRef, other)
		}
	}
	defer func() { recipeDiffHook = nil }()
	if got := onboardingRecipeAllowance(context.Background(), a.opts, rec); got != nil || !moved {
		t.Fatalf("allowed %v after the head reference moved (hook ran: %v)", keysOf(got), moved)
	}
}

// With either lock off the function runs no command: a git context that cannot
// run anything is never touched.
func TestRecipeAllowanceOffRunsNothing(t *testing.T) {
	t.Parallel()
	o := Options{Layout: DefaultLayout(), HeadSHA: strings.Repeat("a", 40), AdmissionEvent: AdmissionEventPullRequestTarget,
		OnboardingGit: &OnboardingGitContext{GitDir: "/nonexistent-" + strings.Repeat("x", 8), BaseCommit: strings.Repeat("b", 40), HeadCommit: strings.Repeat("a", 40)}}
	for _, c := range []struct{ compiled, runtime bool }{{false, false}, {true, false}, {false, true}} {
		o.Layout.OnboardingAdmission.Enabled, o.OnboardingAdmissionInProcess = c.compiled, c.runtime
		if got := onboardingRecipeAllowance(context.Background(), o, recipeBatch("alpha")); got != nil {
			t.Fatalf("%+v: %v", c, got)
		}
	}
}

// The allow-list takes only what the gate found plain and only the batch's
// slug: a state that carries the files of another slug, or of a slug the batch
// does not name, allows nothing of the recipe directory.
func TestRecipeAllowedPathsFollowTheBatchSlug(t *testing.T) {
	t.Parallel()
	st := &onboardingState{}
	rec := recipeBatch("alpha")
	if got := st.recipeAllowedPaths(rec); got != nil {
		t.Fatalf("a state with no files allows %v", got)
	}
	st.recipeFiles = map[string]bool{}
	for _, p := range recipePaths("beta") {
		st.recipeFiles[p] = true
	}
	st.recipeFiles["cli/knowledge/target-recipes/alpha/extra.json"] = true
	st.recipeFiles["cli/knowledge/target-recipes/alpha/sub/recipe.json"] = true
	if got := st.recipeAllowedPaths(rec); len(got) != 0 {
		t.Fatalf("allowed %v", keysOf(got))
	}
	st.recipeFiles[recipePaths("alpha")[2]] = true
	if got := keysOf(st.recipeAllowedPaths(rec)); !reflect.DeepEqual(got, []string{recipePaths("alpha")[2]}) {
		t.Fatalf("allowed %v", got)
	}
	if got := st.recipeAllowedPaths(OnboardingRecord{Projects: []OnboardingProject{{Slug: "alpha"}, {Slug: "beta"}}}); len(got) != 0 {
		t.Fatalf("two slugs allowed %v", keysOf(got))
	}
	if path.Base(recipePaths("alpha")[2]) != "facts.bundle" {
		t.Fatal("recipe file order changed")
	}
}

// ---- through the gate ----

const o2Refusal = "O2: an onboarding change may change only the batch file"

// recipeSeamFixture is a seam fixture whose signed head also carries the
// recipe directory of the project (bytes the gate does not read: the verifier
// does), with the batch signed over that exact change.
func recipeSeamFixture(t *testing.T, edit func(f *onboardingFixture)) *seamFixture {
	t.Helper()
	f := newOnboardingFixture(t)
	for _, p := range recipePaths(obSlug) {
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(p)), []byte("recipe "+path.Base(p)+"\n"))
	}
	if edit != nil {
		edit(f)
	}
	rec, _ := f.tryRecord(t) // the offline tool does not know the allowance
	f.sign(t, rec)
	return seamFixtureSigned(t, f)
}

func gateOnly(t *testing.T, s *seamFixture, mutate func(*Options)) *Report {
	t.Helper()
	o := s.opts
	if mutate != nil {
		mutate(&o)
	}
	return runGate(t, o)
}

// Both locks on: the recipe files of the batch's slug pass the allow-list, the
// gate passes, and the decision has no path reason on the compiled layout.
func TestGateAllowsRecipeFilesWithBothLocks(t *testing.T) {
	t.Parallel()
	s := recipeSeamFixture(t, nil)
	r := gateOnly(t, s, nil)
	requirePass(t, r)
	if r.OnboardingAdmission == nil {
		t.Fatal("no decision")
	}
	if got := pathReasons(r.OnboardingAdmission); len(got) != 0 {
		t.Fatalf("path reasons %v (all %v)", got, r.OnboardingAdmission.Reasons)
	}
	if s.calls() != 1 {
		t.Fatalf("verifier called %d times", s.calls())
	}
}

// With either lock off, or both, the refusal is the one the gate always gave:
// the same text, the six files as "other files", no run of the seam.
func TestGateRecipeFilesRefusedAsBeforeWhenALockIsOff(t *testing.T) {
	t.Parallel()
	s := recipeSeamFixture(t, nil)
	want := make([]string, 0, 6)
	for _, p := range recipePaths(obSlug) {
		want = append(want, p)
	}
	sort.Strings(want)
	wantText := o2Refusal + ", the listed projects' target files, the custom-resource table, the cncf pack file, its corpus attestation, the generated support inventory and the regenerated README coverage block and CNCF source preview counts; it also changes 6 other files" + listDetail(want)
	for label, mutate := range map[string]func(*Options){
		"compiled lock off": func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false },
		"run-time lock off": func(o *Options) { o.OnboardingAdmissionInProcess = false },
		"both off":          func(o *Options) { o.Layout.OnboardingAdmission.Enabled, o.OnboardingAdmissionInProcess = false, false },
		"other event":       func(o *Options) { o.AdmissionEvent = "pull_request" },
		"no git context":    func(o *Options) { o.OnboardingGit = nil },
	} {
		r := gateOnly(t, s, mutate)
		requireFail(t, r, wantText)
		if r.OnboardingAdmission != nil && r.OnboardingAdmission.VerifyPr.Outcome != "" {
			t.Errorf("%s: the seam handed a result", label)
		}
	}
	if s.calls() != 0 {
		t.Fatalf("the verifier ran %d times with a lock off", s.calls())
	}
	// The compiled lock off leaves no admission member at all (as before).
	r := gateOnly(t, s, func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false })
	if r.OnboardingAdmission != nil {
		t.Fatal("a decision with the compiled lock off")
	}
}

// Both locks on, and still refused as before: every file the allowance does not
// name.
func TestGateRecipeAllowanceRefusesOtherFiles(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		extra string
		edit  func(f *onboardingFixture)
		want  string
	}{
		{"another file name", "cli/knowledge/target-recipes/" + obSlug + "/extra.json", nil, "changes 1 other files: cli/knowledge/target-recipes/" + obSlug + "/extra.json"},
		{"a subdirectory", "cli/knowledge/target-recipes/" + obSlug + "/sub/recipe.json", nil, "changes 1 other files: cli/knowledge/target-recipes/" + obSlug + "/sub/recipe.json"},
		{"a second slug", "cli/knowledge/target-recipes/other-project/recipe.json", nil, "changes 1 other files: cli/knowledge/target-recipes/other-project/recipe.json"},
		{"a case variant of the slug", "cli/knowledge/target-recipes/" + strings.ToUpper(obSlug) + "/recipe.json", nil, "changes 1 other files: cli/knowledge/target-recipes/" + strings.ToUpper(obSlug) + "/recipe.json"},
		{"a code file beside", "cli/internal/extract/crdversions/onboarded.go", nil, "changes 1 other files: cli/internal/extract/crdversions/onboarded.go"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := recipeSeamFixture(t, func(f *onboardingFixture) {
				writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(c.extra)), []byte("x\n"))
			})
			r := gateOnly(t, s, nil)
			requireFail(t, r, o2Refusal)
			requireFail(t, r, c.want)
		})
	}
}

// Only the other project's recipe directory: the batch's slug has none, and
// the slug is the batch's, never the head's.
func TestGateRecipeAllowanceSlugIsTheBatchs(t *testing.T) {
	t.Parallel()
	s := recipeSeamFixture(t, func(f *onboardingFixture) {
		for _, p := range recipePaths(obSlug) {
			if err := os.Remove(filepath.Join(f.head.Root, filepath.FromSlash(p))); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range recipePaths("other-project") {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(p)), []byte("x\n"))
		}
	})
	r := gateOnly(t, s, nil)
	requireFail(t, r, o2Refusal+", the listed projects' target files")
	requireFail(t, r, "it also changes 6 other files")
}

// An executable recipe file (git mode 100755) is refused with both locks on:
// the allowance is lost, and so is the file.
func TestGateRecipeAllowanceRefusesExecutable(t *testing.T) {
	t.Parallel()
	s := recipeSeamFixture(t, func(f *onboardingFixture) {
		if err := os.Chmod(filepath.Join(f.head.Root, filepath.FromSlash(recipePaths(obSlug)[0])), 0o755); err != nil {
			t.Fatal(err)
		}
	})
	r := gateOnly(t, s, nil)
	if r.Passed() {
		t.Fatal("an executable recipe file passed")
	}
	if s.calls() != 0 {
		t.Fatal("the verifier ran for a refused change")
	}
}

// The allowance is not the verdict: with it in use the gate passes only when
// the in-process verification ran and passed.
func TestGateRecipeAllowanceNeedsTheVerifier(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		verdict func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult
	}{
		{"the verifier fails", func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			return targetdraft.OnboardingVerifyResult{Mode: "inprocess", Outcome: "fail", Reasons: []string{"binding-mismatch"}, BaseSHA: in.BaseSHA, HeadSHA: in.HeadSHA}
		}},
		{"the verifier has no verdict (runner error)", func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			return targetdraft.OnboardingVerifyResult{Mode: "inprocess", Outcome: "fail", Harness: true, Reasons: []string{"ls-remote-failed"}, BaseSHA: in.BaseSHA, HeadSHA: in.HeadSHA}
		}},
		{"the verifier is not the in-process one", func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			res := s.passFor(in)
			res.Mode = "other"
			return res
		}},
		{"the verdict contradicts the gate", func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			res := s.passFor(in)
			res.BindingVerified = false
			return res
		}},
		{"the reference moves during the verification", func(s *seamFixture, in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			other := admissionCommit(s.t, s.repo, Tree{Root: s.t.TempDir()}, "")
			gitIn(s.t, s.repo, "update-ref", admissionHeadRef, other)
			return s.passFor(in)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := recipeSeamFixture(t, nil)
			s.verdict = func(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult { return c.verdict(s, in) }
			r := gateOnly(t, s, nil)
			requireFail(t, r, "onboarding-recipes")
			if r.AutoMerge.Eligible {
				t.Fatal("auto merge")
			}
			if d := r.OnboardingAdmission; d == nil || d.Admitted || !containsStr(d.Reasons, AdmitReasonGateFailed) {
				t.Fatalf("decision %+v", d)
			}
			if s.calls() != 1 {
				t.Fatalf("verifier called %d times", s.calls())
			}
		})
	}
	// The same change passes with the verifier's pass (control).
	s := recipeSeamFixture(t, nil)
	requirePass(t, gateOnly(t, s, nil))
}
