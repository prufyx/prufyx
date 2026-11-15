// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

func writeTree(t *testing.T, files map[string]string) Tree {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Tree{Root: root}
}

func TestExclusionIdentities(t *testing.T) {
	t.Parallel()
	mk := func(project, path, reason string) crdversions.Target {
		return crdversions.Target{Project: project, Exclude: []crdversions.Exclusion{{Path: path, Reason: reason}}}
	}
	a, err := exclusionIdentities([]crdversions.Target{mk("p", "vendor/", "r1")})
	if err != nil || len(a) != 1 || a[0] == "" {
		t.Fatalf("%v %v", a, err)
	}
	same, _ := exclusionIdentities([]crdversions.Target{mk("p", "vendor/", "r1")})
	if !reflect.DeepEqual(a, same) {
		t.Fatal("identity is not stable")
	}
	for name, other := range map[string]crdversions.Target{
		"reason": mk("p", "vendor/", "r2"), "path": mk("p", "Vendor/", "r1"), "project": mk("q", "vendor/", "r1"),
	} {
		got, _ := exclusionIdentities([]crdversions.Target{other})
		if reflect.DeepEqual(a, got) {
			t.Errorf("a change of the %s keeps the identity", name)
		}
	}
	if none, err := exclusionIdentities([]crdversions.Target{{Project: "p"}}); err != nil || len(none) != 0 {
		t.Fatalf("no exclusion: %v %v", none, err)
	}
	two, _ := exclusionIdentities([]crdversions.Target{{Project: "p", Exclude: []crdversions.Exclusion{{Path: "a"}, {Path: "b"}}}})
	if len(two) != 2 || two[0] == two[1] {
		t.Fatalf("%v", two)
	}
}

func TestRecipeExclusionList(t *testing.T) {
	t.Parallel()
	tree := writeTree(t, map[string]string{
		recipesRoot + "ok/recipe.json":    `{"exclude":["vendor/","docs/"],"other":1}`,
		recipesRoot + "none/recipe.json":  `{}`,
		recipesRoot + "bad/recipe.json":   `{"exclude":`,
		recipesRoot + "wrong/recipe.json": `{"exclude":[1]}`,
	})
	got, err := recipeExclusionList(tree, "ok")
	if err != nil || !reflect.DeepEqual(got, []string{"vendor/", "docs/"}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := recipeExclusionList(tree, "none"); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	for _, slug := range []string{"bad", "wrong", "missing"} {
		if _, err := recipeExclusionList(tree, slug); err == nil {
			t.Errorf("%s: no error", slug)
		}
	}
}

// state records the sides the right way round, the exclusion identities of
// each side, the target digest of each project and the recipe exclusions.
func TestAdmissionFactsState(t *testing.T) {
	t.Parallel()
	excl := crdversions.Exclusion{Path: "vendor/"}
	baseSide := onboardingSide{
		loaded:  []crdversions.Target{{Project: "old", Exclude: []crdversions.Exclusion{excl}}},
		targets: map[string][]byte{"target-old.json": []byte("o")},
		state:   OnboardingState{PackRevision: "r", RegistryDigest: admDigest, TableDigest: admDigest, TargetsDigest: admDigest},
	}
	headSide := onboardingSide{
		loaded:  []crdversions.Target{{Project: "alpha", Exclude: []crdversions.Exclusion{{Path: "docs/"}}}},
		targets: map[string][]byte{"target-alpha.json": []byte("alpha-target")},
		state:   OnboardingState{PackRevision: "r", RegistryDigest: admOther, TableDigest: admOther, TargetsDigest: admOther},
	}
	st := &onboardingState{
		base: baseSide, head: headSide, changeSetDigest: admDigest,
		baseTree: writeTree(t, nil),
		headTree: writeTree(t, map[string]string{recipesRoot + "alpha/recipe.json": `{"exclude":["docs/"]}`}),
	}
	rec := OnboardingRecord{
		Base: baseSide.state, Head: headSide.state,
		Projects: []OnboardingProject{{Slug: "alpha", Kind: OnboardingKindNew}},
	}
	var a admissionFacts
	a.state(st, rec)
	if a.gateBase.Registry != admDigest || a.gateHead.Registry != admOther || a.batchBase.Registry != admDigest || a.batchHead.Registry != admOther {
		t.Fatalf("sides swapped: %+v %+v", a.gateBase, a.gateHead)
	}
	if a.changeSet != admDigest {
		t.Fatal("change set")
	}
	oldID, _ := exclusionIdentities(baseSide.loaded)
	newID, _ := exclusionIdentities(headSide.loaded)
	if !a.exclusionsKnown || !reflect.DeepEqual(a.baseExclusions, oldID) || !reflect.DeepEqual(a.headExclusions, newID) {
		t.Fatalf("exclusions base %v head %v known %v", a.baseExclusions, a.headExclusions, a.exclusionsKnown)
	}
	if !a.recipeKnown || !reflect.DeepEqual(a.recipeExclusions, []string{"alpha\x00docs/"}) || !reflect.DeepEqual(a.targetExclPaths, []string{"alpha\x00docs/"}) {
		t.Fatalf("recipe %v target %v known %v", a.recipeExclusions, a.targetExclPaths, a.recipeKnown)
	}
	if len(a.projects) != 1 || a.projects[0].Slug != "alpha" || a.projects[0].Kind != OnboardingKindNew || a.projects[0].TargetSHA256 != CandidateDigest([]byte("alpha-target")) {
		t.Fatalf("projects %+v", a.projects)
	}
	if !a.baseAbsenceKnown || len(a.basePresent) != 0 {
		t.Fatalf("base absence %+v", a)
	}
	// A project without a head target has no target digest (never admitted).
	st.head.targets = map[string][]byte{}
	var b admissionFacts
	b.state(st, rec)
	if b.projects[0].TargetSHA256 != "" {
		t.Fatal("target digest of a missing target")
	}
	// A missing recipe is unknown, not empty.
	st.headTree = writeTree(t, nil)
	var c admissionFacts
	c.state(st, rec)
	if c.recipeKnown {
		t.Fatal("a missing recipe is known")
	}
}

func TestAdmissionFactsBaseAbsence(t *testing.T) {
	t.Parallel()
	rec := OnboardingRecord{Projects: []OnboardingProject{{Slug: "alpha"}}}
	cases := []struct {
		name    string
		table   []customresources.Project
		targets map[string][]byte
		files   map[string]string
		known   bool
		present []string
	}{
		{"absent everywhere", nil, nil, nil, true, nil},
		{"in the table", []customresources.Project{{Slug: "alpha"}}, nil, nil, true, []string{"alpha"}},
		{"in the targets", nil, map[string][]byte{"target-alpha.json": {1}}, nil, true, []string{"alpha"}},
		{"in the recipes", nil, nil, map[string]string{recipesRoot + "alpha/recipe.json": "{}"}, true, []string{"alpha"}},
		{"another slug is not this one", []customresources.Project{{Slug: "beta"}}, map[string][]byte{"target-beta.json": {1}}, map[string]string{recipesRoot + "beta/recipe.json": "{}"}, true, nil},
		{"recipe unreadable is unknown", nil, nil, map[string]string{recipesRoot + "alpha/recipe.json/x": "{}"}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &onboardingState{base: onboardingSide{projects: tc.table, targets: tc.targets}, baseTree: writeTree(t, tc.files)}
			var a admissionFacts
			a.baseAbsence(st, rec)
			if a.baseAbsenceKnown != tc.known || !reflect.DeepEqual(a.basePresent, tc.present) {
				t.Fatalf("known %v present %v", a.baseAbsenceKnown, a.basePresent)
			}
		})
	}
}

func TestRegenerationFacts(t *testing.T) {
	t.Parallel()
	head := writeTree(t, map[string]string{"out.json": "J", "out.md": "M", "README.md": "R"})
	pair := GeneratedPair{JSONPath: "out.json", MarkdownPath: "out.md"}
	block := GeneratedBlock{Path: "README.md"}
	pass := func(names ...string) *Report {
		r := &Report{}
		for _, n := range names {
			r.Checks = append(r.Checks, Check{Name: "generated/" + n, OK: true})
		}
		return r
	}
	opts := func(l Layout) Options { return Options{Layout: l, Head: head} }

	// Nothing to check is not a pass.
	if known, equal, d := pass().regenerationFacts(opts(Layout{})); known || equal || d != "" {
		t.Fatalf("empty layout: %v %v %q", known, equal, d)
	}
	both := Layout{Generated: []GeneratedPair{pair}, GeneratedBlocks: []GeneratedBlock{block}}
	known, equal, d := pass("out.json", "README.md").regenerationFacts(opts(both))
	if !known || !equal || d == "" {
		t.Fatalf("all checked: %v %v %q", known, equal, d)
	}
	// Pairs alone and blocks alone are each covered, and differ.
	_, eqP, dP := pass("out.json").regenerationFacts(opts(Layout{Generated: []GeneratedPair{pair}}))
	_, eqB, dB := pass("README.md").regenerationFacts(opts(Layout{GeneratedBlocks: []GeneratedBlock{block}}))
	if !eqP || !eqB || dP == "" || dB == "" || dP == dB || dP == d {
		t.Fatalf("pair %v %q block %v %q", eqP, dP, eqB, dB)
	}
	// A failing, a missing or an unnamed check is not equal.
	failing := pass("out.json", "README.md")
	failing.Checks[1].OK = false
	for name, r := range map[string]*Report{"block fails": failing, "block missing": pass("out.json"), "pair missing": pass("README.md"), "wrong name": pass("out.md", "README.md")} {
		if _, eq, dg := r.regenerationFacts(opts(both)); eq || dg != "" {
			t.Errorf("%s: equal %v %q", name, eq, dg)
		}
	}
	pairFails := pass("out.json", "README.md")
	pairFails.Checks[0].OK = false
	if _, eq, _ := pairFails.regenerationFacts(opts(both)); eq {
		t.Error("pair check fails but equal")
	}
	// An unreadable output is unknown.
	missing := Layout{Generated: []GeneratedPair{{JSONPath: "out.json", MarkdownPath: "absent.md"}}}
	if known, eq, _ := pass("out.json").regenerationFacts(opts(missing)); known || eq {
		t.Fatalf("unreadable: %v %v", known, eq)
	}
	// The digest follows the head bytes.
	head2 := writeTree(t, map[string]string{"out.json": "J2", "out.md": "M", "README.md": "R"})
	_, _, d2 := pass("out.json", "README.md").regenerationFacts(Options{Layout: both, Head: head2})
	if d2 == d {
		t.Fatal("digest ignores the bytes")
	}
}

// At gate level, with the flag on, the facts the run records are the gate's
// own: sides in the right order, equal to the signed record, one project with
// the head target's digest, nothing present in the base.
func TestAdmissionFactsFromGate(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	r := f.gateWith(t, func(o *Options) {
		o.Layout = DefaultLayout()
		o.Layout.OnboardingAdmission.Enabled = true
	})
	requirePass(t, r)
	a := r.onboarding.adm
	if !a.signatureVerified || !a.keyInBase || a.tier == "" || a.batch.ID == "" {
		t.Fatalf("signature facts %+v", a)
	}
	if a.gateBase == a.gateHead || a.batchBase == a.batchHead {
		t.Fatal("base and head digests are equal")
	}
	if a.gateHead != a.batchHead || a.gateBase != a.batchBase {
		t.Fatalf("gate %+v %+v batch %+v %+v", a.gateBase, a.gateHead, a.batchBase, a.batchHead)
	}
	if !a.exclusionsKnown || len(a.baseExclusions) != 0 || len(a.headExclusions) != 0 {
		t.Fatalf("exclusions %+v", a)
	}
	if !a.baseAbsenceKnown || len(a.basePresent) != 0 {
		t.Fatalf("base absence %+v", a)
	}
	raw, err := f.head.Read("cli/internal/extract/crdversions/"+crdversions.TargetFileName(obSlug), MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.projects) != 1 || a.projects[0].Slug != obSlug || a.projects[0].TargetSHA256 != CandidateDigest(raw) {
		t.Fatalf("projects %+v", a.projects)
	}
	if d := r.OnboardingAdmission; d == nil || !d.Regen.ByteEqual || d.Regen.OutputsSHA256 == "" {
		t.Fatalf("regeneration %+v", d)
	}
}
