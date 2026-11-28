// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"strings"
	"testing"
)

// newDeriveFixture builds a data PR whose rules.json is the output of derive
// mode: the control tree plus one vendored carrier of a foreign module.
func newDeriveFixture(t *testing.T, mutate func(tag string, m *memTree)) *fixture {
	t.Helper()
	carry := func(tag string, m *memTree) {
		m.files["vendor/example.org/dep/crd/x.yaml"] = crdText("dep.example.org", "Gamma")
		m.files["vendor/modules.txt"] = []byte("# example.org/dep v1.0.0\n")
		if mutate != nil {
			mutate(tag, m)
		}
	}
	mk := func(s Source) Input {
		in := collapseInputFor(s, false)
		in.DeriveRules = true
		return in
	}
	raw, _ := recordBundle(t, collapseSource(carry), mk)
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, mk(FactSource{B: b}))
	rep, _ := marshal(res.Report)
	f := &fixture{t: t, bundle: raw, env: defaultVerifyEnv(), base: map[string][]byte{}, files: map[string][]byte{
		"facts.bundle": raw, "target-demo.json": res.A, "report.json": rep, "table-row.json": res.TableRow, "changelog.md": res.Changelog,
		"rules.json": res.RulesJSON,
	}}
	f.recipe = Recipe{Schema: RecipeSchema, Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf",
		Tags: collapseTags, RangeCheckTags: []string{}, Rules: "rules.json", DeriveRules: true, Half: "A", Exclude: []string{},
		FactBundleDigest: sha256Of(raw)}
	for _, tag := range b.Tags() {
		c, _ := b.Commit(tag)
		f.recipe.Commits = append(f.recipe.Commits, recipeCommit{Tag: tag, Commit: c})
	}
	return f
}

func TestVerifyPRDerivedRulesAreRederivedAndByteCompared(t *testing.T) {
	f := newDeriveFixture(t, nil)
	if !bytes.Contains(f.files["rules.json"], []byte(`"exact-file"`)) {
		t.Fatalf("the fixture must carry a derived exclusion: %s", f.files["rules.json"])
	}
	if res, fl := f.verify(); fl != nil || res == nil {
		t.Fatalf("a clean derived recipe was refused: %v", fl)
	}

	// One byte changed in the derived rules: rejected, even though the file
	// still parses and is canonical.
	f = newDeriveFixture(t, nil)
	f.files["rules.json"] = bytes.Replace(f.files["rules.json"], []byte("proof module"), []byte("proof modulE"), 1)
	wantFail(t, f, "rules-derivation-differs")

	// The exclusion removed, or an extra one added, or an install path
	// widened by hand: rejected.
	for name, edit := range map[string]func(string) string{
		"exclusion removed": func(s string) string {
			a := strings.Index(s, `"exclusions": [`)
			b := strings.Index(s, `"installPaths"`)
			return s[:a] + `"exclusions": [],` + "\n " + s[b:]
		},
		"install path widened": func(s string) string { return strings.Replace(s, `"config/crd/"`, `"config/"`, 1) },
		"another reason":       func(s string) string { return strings.Replace(s, "foreign origin proven", "reviewed by hand", 1) },
	} {
		g := newDeriveFixture(t, nil)
		g.files["rules.json"] = []byte(edit(string(g.files["rules.json"])))
		if bytes.Equal(g.files["rules.json"], newDeriveFixture(t, nil).files["rules.json"]) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		if _, fl := g.verify(); fl == nil || (fl.Code != "rules-derivation-differs" && fl.Code != "rules-invalid") {
			t.Fatalf("%s: %v", name, fl)
		}
	}

	// A hand-written rules file next to a recipe that does not say
	// deriveRules keeps the exclusion refusal.
	f = newDeriveFixture(t, nil)
	f.recipe.DeriveRules = false
	wantFail(t, f, "exclusion-present")

	// deriveRules needs rules.json.
	f = newDeriveFixture(t, nil)
	f.recipe.Rules = ""
	delete(f.files, "rules.json")
	wantFail(t, f, "recipe-invalid")
}

// The derived recipe's report carries the loosening, so the byte-compare of
// report.json also binds it.
func TestVerifyPRDerivedReportBindsTheLoosening(t *testing.T) {
	f := newDeriveFixture(t, nil)
	f.files["report.json"] = bytes.Replace(f.files["report.json"], []byte(`"loosening": [`), []byte(`"loosening": [ `), 1)
	if bytes.Equal(f.files["report.json"], newDeriveFixture(t, nil).files["report.json"]) {
		t.Fatal("the edit changed nothing")
	}
	wantFail(t, f, "report-differs")
	if !strings.Contains(string(f.files["report.json"]), `"loosening"`) {
		t.Fatal("report lacks the loosening block")
	}
}
