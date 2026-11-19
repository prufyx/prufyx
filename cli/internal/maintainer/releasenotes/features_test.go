// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"strings"
	"testing"
)

const featHead = `{"schema":"prufyx.io/release-features/v1","features":[`
const featTail = `]}`

func works(id string) string {
	return `{"id":"` + id + `","title":"T ` + id + `","state":"works","demo":"prufyx x","evidence":"file:README.md","notYet":""}`
}

func notYet(id string) string {
	return `{"id":"` + id + `","title":"T ` + id + `","state":"not-yet","demo":"","evidence":"","notYet":"Not built."}`
}

func TestLoadFeaturesAccepts(t *testing.T) {
	f, err := LoadFeatures([]byte(featHead + works("a") + "," + notYet("b") + featTail))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Features) != 2 {
		t.Fatalf("got %d features", len(f.Features))
	}
	var b strings.Builder
	renderFeatures(&b, f)
	out := b.String()
	for _, want := range []string{"### Works in this release", "- T a. Run: `prufyx x`", "### Not yet", "- T b: Not built."} {
		if !strings.Contains(out, want) {
			t.Errorf("render lacks %q:\n%s", want, out)
		}
	}
}

func TestLoadFeaturesRefusals(t *testing.T) {
	cases := map[string]string{
		"empty":               ``,
		"wrong schema":        `{"schema":"x","features":[` + works("a") + `]}`,
		"no feature":          featHead + featTail,
		"unknown field":       featHead + `{"id":"a","title":"T","state":"works","demo":"d","evidence":"e","notYet":"","extra":1}` + featTail,
		"trailing data":       featHead + works("a") + featTail + `{}`,
		"duplicate id":        featHead + works("a") + "," + notYet("a") + featTail,
		"bad id":              featHead + strings.Replace(works("a"), `"a"`, `"A b"`, 1) + featTail,
		"bad state":           featHead + strings.Replace(works("a"), `"works"`, `"partial"`, 1) + featTail,
		"works no demo":       featHead + strings.Replace(works("a"), `"prufyx x"`, `""`, 1) + featTail,
		"works no evidence":   featHead + strings.Replace(works("a"), `"file:README.md"`, `""`, 1) + featTail,
		"works with reason":   featHead + strings.Replace(works("a"), `"notYet":""`, `"notYet":"later"`, 1) + featTail,
		"not-yet no reason":   featHead + strings.Replace(notYet("a"), `"Not built."`, `""`, 1) + featTail,
		"not-yet with demo":   featHead + strings.Replace(notYet("a"), `"demo":""`, `"demo":"prufyx x"`, 1) + featTail,
		"backtick in title":   featHead + strings.Replace(works("a"), `"T a"`, "\"T `a`\"", 1) + featTail,
		"pipe in reason":      featHead + strings.Replace(notYet("a"), `Not built.`, `a | b`, 1) + featTail,
		"newline in reason":   featHead + strings.Replace(notYet("a"), `Not built.`, `a\nb`, 1) + featTail,
		"padded title":        featHead + strings.Replace(works("a"), `"T a"`, `" T a"`, 1) + featTail,
		"long reason":         featHead + strings.Replace(notYet("a"), `Not built.`, strings.Repeat("x", 400), 1) + featTail,
		"title with period":   featHead + strings.Replace(works("a"), `"T a"`, `"T a."`, 1) + featTail,
		"empty title":         featHead + strings.Replace(works("a"), `"T a"`, `""`, 1) + featTail,
		"kind test is works":  featHead + works("kind-per-version") + featTail,
		"citations are works": featHead + works("source-citations") + featTail,
	}
	for name, in := range cases {
		if _, err := LoadFeatures([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The reserved ones are fine as not-yet.
	if _, err := LoadFeatures([]byte(featHead + notYet("kind-per-version") + "," + notYet("source-citations") + featTail)); err != nil {
		t.Errorf("reserved not-yet refused: %v", err)
	}
}

const smokeHead = `{"schema":"prufyx.io/release-features-smoke/v1","entries":[`

func TestLoadSmoke(t *testing.T) {
	good := smokeHead + `{"demo":"prufyx a b","kind":"binary","args":["a","b"],"wantExit":0,"wantContains":"ok"}]}`
	if _, err := LoadSmoke([]byte(good)); err != nil {
		t.Fatal(err)
	}
	ent := func(demo, rest string) string {
		return smokeHead + `{"demo":"` + demo + `","kind":"binary",` + rest + `}]}`
	}
	bad := map[string]string{
		"wrong schema":           `{"schema":"x","entries":[]}`,
		"no exit":                ent("prufyx a", `"args":["a"],"wantContains":"ok"`),
		"no text":                ent("prufyx a", `"args":["a"],"wantExit":0`),
		"no args":                ent("prufyx a", `"wantExit":0,"wantContains":"ok"`),
		"demo differs from args": ent("prufyx a", `"args":["b"],"wantExit":0,"wantContains":"ok"`),
		"demo without prufyx":    ent("a", `"args":["a"],"wantExit":0,"wantContains":"ok"`),
		"workflow kind":          smokeHead + `{"demo":"d","kind":"workflow","workflow":"r.yml","contains":"x"}]}`,
		"unknown kind":           smokeHead + `{"demo":"prufyx a","kind":"shell","args":["a"],"wantExit":0,"wantContains":"ok"}]}`,
		"duplicate demo":         smokeHead + `{"demo":"prufyx a","kind":"binary","args":["a"],"wantExit":0,"wantContains":"ok"},{"demo":"prufyx a","kind":"binary","args":["a"],"wantExit":0,"wantContains":"ok"}]}`,
		"empty demo":             ent("", `"args":["a"],"wantExit":0,"wantContains":"ok"`),
		"unknown field":          ent("prufyx a", `"args":["a"],"wantExit":0,"wantContains":"ok","run":"rm"`),
	}
	for name, in := range bad {
		if _, err := LoadSmoke([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenderWithFeaturesAndWithout(t *testing.T) {
	f, err := LoadFeatures([]byte(featHead + works("a") + "," + notYet("b") + featTail))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ReadSnapshot(DirTree{writeTree(t, fromFiles())})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadSnapshot(DirTree{writeTree(t, toFiles())})
	if err != nil {
		t.Fatal(err)
	}
	with := mustRender(t, a, b, Options{FromLabel: "v1", ToLabel: "main", OmitMergedPRs: true, Features: f})
	if !strings.Contains(with, "### Works in this release") || !strings.Contains(with, "### Not yet") {
		t.Errorf("feature lists missing:\n%s", with)
	}
	without := mustRender(t, a, b, Options{FromLabel: "v1", ToLabel: "main", OmitMergedPRs: true})
	if strings.Contains(without, "Works in this release") {
		t.Error("feature lists rendered without a feature file")
	}
}
