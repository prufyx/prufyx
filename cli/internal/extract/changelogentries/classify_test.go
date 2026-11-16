// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func classifyFile(t *testing.T, tg Target, tagName, file string) (*Entry, []Classified) {
	t.Helper()
	e := mustLocate(t, tg, tagName, file)
	cs, err := classifyT(e, []byte(file))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(cs) != len(e.Items) {
		t.Fatalf("%d results for %d items", len(cs), len(e.Items))
	}
	return e, cs
}

// promOne wraps the given item lines in a prometheus-style entry.
func promOne(lines ...string) string {
	return "# Changelog\n\n## main / unreleased\n\n## 3.5.0 / 2025-07-14\n\n" +
		strings.Join(lines, "\n") + "\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] D. #4\n"
}

func cortexOne(lines ...string) string {
	return "# Changelog\n\n## master / unreleased\n\n## 1.19.0 2025-07-14\n\n" +
		strings.Join(lines, "\n") + "\n\n## 1.18.0 2025-05-17\n\n* [FEATURE] D. #4\n"
}

func thanosOne(body string) string {
	return "# Changelog\n\n## Unreleased\n\n## [v0.38.0](https://x/tree/release-0.38) - 03.04.2025\n\n" +
		body + "\n\n## [v0.37.2](https://x/tree/release-0.37) - 11.12.2024\n\n### Fixed\n\n- [#2](u) y\n"
}

func wantClass(t *testing.T, c Classified, want Class, what string) {
	t.Helper()
	if c.Class != want {
		t.Fatalf("%s: want %s got %s (reasons %v triggers %v)", what, want, c.Class, c.Reasons, c.Triggers)
	}
}

func TestNeutralPositive(t *testing.T) {
	_, cs := classifyFile(t, promTarget, "v3.5.0", promOne(
		"* [FEATURE] Scraping: add support for X. #1",
		"* [ENHANCEMENT] TSDB: faster block loading. #2",
		"* [BUGFIX] Rules: fix a logging typo. #3",
		"* [PERF] Kubernetes SD: cheaper discovery. #4",
	))
	for i, c := range cs {
		wantClass(t, c, ClassMechanicalNeutral, fmt.Sprintf("item %d", i))
		if len(c.Triggers) != 0 || len(c.Reasons) != 0 {
			t.Fatalf("neutral item with triggers or reasons: %+v", c)
		}
	}
	_, ct := classifyFile(t, cortexTarget, "1.19.0", cortexOne("* [ENHANCEMENT] Ruler: more logging. #9", "* [BUGFIX] Fix a crash. #10"))
	for _, c := range ct {
		wantClass(t, c, ClassMechanicalNeutral, "cortex")
	}
	_, th := classifyFile(t, thanosTarget, "v0.38.0", thanosOne("### Added\n\n- [#1](u) Store: new metric.\n\n### Fixed\n\n- [#2](u) Query: fix a typo."))
	for _, c := range th {
		wantClass(t, c, ClassMechanicalNeutral, "thanos")
	}
}

func TestOperatorMarkersNeedReview(t *testing.T) {
	for _, m := range []string{"CHANGE", "BREAKING", "REMOVED", "DEPRECATED", "SECURITY"} {
		_, cs := classifyFile(t, promTarget, "v3.5.0", promOne("* ["+m+"] Plain words only. #1"))
		wantClass(t, cs[0], ClassNeedsReview, m)
		if !hasStr(cs[0].Reasons, ReasonOperatorMarker) {
			t.Fatalf("%s: reasons %v", m, cs[0].Reasons)
		}
	}
}

func TestMarkerShapeNegatives(t *testing.T) {
	cases := map[string]string{
		"unknown marker":         "* [DOCS] Plain words. #1",
		"lowercase marker":       "* [feature] Plain words. #1",
		"no marker":              "* Plain words. #1",
		"two markers":            "* [FEATURE] [BUGFIX] Plain words. #1",
		"two markers neutral+op": "* [FEATURE] [CHANGE] Plain words. #1",
		"marker mid text":        "* Plain [FEATURE] words. #1",
		"bold marker":            "* **[FEATURE]** Plain words. #1",
		"nested class":           "* [FEATURE] Plain words:\n  * [CHANGE] Other words.",
		"nested neutral class":   "* [FEATURE] Plain words:\n  * [BUGFIX] Other words.",
		"nested operator":        "* [BUGFIX] Plain words:\n  * [REMOVED] Other words.",
		"slash marker":           "* [FEATURE/BUGFIX] Plain words. #1",
		"empty marker":           "* [] Plain words. #1",
		"ordered no marker":      "1. Plain words. #1",
		"code fence in item":     "* [FEATURE] Plain words:\n  ```\n  text\n  ```",
		"paragraph":              "Plain words in a paragraph.",
		"fenced block":           "```\n[FEATURE] words\n```",
		"homoglyph":              "* [FEATURE] Plain wоrds. #1",
		"zero width":             "* [FEATURE] Plain\u200b words. #1",
		"control char":           "* [FEATURE] Plain\x01 words. #1",
	}
	for name, item := range cases {
		file := promOne(item)
		e, err := locateMem(promTarget, "v3.5.0", file)
		if err != nil {
			continue // a shape P1 already withholds is not classified at all
		}
		cs, err := classifyT(e, []byte(file))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range cs {
			wantClass(t, c, ClassNeedsReview, name)
		}
	}
	// The controls really do reach the classifier (P1 does not withhold them).
	for _, name := range []string{"unknown marker", "no marker", "two markers", "nested class", "paragraph", "homoglyph", "zero width"} {
		if _, err := locateMem(promTarget, "v3.5.0", promOne(cases[name])); err != nil {
			t.Fatalf("%s did not reach the classifier: %v", name, err)
		}
	}
}

// lexiconProbe wraps a term in sentences in several shapes.
func lexiconProbes(term string) []string {
	up := strings.ToUpper(term)
	hy := strings.ReplaceAll(term, " ", "-")
	return []string{
		"Plain words " + term + " more words.",
		"Plain words " + up + " more words.",
		"Plain words " + strings.ToUpper(term[:1]) + term[1:] + " more words.",
		"Plain words " + hy + " more words.",
		"Plain words " + strings.ReplaceAll(term, " ", "\n  ") + " more words.",
		"Plain words `--flag." + term + "` more words.",
		term + "x suffix words.",
		"prefix" + term + " words.",
	}
}

func TestMarkerTimesTriggerMatrix(t *testing.T) {
	neutral := []string{"FEATURE", "ENHANCEMENT", "BUGFIX", "PERF"}
	operator := []string{"CHANGE", "BREAKING", "REMOVED", "DEPRECATED", "SECURITY"}
	n := 0
	for _, term := range defaultVocab.Lexicon {
		for _, m := range append(append([]string{}, neutral...), operator...) {
			for _, p := range lexiconProbes(term) {
				file := promOne("* [" + m + "] " + p + " #1")
				e, err := locateMem(promTarget, "v3.5.0", file)
				if err != nil {
					t.Fatalf("probe %q: %v", p, err)
				}
				cs, err := classifyT(e, []byte(file))
				if err != nil {
					t.Fatal(err)
				}
				if cs[0].Class != ClassNeedsReview || !hasStr(cs[0].Reasons, ReasonTriggerLexicon) || !hasStr(cs[0].Triggers, term) {
					t.Fatalf("[%s] %q (term %q): %+v", m, p, term, cs[0])
				}
				n++
			}
		}
	}
	if n < 22*9*8 {
		t.Fatalf("matrix ran %d probes", n)
	}
	// Cortex and thanos shapes: same lexicon.
	for _, term := range defaultVocab.Lexicon {
		f := cortexOne("* [FEATURE] Plain " + term + " words. #1")
		_, cs := classifyFile(t, cortexTarget, "1.19.0", f)
		wantClass(t, cs[0], ClassNeedsReview, "cortex "+term)
		f = thanosOne("### Added\n\n- [#1](u) Plain " + term + " words.")
		_, cs = classifyFile(t, thanosTarget, "v0.38.0", f)
		wantClass(t, cs[0], ClassNeedsReview, "thanos "+term)
	}
}

func TestHeadingStyleNegatives(t *testing.T) {
	bodies := map[string]string{
		"removed heading":      "### Removed\n\n- [#1](u) Plain words.",
		"changed heading":      "### Changed\n\n- [#1](u) Plain words.",
		"security heading":     "### Security\n\n- [#1](u) Plain words.",
		"breaking heading":     "### Breaking changes\n\n- [#1](u) Plain words.",
		"deprecated heading":   "### Deprecated\n\n- [#1](u) Plain words.",
		"unknown heading":      "### Docs\n\n- [#1](u) Plain words.",
		"no heading":           "- [#1](u) Plain words.",
		"nested subheading":    "### Added\n\n#### Store\n\n- [#1](u) Plain words.",
		"marker under Added":   "### Added\n\n- [FEATURE] Plain words.",
		"paragraph in Added":   "### Added\n\nPlain words in a paragraph.",
		"nested class":         "### Added\n\n- [#1](u) Plain words:\n  - [REMOVED] Other.",
		"lowercase heading":    "### added\n\n- [#1](u) Plain words.",
		"decorated heading":    "### Added things\n\n- [#1](u) Plain words.",
		"breaking under Added": "### Added\n\n- [#6690](u) Store: *breaking :warning:* Add a label.",
	}
	for name, body := range bodies {
		file := thanosOne(body)
		e, err := locateMem(thanosTarget, "v0.38.0", file)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cs, err := classifyT(e, []byte(file))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			wantClass(t, c, ClassNeedsReview, name)
		}
	}
}

func TestNoVocabularyAndCrossVocabulary(t *testing.T) {
	other := promTarget
	other.Component = "alertmanager" // prometheus-shaped, but not in the reviewed table
	_, cs := classifyFile(t, other, "v3.5.0", promOne("* [FEATURE] Plain words. #1"))
	wantClass(t, cs[0], ClassNeedsReview, "component without vocabulary")
	if !hasStr(cs[0].Reasons, ReasonNoVocabulary) {
		t.Fatalf("reasons %v", cs[0].Reasons)
	}
	// A marker neutral for prometheus is not neutral for cortex.
	_, cs = classifyFile(t, cortexTarget, "1.19.0", cortexOne("* [PERF] Plain words. #1"))
	wantClass(t, cs[0], ClassNeedsReview, "cortex PERF")
	if !hasStr(cs[0].Reasons, ReasonMarkerNotNeutral) {
		t.Fatalf("reasons %v", cs[0].Reasons)
	}
	// Thanos has no marker vocabulary.
	_, cs = classifyFile(t, thanosTarget, "v0.38.0", thanosOne("### Added\n\n- [FEATURE] Plain words."))
	wantClass(t, cs[0], ClassNeedsReview, "thanos marker")
}

func TestPlainNestedBulletInheritsAndIsScanned(t *testing.T) {
	_, cs := classifyFile(t, promTarget, "v3.5.0", promOne("* [FEATURE] Plain words:\n  * more plain words"))
	wantClass(t, cs[0], ClassMechanicalNeutral, "plain nested bullet")
	_, cs = classifyFile(t, promTarget, "v3.5.0", promOne("* [FEATURE] Plain words:\n  * the old flag is removed"))
	wantClass(t, cs[0], ClassNeedsReview, "nested trigger")
}

func TestFixtureEntries(t *testing.T) {
	r := fixtureRoot(t)
	for _, c := range []struct {
		tg  Target
		tag string
	}{
		{promTarget, "v3.5.0"}, {promTarget, "v3.4.0"},
		{cortexTarget, "v1.18.0"},
		{thanosTarget, "v0.38.0"}, {thanosTarget, "v0.37.0"},
	} {
		tag := fixtureTag(t, r, c.tg, c.tag)
		e, err := Locate(r, c.tg, tag)
		if err != nil {
			t.Fatalf("%s %s: %v", c.tg.Component, c.tag, err)
		}
		raw, err := r.Read(c.tg.Repo, tag.Commit, c.tg.Path)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := classifyT(e, raw)
		if err != nil {
			t.Fatalf("%s %s: %v", c.tg.Component, c.tag, err)
		}
		lines, _ := splitLines(raw)
		neutral := 0
		for i, k := range cs {
			it := e.Items[i]
			text := strings.Join(lines[it.StartLine-1:it.EndLine], "\n")
			switch k.Class {
			case ClassMechanicalNeutral:
				neutral++
				// Independent oracle: a neutral item shows none of a short
				// hand-written list of operator words.
				low := strings.ToLower(text)
				for _, w := range []string{"remov", "deprecat", "break", "no longer", "[change]", "renam", "default", "must"} {
					if strings.Contains(low, w) {
						t.Fatalf("%s %s: neutral item %d holds %q: %s", c.tg.Component, c.tag, i, w, text)
					}
				}
			case ClassNeedsReview:
				if len(k.Reasons) == 0 {
					t.Fatalf("needs-review without a reason: %+v", k)
				}
			default:
				t.Fatalf("class %q", k.Class)
			}
			if strings.Contains(text, "[CHANGE]") && k.Class != ClassNeedsReview {
				t.Fatalf("CHANGE item is %s", k.Class)
			}
		}
		if neutral == 0 && c.tg.Component != "thanos" {
			t.Fatalf("%s %s: nothing neutral, the classifier would be vacuous", c.tg.Component, c.tag)
		}
	}
}

// backtest reads a real excerpt that holds a known reviewed removal and
// requires the item at the cited line to be needs-review.
func backtest(t *testing.T, tg Target, tagName, file string, citedLines ...int) (*Entry, []Classified, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "backtest", file))
	if err != nil {
		t.Fatal(err)
	}
	e, err := locateBytes(tg, tagName, raw)
	if err != nil {
		t.Fatalf("locate %s: %v", file, err)
	}
	cs, err := classifyT(e, raw)
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := splitLines(raw)
	for _, ln := range citedLines {
		found := false
		for i, it := range e.Items {
			if it.StartLine <= ln && ln <= it.EndLine {
				found = true
				wantClass(t, cs[i], ClassNeedsReview, fmt.Sprintf("%s line %d", file, ln))
			}
		}
		if !found {
			t.Fatalf("%s: no item holds line %d", file, ln)
		}
	}
	return e, cs, lines
}

func TestBacktestThanos0330(t *testing.T) {
	// The reviewed rule cites line 48 (the removed --log.request.decision).
	e, cs, lines := backtest(t, thanosTarget, "v0.33.0", "thanos-0.33.0.CHANGELOG.md", 48)
	for i, it := range e.Items {
		text := strings.Join(lines[it.StartLine-1:it.EndLine], "\n")
		if strings.Contains(text, "breaking") && cs[i].Class != ClassNeedsReview {
			t.Fatalf("breaking item %d is %s", i, cs[i].Class)
		}
	}
	// Items filed under the neutral heading Added that say breaking stay in review.
	n := 0
	for i, it := range e.Items {
		if len(it.HeadingPath) == 1 && it.HeadingPath[0] == "Added" && strings.Contains(strings.Join(lines[it.StartLine-1:it.EndLine], "\n"), "*breaking") {
			wantClass(t, cs[i], ClassNeedsReview, "breaking under Added")
			n++
		}
	}
	if n < 2 {
		t.Fatalf("expected the real breaking items under Added, got %d", n)
	}
}

// cortexOldTarget reads the "1.9.0 / 2021-05-14" heading style of 2021.
var cortexOldTarget = func() Target {
	t := cortexTarget
	t.HeadingPattern = `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`
	return t
}()

func TestBacktestCortex190(t *testing.T) {
	// The reviewed rules cite lines 17 and 18.
	_, _, _ = backtest(t, cortexOldTarget, "1.9.0", "cortex-1.9.0.CHANGELOG.md", 17, 18)
}

func TestBacktestNoNeutralItemHoldsAKnownRemoval(t *testing.T) {
	for _, c := range []struct {
		tg        Target
		tag, file string
	}{
		{thanosTarget, "v0.33.0", "thanos-0.33.0.CHANGELOG.md"},
		{cortexOldTarget, "1.9.0", "cortex-1.9.0.CHANGELOG.md"},
	} {
		e, cs, lines := backtest(t, c.tg, c.tag, c.file)
		for i, it := range e.Items {
			text := strings.ToLower(strings.Join(lines[it.StartLine-1:it.EndLine], "\n"))
			if cs[i].Class == ClassMechanicalNeutral && (strings.Contains(text, "remov") || strings.Contains(text, "deprecat")) {
				t.Fatalf("%s item %d neutral: %s", c.file, i, text)
			}
		}
	}
}

func TestBindingRefusals(t *testing.T) {
	file := promOne("* [FEATURE] Plain words. #1", "* [BUGFIX] Other words. #2")
	good := mustLocate(t, promTarget, "v3.5.0", file)
	if _, err := classifyT(good, []byte(file)); err != nil {
		t.Fatal(err)
	}
	clone := func() *Entry {
		b, _ := json.Marshal(good)
		var e Entry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		return &e
	}
	type mut struct {
		name string
		do   func(e *Entry, f *[]byte)
	}
	muts := []mut{
		{"file edited", func(e *Entry, f *[]byte) { *f = []byte(strings.Replace(file, "Plain", "Plaim", 1)) }},
		{"file digest", func(e *Entry, f *[]byte) { e.Source.FileDigest = strings.Repeat("0", 64) }},
		{"section digest", func(e *Entry, f *[]byte) { e.Section.Digest = strings.Repeat("0", 64) }},
		{"section end short", func(e *Entry, f *[]byte) { e.Section.EndLine-- }},
		{"section outside", func(e *Entry, f *[]byte) { e.Section.EndLine = 9999 }},
		{"item dropped", func(e *Entry, f *[]byte) { e.Items = e.Items[:1] }},
		{"item added", func(e *Entry, f *[]byte) { e.Items = append(e.Items, e.Items[0]) }},
		{"item digest", func(e *Entry, f *[]byte) { e.Items[0].Digest = strings.Repeat("0", 64) }},
		{"item marker", func(e *Entry, f *[]byte) { e.Items[0].Marker = "CHANGE" }},
		{"item bounds", func(e *Entry, f *[]byte) { e.Items[0].EndLine++ }},
		{"item kind", func(e *Entry, f *[]byte) { e.Items[0].Kind = "block" }},
		{"heading path forged", func(e *Entry, f *[]byte) { e.Items[0].HeadingPath = []string{"Added"} }},
		{"structure dropped", func(e *Entry, f *[]byte) { e.Structure = e.Structure[:0] }},
		{"structure text", func(e *Entry, f *[]byte) { e.Structure[0].Text = "9.9.9 / 2030-01-01" }},
		{"occurrence", func(e *Entry, f *[]byte) { e.Items[1].Occurrence = 2 }},
		{"bom file", func(e *Entry, f *[]byte) { *f = append([]byte("\xef\xbb\xbf"), *f...) }},
	}
	for _, m := range muts {
		e := clone()
		f := []byte(file)
		m.do(e, &f)
		out, err := classifyT(e, f)
		if err == nil || out != nil {
			t.Fatalf("%s: classified a mismatched entry (%v)", m.name, err)
		}
	}
	if _, err := classifyT(nil, []byte(file)); !errors.Is(err, ErrEntryBinding) {
		t.Fatalf("nil entry: %v", err)
	}
	// A refused entry is a binding error, not a typed G reason.
	e := clone()
	e.Source.FileDigest = "x"
	_, err := classifyT(e, []byte(file))
	if !errors.Is(err, ErrEntryBinding) {
		t.Fatalf("want binding error: %v", err)
	}
	if _, ok := CodeOf(err); ok {
		t.Fatal("a binding error must not read as a typed reason")
	}
}

func TestOutputIsExactlyTwoValuesAndDeterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	markers := []string{"FEATURE", "ENHANCEMENT", "BUGFIX", "PERF", "CHANGE", "BREAKING", "REMOVED", "DEPRECATED", "SECURITY", "DOCS", "X", ""}
	words := []string{"plain", "words", "remove", "the", "flag", "`--a.b`", "Default", "must", "[CHANGE]", "[FEATURE]", "#12", "(see)", "[l](u)", "drop-in", "no\nlonger", "café", "а", "[a]:", "- x", "* y", "`", "```"}
	for i := 0; i < 400; i++ {
		var lines []string
		for j := 0; j < 1+rng.Intn(4); j++ {
			l := "*"
			if m := markers[rng.Intn(len(markers))]; m != "" {
				l += " [" + m + "]"
			}
			for k := 0; k < rng.Intn(6); k++ {
				l += " " + words[rng.Intn(len(words))]
			}
			lines = append(lines, l)
		}
		file := promOne(lines...)
		e, err := locateMem(promTarget, "v3.5.0", file)
		if err != nil {
			continue // withheld by the reader; nothing to classify
		}
		a, err := classifyT(e, []byte(file))
		if err != nil {
			t.Fatalf("%q: %v", file, err)
		}
		b, _ := classifyT(e, []byte(file))
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Fatal("not deterministic")
		}
		for _, c := range a {
			switch c.Class {
			case ClassMechanicalNeutral:
				if len(c.Triggers) != 0 || len(c.Reasons) != 0 {
					t.Fatalf("neutral with triggers/reasons: %+v", c)
				}
				body := strings.Join(strings.Split(file, "\n")[c.StartLine-1:c.EndLine], "\n")
				if len(lexiconHits(defaultVocab, body)) != 0 || strings.Contains(body, "[CHANGE]") {
					t.Fatalf("neutral item with a trigger: %q", body)
				}
			case ClassNeedsReview:
				if len(c.Reasons) == 0 {
					t.Fatalf("needs-review without a reason: %+v", c)
				}
			default:
				t.Fatalf("a third class: %q", c.Class)
			}
		}
	}
}

func TestVocabularyValidation(t *testing.T) {
	var base map[string]any
	if err := json.Unmarshal(vocabJSON, &base); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]any {
		b, _ := json.Marshal(base)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	enc := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	if _, err := parseVocabulary(vocabJSON); err != nil {
		t.Fatal(err)
	}
	drop := func(key string, term string) map[string]any {
		m := clone()
		var out []any
		for _, x := range m[key].([]any) {
			if x != term {
				out = append(out, x)
			}
		}
		m[key] = out
		return m
	}
	for _, term := range requiredLexicon {
		if _, err := parseVocabulary(enc(drop("lexicon", term))); err == nil {
			t.Fatalf("lexicon without %q accepted", term)
		}
	}
	for _, term := range requiredOperatorMarkers {
		if _, err := parseVocabulary(enc(drop("operatorMarkers", term))); err == nil {
			t.Fatalf("operator markers without %q accepted", term)
		}
	}
	for _, term := range requiredOperatorHeadings {
		if _, err := parseVocabulary(enc(drop("operatorHeadings", term))); err == nil {
			t.Fatalf("operator headings without %q accepted", term)
		}
	}
	bad := map[string]func(m map[string]any){
		"neutral marker is an operator marker": func(m map[string]any) {
			m["components"].(map[string]any)["prometheus"] = map[string]any{"markers": []any{"CHANGE"}}
		},
		"neutral heading is operator": func(m map[string]any) {
			m["components"].(map[string]any)["thanos"] = map[string]any{"headings": []any{"Changed"}}
		},
		"neutral heading hits lexicon": func(m map[string]any) {
			m["components"].(map[string]any)["thanos"] = map[string]any{"headings": []any{"Default settings"}}
		},
		"markers and headings": func(m map[string]any) {
			m["components"].(map[string]any)["thanos"] = map[string]any{"headings": []any{"Added"}, "markers": []any{"FEATURE"}}
		},
		"neither": func(m map[string]any) { m["components"].(map[string]any)["thanos"] = map[string]any{} },
		"bad marker token": func(m map[string]any) {
			m["components"].(map[string]any)["prometheus"] = map[string]any{"markers": []any{"feature"}}
		},
		"schema":        func(m map[string]any) { m["schema"] = 2 },
		"unknown field": func(m map[string]any) { m["extra"] = 1 },
		"unnormalised lexicon": func(m map[string]any) {
			m["lexicon"] = append(m["lexicon"].([]any), "No-Longer")
		},
		"empty components": func(m map[string]any) { m["components"] = map[string]any{} },
	}
	for name, f := range bad {
		m := clone()
		f(m)
		if _, err := parseVocabulary(enc(m)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := parseVocabulary(append(vocabJSON[:len(vocabJSON):len(vocabJSON)], []byte(`{}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestClassifierDoesNotChangeTheEntry(t *testing.T) {
	file := promOne("* [FEATURE] Plain words. #1")
	e := mustLocate(t, promTarget, "v3.5.0", file)
	before, _ := e.Canonical()
	if _, err := classifyT(e, []byte(file)); err != nil {
		t.Fatal(err)
	}
	after, _ := e.Canonical()
	if string(before) != string(after) {
		t.Fatal("Classify changed the entry")
	}
}

// An entry cut after its first item, with every field recomputed to be
// self-consistent (section digest, item list, line accounting), is refused:
// the section is re-derived from the file bytes, never taken from the entry.
func TestSelfConsistentTruncationIsRefused(t *testing.T) {
	file := promOne("* [FEATURE] Plain words. #1", "* [BUGFIX] Other words. #2", "* [ENHANCEMENT] Gone: the flag --old was removed. #3")
	good := mustLocate(t, promTarget, "v3.5.0", file)
	if len(good.Items) != 3 {
		t.Fatalf("setup: %d items", len(good.Items))
	}
	b, _ := json.Marshal(good)
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	cut := e.Items[0].EndLine
	e.Items = e.Items[:1]
	e.Section.EndLine = cut
	e.Section.Digest = hexSum([]byte(strings.Join(lines[e.Section.StartLine-1:cut], "\n") + "\n"))
	e.Tiling = Tiling{Lines: cut - e.Section.StartLine + 1, Headings: 1, Blanks: 1, ItemLines: 1}
	out, err := classifyT(&e, []byte(file))
	if err == nil || out != nil || !errors.Is(err, ErrEntryBinding) {
		t.Fatalf("truncated entry classified: %v", err)
	}
	// A stretched section (past the next release heading) is refused too.
	g := mustLocate(t, promTarget, "v3.5.0", file)
	b, _ = json.Marshal(g)
	var f Entry
	_ = json.Unmarshal(b, &f)
	f.Section.EndLine += 4
	f.Section.Digest = hexSum([]byte(strings.Join(lines[f.Section.StartLine-1:f.Section.EndLine], "\n") + "\n"))
	if _, err := classifyT(&f, []byte(file)); !errors.Is(err, ErrEntryBinding) {
		t.Fatalf("stretched entry classified: %v", err)
	}
	// Control: the untouched entry still classifies.
	if _, err := classifyT(good, []byte(file)); err != nil {
		t.Fatal(err)
	}
}

func TestAnnotationAndInvisibleCharacterNegatives(t *testing.T) {
	cases := map[string]string{
		"lowercase after marker":    "* [FEATURE] [security] Plain words.",
		"slash after marker":        "* [FEATURE] [SECURITY/BUGFIX] Plain words.",
		"unknown after marker":      "* [FEATURE] [Docs] Plain words.",
		"lowercase operator nested": "* [FEATURE] Plain words:\n  * [removed] Other words.",
		"mixed case operator":       "* [BUGFIX] [Breaking] Plain words.",
		"combining grapheme joiner": "* [FEATURE] re͏moved --old.",
		"combining acute":           "* [FEATURE] Plain wórds.",
		"variation selector":        "* [FEATURE] Plain️ words.",
		"no-break space":            "* [FEATURE] no longer works.",
		"en dash":                   "* [FEATURE] Plain – words.",
		"soft hyphen":               "* [FEATURE] rem\u00adoved --old.",
	}
	for name, item := range cases {
		file := promOne(item)
		e, err := locateMem(promTarget, "v3.5.0", file)
		if err != nil {
			t.Fatalf("%s did not reach the classifier: %v", name, err)
		}
		cs, err := classifyT(e, []byte(file))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range cs {
			wantClass(t, c, ClassNeedsReview, name)
		}
	}
	// Control: the plain neutral shape still passes, also with emphasis and code around whole words.
	_, cs := classifyFile(t, promTarget, "v3.5.0", promOne("* [FEATURE] Plain words. #1", "* [FEATURE] Plain *words* and `code`. #2"))
	wantClass(t, cs[0], ClassMechanicalNeutral, "control")
	wantClass(t, cs[1], ClassMechanicalNeutral, "control emphasis")
}

// classifyT classifies e under the test target of its component whose reader
// accepts the file (the first one that does), with the entry's own tag.
func classifyT(e *Entry, file []byte) ([]Classified, error) {
	alert := promTarget
	alert.Component = "alertmanager"
	tag := extract.Tag{Name: "v3.5.0", Commit: testCommit}
	if e != nil {
		tag = extract.Tag{Name: e.Tag, Commit: e.TagCommit}
	}
	var first []Classified
	var firstErr error
	for _, tg := range []Target{promTarget, cortexTarget, cortexOldTarget, thanosTarget, alert} {
		if e != nil && tg.Component != e.Component {
			continue
		}
		cs, err := Classify(tg, tag, e, file)
		if err == nil {
			return cs, nil
		}
		if firstErr == nil {
			first, firstErr = cs, err
		}
	}
	if firstErr == nil && e == nil {
		_, firstErr = Classify(promTarget, tag, nil, file)
	}
	return first, firstErr
}

func cloneEntry(t *testing.T, e *Entry) *Entry {
	t.Helper()
	b, _ := json.Marshal(e)
	var c Entry
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// The entry is re-derived by the reader itself: a self-consistent forged entry
// (rooted at a sub-heading, at another release's heading, or under another
// component or version) is refused and nothing is classified.
func TestForgedEntryIdentityIsRefused(t *testing.T) {
	file := "## 3.5.0 / 2025-07-14\n### Notes\n* [FEATURE] Plain words. #1\n### Other\n* [CHANGE] The flag --x was removed. #2\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] D. #4\n"
	tag := extract.Tag{Name: "v3.5.0", Commit: testCommit}
	good := mustLocate(t, promTarget, "v3.5.0", file)
	if _, err := Classify(promTarget, tag, good, []byte(file)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	// a. rooted at the "Notes" sub-heading, everything recomputed.
	a := cloneEntry(t, good)
	a.Section = Section{HeadingLine: 2, StartLine: 2, EndLine: 3, Digest: hexSum([]byte(strings.Join(lines[1:3], "\n") + "\n"))}
	a.Structure = []Heading{{Level: 3, Text: "Notes", Kind: "version", Line: 2, EndLine: 2}}
	a.Items = a.Items[:1]
	a.Items[0].HeadingPath = []string{}
	a.Tiling = Tiling{Lines: 2, Headings: 1, ItemLines: 1}
	// b. another release's heading under this version, and another component.
	b := cloneEntry(t, good)
	b.Section.HeadingLine, b.Section.StartLine = 7, 7
	c := cloneEntry(t, good)
	c.Component = "cortex"
	d := cloneEntry(t, good)
	d.Version = "3.4.0"
	for name, e := range map[string]*Entry{"sub-heading root": a, "other release root": b, "component": c, "version": d} {
		out, err := Classify(promTarget, tag, e, []byte(file))
		if err == nil || out != nil || !errors.Is(err, ErrEntryBinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The re-derived entry is used, so the same entry under the wrong target is refused too.
	if _, err := Classify(cortexTarget, tag, good, []byte(file)); err == nil {
		t.Error("entry accepted under another target")
	}
}

// Every refusal of the reader reaches the classifier as its typed Failure.
func TestReaderRefusalsAreInherited(t *testing.T) {
	tag := extract.Tag{Name: "v3.5.0", Commit: testCommit}
	ok := mustLocate(t, promTarget, "v3.5.0", promOne("* [FEATURE] Plain words. #1"))
	for name, f := range map[string]struct {
		file string
		code Code
	}{
		"nested release heading": {"## 3.5.0 / 2025-07-14\n\n### 3.4.0 / 2025-05-17\n\n* [FEATURE] x\n", EntryBoundaryUnproven},
		"duplicate":              {promOne("* [FEATURE] x") + "\n## 3.5.0 / 2025-07-14\n\n* [FEATURE] y\n", EntryDuplicate},
		"container fence":        {shapeListFence, EntryParseResidue},
		"indented fence stop":    {shapeItemFenceNoCloser, EntryParseResidue},
		"missing":                {"## 3.4.0 / 2025-05-17\n\n* [FEATURE] x\n", EntryMissing},
	} {
		out, err := Classify(promTarget, tag, ok, []byte(f.file))
		if out != nil {
			t.Errorf("%s: classified", name)
		}
		wantCode(t, err, f.code)
	}
}
