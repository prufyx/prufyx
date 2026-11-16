// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"
)

//go:embed classify_vocab.json
var vocabJSON []byte

// vocabulary is the reviewed vocabulary and trigger lexicon. It is embedded
// in the package, so it is part of the extractor code digest, and it is
// validated when the package loads: an invalid or weakened file stops the
// process instead of classifying with a smaller lexicon.
type vocabulary struct {
	Schema           int                       `json:"schema"`
	OperatorMarkers  []string                  `json:"operatorMarkers"`
	OperatorHeadings []string                  `json:"operatorHeadings"`
	Lexicon          []string                  `json:"lexicon"`
	Components       map[string]componentVocab `json:"components"`
}

// componentVocab is one target's reviewed NEUTRAL vocabulary: bracket markers
// (prometheus style) or classed headings (keep-a-changelog style).
type componentVocab struct {
	Markers  []string `json:"markers"`
	Headings []string `json:"headings"`
}

// requiredLexicon and requiredOperatorMarkers are the floor the design fixes;
// a vocabulary file missing one of them is refused. Extra terms only make
// the classifier stricter.
var (
	requiredLexicon = []string{
		"remov", "renam", "deprecat", "drop", "no longer", "break", "incompatib",
		"must", "requir", "minimum", "at least", "unsupported", "migrat", "upgrad",
		"downgrad", "default", "replac", "instead", "disabl", "reject", "format", "schema",
	}
	requiredOperatorMarkers  = []string{"CHANGE", "BREAKING", "REMOVED", "DEPRECATED", "SECURITY"}
	requiredOperatorHeadings = []string{"break", "deprecat", "remov", "upgrad", "migrat", "incompatib", "action required", "notable", "important", "chang"}
)

var markerTokenRE = regexp.MustCompile(`^[A-Z][A-Z0-9 _-]{0,30}$`)

// normText lower-cases and turns every run of non letter/digit runes into one
// space, padded at both ends, so that "No-longer", "no\nlonger" and "NO  LONGER"
// all read "no longer".
func normText(s string) string {
	var b strings.Builder
	b.WriteByte(' ')
	sp := true
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			sp = false
			continue
		}
		if !sp {
			b.WriteByte(' ')
			sp = true
		}
	}
	if !sp {
		b.WriteByte(' ')
	}
	return b.String()
}

func parseVocabulary(raw []byte) (*vocabulary, error) {
	var v vocabulary
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	if v.Schema != 1 {
		return nil, fmt.Errorf("schema %d is not 1", v.Schema)
	}
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}
	for _, m := range requiredOperatorMarkers {
		if !has(v.OperatorMarkers, m) {
			return nil, fmt.Errorf("operator marker %s missing", m)
		}
	}
	for _, m := range v.OperatorMarkers {
		if !markerTokenRE.MatchString(m) {
			return nil, fmt.Errorf("operator marker %q is not a marker token", m)
		}
	}
	for _, h := range requiredOperatorHeadings {
		if !has(v.OperatorHeadings, h) {
			return nil, fmt.Errorf("operator heading fragment %q missing", h)
		}
	}
	for _, h := range v.OperatorHeadings {
		if h == "" || normText(h) != " "+h+" " {
			return nil, fmt.Errorf("operator heading fragment %q is not normalised", h)
		}
	}
	for _, t := range requiredLexicon {
		if !has(v.Lexicon, t) {
			return nil, fmt.Errorf("lexicon term %q missing", t)
		}
	}
	for _, t := range v.Lexicon {
		if t == "" || normText(t) != " "+t+" " {
			return nil, fmt.Errorf("lexicon term %q is not normalised", t)
		}
	}
	if len(v.Components) == 0 {
		return nil, fmt.Errorf("no component vocabulary")
	}
	for name, c := range v.Components {
		if name == "" || strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("empty component name")
		}
		if (len(c.Markers) == 0) == (len(c.Headings) == 0) {
			return nil, fmt.Errorf("component %s: exactly one of markers and headings", name)
		}
		for _, m := range c.Markers {
			if !markerTokenRE.MatchString(m) || has(v.OperatorMarkers, m) {
				return nil, fmt.Errorf("component %s: marker %q is not a neutral marker token", name, m)
			}
		}
		for _, h := range c.Headings {
			if h == "" || h != strings.TrimSpace(h) {
				return nil, fmt.Errorf("component %s: heading %q is not trimmed", name, h)
			}
			if operatorHeading(&v, h) {
				return nil, fmt.Errorf("component %s: neutral heading %q matches the operator vocabulary", name, h)
			}
			if hit := lexiconHits(&v, h); len(hit) > 0 {
				return nil, fmt.Errorf("component %s: neutral heading %q hits the trigger lexicon", name, h)
			}
		}
	}
	return &v, nil
}

func operatorHeading(v *vocabulary, text string) bool {
	n := normText(text)
	for _, f := range v.OperatorHeadings {
		if strings.Contains(n, f) {
			return true
		}
	}
	return false
}

// lexiconHits returns the sorted distinct lexicon terms found in text.
func lexiconHits(v *vocabulary, text string) []string {
	var hits []string
	for _, form := range textForms(text) {
		n := normText(form)
		for _, t := range v.Lexicon {
			if strings.Contains(n, t) {
				hits = append(hits, t)
			}
		}
	}
	// Fifth form: lower-cased with every character that is not a letter or
	// digit deleted, so any split of a word by punctuation, link syntax or
	// spaces still hits. It over-flags on purpose: any hit is needs-review.
	squashed := squash(text)
	for _, t := range v.Lexicon {
		if strings.Contains(squashed, squash(t)) {
			hits = append(hits, t)
		}
	}
	return sortedUnique(hits)
}

// squash lower-cases s and deletes every rune that is not a letter or digit.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	linkSplitRE   = regexp.MustCompile(`[0-9A-Za-z]\[|[\])][0-9A-Za-z]`)
	markupCharsRE = regexp.MustCompile("[*_`~\\\\]")
	htmlTagRE     = regexp.MustCompile(`<!--.*?-->|</?[A-Za-z][^<>]*>`)
)

// textForms is the text as written and the text a page would show: with
// emphasis and code markers deleted (not turned into a space), and with HTML
// comments and tags removed and character references decoded. A trigger word
// is looked for in every form.
func textForms(text string) []string {
	noMarkup := markupCharsRE.ReplaceAllString(text, "")
	rendered := html.UnescapeString(htmlTagRE.ReplaceAllString(text, ""))
	return []string{text, noMarkup, rendered, markupCharsRE.ReplaceAllString(rendered, "")}
}

// hasSplitMarkup is true when the text holds an HTML angle bracket or a
// character reference, or a markup character directly between two letters or
// digits ("re**mov**ed", "snake_case"): the page then shows a different word
// than the bytes spell.
func hasSplitMarkup(text string) bool {
	if strings.ContainsAny(text, "<&") {
		return true
	}
	// Link syntax inside a word: a letter or digit directly before "[" or
	// directly after "]" or ")", on the text and on the text without markup.
	if linkSplitRE.MatchString(text) || linkSplitRE.MatchString(markupCharsRE.ReplaceAllString(text, "")) {
		return true
	}
	rs := []rune(text)
	for i, r := range rs {
		if !strings.ContainsRune("*_`~\\", r) {
			continue
		}
		j := i
		for j > 0 && strings.ContainsRune("*_`~\\", rs[j-1]) {
			j--
		}
		k := i
		for k+1 < len(rs) && strings.ContainsRune("*_`~\\", rs[k+1]) {
			k++
		}
		if j > 0 && k+1 < len(rs) && isWordRune(rs[j-1]) && isWordRune(rs[k+1]) {
			return true
		}
	}
	return false
}

func isWordRune(r rune) bool {
	return r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
}

var defaultVocab = func() *vocabulary {
	v, err := parseVocabulary(vocabJSON)
	if err != nil {
		panic("changelogentries: classify_vocab.json: " + err.Error())
	}
	return v
}()
