// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
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
	n := normText(text)
	var hits []string
	for _, t := range v.Lexicon {
		if strings.Contains(n, t) {
			hits = append(hits, t)
		}
	}
	return sortedUnique(hits)
}

var defaultVocab = func() *vocabulary {
	v, err := parseVocabulary(vocabJSON)
	if err != nil {
		panic("changelogentries: classify_vocab.json: " + err.Error())
	}
	return v
}()
