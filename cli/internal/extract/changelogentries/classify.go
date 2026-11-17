// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Class is the classifier's whole output. There are exactly two values. The
// classifier never decides that an item is safe to ignore for an operator, it
// never emits a rule and it never drops an item: it only separates items that
// are provably plain by a closed pattern (ClassMechanicalNeutral) from every
// other item (ClassNeedsReview), which a reviewed mark must resolve.
type Class string

const (
	ClassNeedsReview       Class = "needs-review"
	ClassMechanicalNeutral Class = "mechanical-neutral"
)

// Reason codes explain a needs-review result. The list is closed; a
// mechanical-neutral item carries none.
const (
	ReasonNoVocabulary       = "no-vocabulary-for-component"
	ReasonNotListItem        = "not-a-list-item"
	ReasonFencedCode         = "fenced-code"
	ReasonOddCharacter       = "non-ascii-or-control-character"
	ReasonSplitMarkup        = "inline-html-entity-or-intraword-markup"
	ReasonStrikethrough      = "tilde-strikethrough-or-unproven-literal"
	ReasonOperatorMarker     = "operator-marker"
	ReasonOperatorHeading    = "operator-heading"
	ReasonNoMarker           = "no-marker"
	ReasonMultipleMarkers    = "multiple-markers"
	ReasonNestedMarker       = "nested-marker"
	ReasonMarkerNotNeutral   = "marker-not-in-vocabulary"
	ReasonHeadingNotNeutral  = "heading-not-in-vocabulary"
	ReasonMarkerAndHeading   = "marker-and-heading"
	ReasonHeadingPathShape   = "heading-path-not-single-classed"
	ReasonTriggerLexicon     = "trigger-lexicon"
	ReasonTargetNotMarkerOrH = "no-neutral-class"
)

// Classified is the classifier output for one extracted item.
type Classified struct {
	Digest    string   `json:"digest"`
	StartLine int      `json:"startLine"`
	EndLine   int      `json:"endLine"`
	Class     Class    `json:"class"`
	Triggers  []string `json:"triggers"`
	Reasons   []string `json:"reasons"`
}

// ErrEntryBinding means the entry does not match the bytes handed to the
// classifier. Nothing is classified in that case.
var ErrEntryBinding = errors.New("changelogentries: entry does not match the file bytes")

var (
	bulletPrefixRE = regexp.MustCompile(`^(?:[*+-]|[0-9]{1,9}[.)])[ \t]+`)
	classTokenRE   = regexp.MustCompile(`\[([^\[\]\n]*)\]`)
	fenceLineRE    = regexp.MustCompile("(?m)^[ \t]*(?:```|~~~)")
)

func bind(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrEntryBinding, fmt.Sprintf(format, a...))
}

// Classify classifies every item of e. The entry is never trusted: the file is
// parsed again by the same reader Locate uses (LocateBytes) under the reviewed
// target and the tag, and e must equal the entry derived from the bytes in
// every field, else nothing is classified (ErrEntryBinding). A refusal of the
// reader (a fence stop, a nested release heading, a duplicate heading and so
// on) is returned unchanged as its typed Failure. That file is the blob at the
// tag's commit is proven only by the pinned reader: the caller must obtain
// both the entry and the bytes through Locate, never from stored JSON. The
// result has one element per item, in item order.
func Classify(t Target, tag extract.Tag, e *Entry, file []byte) ([]Classified, error) {
	return classifyWith(defaultVocab, t, tag, e, file)
}

func classifyWith(v *vocabulary, t Target, tag extract.Tag, e *Entry, file []byte) ([]Classified, error) {
	if e == nil {
		return nil, bind("nil entry")
	}
	want, err := LocateBytes(t, tag, file)
	if err != nil {
		return nil, err
	}
	got, err1 := e.Canonical()
	exp, err2 := want.Canonical()
	if err1 != nil || err2 != nil || !bytes.Equal(got, exp) {
		return nil, bind("the entry differs from the entry derived from the file bytes")
	}
	lines, err := splitLines(file)
	if err != nil {
		return nil, err
	}
	out := make([]Classified, 0, len(want.Items))
	for _, it := range want.Items {
		body := strings.Join(lines[it.StartLine-1:it.EndLine], "\n")
		out = append(out, classifyItem(v, want.Component, it, body))
	}
	return out, nil
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	sort.Strings(in)
	out := in[:1]
	for _, x := range in[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// classTokens lists every bracketed token of text, of any case or content,
// that is not a link text or reference (followed by "(" or "["). A token the
// vocabulary does not know is therefore still counted, never ignored.
func classTokens(text string) []string {
	var toks []string
	for _, m := range classTokenRE.FindAllStringSubmatchIndex(text, -1) {
		if m[1] < len(text) && (text[m[1]] == '(' || text[m[1]] == '[') {
			continue
		}
		toks = append(toks, text[m[2]:m[3]])
	}
	return toks
}

// leadingTokens counts the class tokens that directly follow the bullet.
func leadingTokens(first string) int {
	rest := bulletPrefixRE.ReplaceAllString(first, "")
	n := 0
	for {
		m := classTokenRE.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			return n
		}
		if m[1] < len(rest) && (rest[m[1]] == '(' || rest[m[1]] == '[') {
			return n
		}
		n++
		rest = strings.TrimLeft(rest[m[1]:], " \t")
	}
}

// hasOddRune is true for any rune outside printable ASCII (tab and newline
// aside): a letter look-alike, a format character, a combining mark or other
// invisible character can split or hide a trigger word, so an item holding
// one is never classified neutral.
func hasOddRune(s string) bool {
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f:
			return true
		case r > unicode.MaxASCII:
			return true
		}
	}
	return false
}

func hasStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// classifyItem decides one item. Everything that is not provably neutral is
// needs-review: each check below can only add a reason, and the item is
// neutral only when no reason was found and a neutral class was positively
// established.
func classifyItem(v *vocabulary, component string, it Item, body string) Classified {
	c := Classified{Digest: it.Digest, StartLine: it.StartLine, EndLine: it.EndLine, Class: ClassNeedsReview}
	var reasons []string
	add := func(r string) { reasons = append(reasons, r) }

	cv, haveVocab := v.Components[component]
	if !haveVocab {
		add(ReasonNoVocabulary)
	}
	if it.Kind != "list" {
		add(ReasonNotListItem)
	}
	if fenceLineRE.MatchString(body) {
		add(ReasonFencedCode)
	}
	if hasOddRune(body) {
		add(ReasonOddCharacter)
	}
	if hasSplitMarkup(body) {
		add(ReasonSplitMarkup)
	}

	// A tilde in any form may strike text through; a lone one is not proven a
	// literal, so it is never neutral.
	if strings.Contains(body, "~") {
		add(ReasonStrikethrough)
	}

	// Triggers: the whole item text, marker included.
	c.Triggers = lexiconHits(v, body)
	if len(c.Triggers) > 0 {
		add(ReasonTriggerLexicon)
	}

	// Markers.
	first := strings.SplitN(body, "\n", 2)[0]
	toks := classTokens(body)
	lead := leadingTokens(first)
	for _, t := range toks {
		if hasStr(v.OperatorMarkers, strings.ToUpper(strings.TrimSpace(t))) {
			add(ReasonOperatorMarker)
		}
	}
	if lead > 1 {
		add(ReasonMultipleMarkers)
	}
	if len(toks) > lead {
		add(ReasonNestedMarker)
	}

	// Headings.
	for _, h := range it.HeadingPath {
		if operatorHeading(v, h) {
			add(ReasonOperatorHeading)
		}
	}

	// Positive establishment of exactly one neutral class.
	neutralClass := false
	if haveVocab {
		switch {
		case len(cv.Markers) > 0:
			switch {
			case it.Marker == "" || len(toks) == 0:
				add(ReasonNoMarker)
			case !hasStr(cv.Markers, it.Marker):
				add(ReasonMarkerNotNeutral)
			case len(toks) != 1 || lead != 1 || toks[0] != it.Marker:
				// Extra tokens already added their own reason; never pass.
				if len(reasons) == 0 {
					add(ReasonNoMarker)
				}
			case len(it.HeadingPath) > 0:
				add(ReasonMarkerAndHeading)
			default:
				neutralClass = true
			}
		case len(cv.Headings) > 0:
			switch {
			case it.Marker != "" || len(toks) > 0:
				add(ReasonMarkerAndHeading)
			case len(it.HeadingPath) != 1:
				add(ReasonHeadingPathShape)
			case !hasStr(cv.Headings, it.HeadingPath[0]):
				add(ReasonHeadingNotNeutral)
			default:
				neutralClass = true
			}
		}
	}
	if len(reasons) == 0 && neutralClass {
		c.Class = ClassMechanicalNeutral
		c.Reasons = []string{}
		return c
	}
	if len(reasons) == 0 {
		add(ReasonTargetNotMarkerOrH)
	}
	c.Reasons = sortedUnique(reasons)
	return c
}
