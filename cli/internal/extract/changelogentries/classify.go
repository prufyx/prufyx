// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
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
	ReasonOddCharacter       = "non-ascii-letter-or-format-character"
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
	classTokenRE   = regexp.MustCompile(`\[([A-Z][A-Z0-9 _-]{0,30})\]`)
	fenceLineRE    = regexp.MustCompile("(?m)^[ \t]*(?:```|~~~)")
)

func bind(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrEntryBinding, fmt.Sprintf(format, a...))
}

// Classify classifies every item of e. file must be the exact changelog blob
// the entry was located in: the entry is re-derived from it (file digest,
// section digest, headings, heading paths, item bounds, markers and item
// digests) and any difference refuses the whole entry. The result has one
// element per item, in item order.
func Classify(e *Entry, file []byte) ([]Classified, error) {
	return classifyWith(defaultVocab, e, file)
}

func classifyWith(v *vocabulary, e *Entry, file []byte) ([]Classified, error) {
	if e == nil {
		return nil, bind("nil entry")
	}
	lines, err := verifyEntry(e, file)
	if err != nil {
		return nil, err
	}
	out := make([]Classified, 0, len(e.Items))
	for _, it := range e.Items {
		body := strings.Join(lines[it.StartLine-1:it.EndLine], "\n")
		c := classifyItem(v, e.Component, it, body)
		out = append(out, c)
	}
	return out, nil
}

// verifyEntry re-derives the entry from the bytes and returns the file lines.
func verifyEntry(e *Entry, file []byte) ([]string, error) {
	if hexSum(file) != e.Source.FileDigest {
		return nil, bind("file digest differs")
	}
	lines, err := splitLines(file)
	if err != nil {
		return nil, err
	}
	s, t := e.Section.StartLine, e.Section.EndLine
	if s < 1 || t < s || t > len(lines) || e.Section.HeadingLine != s {
		return nil, bind("section span is outside the file")
	}
	if hexSum([]byte(strings.Join(lines[s-1:t], "\n")+"\n")) != e.Section.Digest {
		return nil, bind("section digest differs")
	}
	sc := scan(lines)

	// Headings: the entry's structure must be exactly the scanned headings of
	// the span, and the first one the version heading.
	var hs []heading
	for _, h := range sc.headings {
		if h.Line >= s && h.Line <= t {
			hs = append(hs, h)
		}
	}
	if len(hs) != len(e.Structure) || len(hs) == 0 {
		return nil, bind("heading count differs")
	}
	for i, h := range hs {
		g := e.Structure[i]
		kind := "sub"
		if i == 0 {
			kind = "version"
		}
		if g.Level != h.Level || g.Text != h.Text || g.Line != h.Line || g.EndLine != h.EndLine || g.Kind != kind {
			return nil, bind("heading %d differs", i+1)
		}
	}

	// Items: exactly the scanned items of the span, same bounds, marker, kind.
	var raw []rawItem
	for _, it := range sc.items {
		if it.Start >= s && it.Start <= t {
			if it.End > t {
				return nil, bind("an item reaches past the section end")
			}
			raw = append(raw, it)
		}
	}
	if len(raw) != len(e.Items) || len(raw) == 0 {
		return nil, bind("item count differs: %d scanned, %d in the entry", len(raw), len(e.Items))
	}
	var stack []Heading
	hi := 0
	seen := map[string]int{}
	for i, it := range e.Items {
		r := raw[i]
		kind := "list"
		if r.Block {
			kind = "block"
		}
		if it.StartLine != r.Start || it.EndLine != r.End || it.Marker != r.Marker || it.Kind != kind {
			return nil, bind("item %d differs", i+1)
		}
		for hi < len(e.Structure) && e.Structure[hi].Line < r.Start {
			h := e.Structure[hi]
			hi++
			if h.Kind == "version" {
				continue
			}
			for len(stack) > 0 && stack[len(stack)-1].Level >= h.Level {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, h)
		}
		if len(it.HeadingPath) != len(stack) {
			return nil, bind("item %d heading path differs", i+1)
		}
		for j, h := range stack {
			if it.HeadingPath[j] != h.Text {
				return nil, bind("item %d heading path differs", i+1)
			}
		}
		body := strings.Join(lines[r.Start-1:r.End], "\n")
		want := itemDigest(e.Component, e.Version, it.HeadingPath, it.Marker, body)
		if it.Digest != want {
			return nil, bind("item %d digest differs", i+1)
		}
		seen[want]++
		if it.Occurrence != seen[want] {
			return nil, bind("item %d occurrence differs", i+1)
		}
	}
	return lines, nil
}

// itemDigest mirrors the digest Locate gives an item: hex sha256(component NUL
// version NUL headingPath NUL marker NUL item bytes), NUL between parts only, the heading path joined
// with U+001F. verifyEntry compares it with the entry, so a drift between the
// two is a refusal, never a silent pass.
func itemDigest(component, version string, path []string, marker, body string) string {
	d := sha256.New()
	for i, part := range []string{component, version, strings.Join(path, "\x1f"), marker, body} {
		if i > 0 {
			d.Write([]byte{0})
		}
		d.Write([]byte(part))
	}
	return hex.EncodeToString(d.Sum(nil))
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

// classTokens lists the bracketed upper-case tokens of text that are not a
// link text or reference (followed by "(" or "[").
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

func hasOddRune(s string) bool {
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return true
		case r > unicode.MaxASCII && unicode.IsLetter(r):
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
		if hasStr(v.OperatorMarkers, t) {
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
