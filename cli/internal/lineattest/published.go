// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import "fmt"

// publishedLineComponents is the closed set of components whose hops go
// between consecutive PUBLISHED lines: a line is a major.minor with at least
// one final release tag, and a minor number nobody released is skipped. A
// component is added by a reviewed change to the code, together with its
// target; it is not a calendar component (calverComponents) and the set is
// empty until a project is registered.
var publishedLineComponents = map[string]bool{}

// PublishedLineComponent reports whether the component's hops are between
// consecutive published lines.
func PublishedLineComponent(component string) bool { return publishedLineComponents[component] }

// CalverMajorFrom is the first major of the calendar era: a line whose major
// is below it is a semantic-version line (a hop goes from M.(m-1) strictly),
// a line from it on is a calendar line (YY.minor).
const CalverMajorFrom = 20

func sameEra(a, b string) bool {
	am, _ := lineNumbers(a)
	bm, _ := lineNumbers(b)
	return (am < CalverMajorFrom) == (bm < CalverMajorFrom)
}

// publishedHopShape reports whether a hop from line from into line to has
// the shape of a published-line hop: both valid lines, from below to, in one
// era, and, in the semantic-version era, M.(m-1) -> M.m exactly. It says
// nothing about whether from is the line the upstream publishes just below to;
// only AdjacentPublishedLine, over a live tag listing, does.
func publishedHopShape(from, to string) bool {
	if !ValidLine(from) || !ValidLine(to) || !LineLess(from, to) || !sameEra(from, to) {
		return false
	}
	fm, fn := lineNumbers(from)
	tm, tn := lineNumbers(to)
	if tm < CalverMajorFrom {
		return fm == tm && fn+1 == tn
	}
	return true
}

// LineHop reports whether a hop from line from into line to is of the hop
// shape the component's own line scheme defines: PreviousLine for an
// ordinary or calendar component, the published-line shape for a component
// of publishedLineComponents.
func LineHop(component, hopFromLine, to string) bool {
	if PublishedLineComponent(component) {
		return publishedHopShape(hopFromLine, to)
	}
	previous, ok := PreviousLine(component, to)
	return ok && previous == hopFromLine
}

// AdjacentPublishedLine is the published line a hop into line to comes from:
// the highest line below to in published, provided a hop between them has the
// published-line shape (same era; strict m-1 below major CalverMajorFrom).
// published is every line the live tags show, lines that cannot be read
// included by the caller as lines, so that an unknown line blocks the hop
// rather than being skipped. ok is false when there is no line below to or the
// highest one is across an era boundary or not the strict previous minor.
func AdjacentPublishedLine(published []string, to string) (string, bool) {
	if !ValidLine(to) {
		return "", false
	}
	best := ""
	for _, l := range published {
		if !ValidLine(l) {
			return "", false
		}
		if LineLess(l, to) && (best == "" || LineLess(best, l)) {
			best = l
		}
	}
	if best == "" || !publishedHopShape(best, to) {
		return "", false
	}
	return best, true
}

// FromLine is the line the attestation's hop comes from. For an ordinary or
// calendar component it is PreviousLine of the attested line. For a
// component of publishedLineComponents it is carried by the attestation:
// every release of releases.from is one line, in the era of the attested line
// and below it, in the published-line hop shape. ok is false when the
// attestation does not state such a line.
func (a LineAttestation) FromLine() (string, bool) {
	if !PublishedLineComponent(a.Component) {
		return PreviousLine(a.Component, a.Line)
	}
	if a.Releases == nil {
		return "", false
	}
	return releasesFromLine(a.Line, a.Releases.From)
}

// HopFrom reports whether the attestation covers hops from line from: it is
// the attestation's FromLine.
func (a LineAttestation) HopFrom(fromLine string) bool {
	line, ok := a.FromLine()
	return ok && line == fromLine
}

// releasesFromLine reads the one line of a from-release list and checks it
// is a published-line hop source of line.
func releasesFromLine(line string, from []Release) (string, bool) {
	if len(from) == 0 {
		return "", false
	}
	l, ok := LineOf(from[0].Version)
	if !ok {
		return "", false
	}
	for _, r := range from {
		if x, ok := LineOf(r.Version); !ok || x != l {
			return "", false
		}
	}
	if !publishedHopShape(l, line) {
		return "", false
	}
	return l, true
}

// fromLineOf is the line releases.from of an attestation of line must name.
func fromLineOf(component, line string, r *Releases) (string, error) {
	if !PublishedLineComponent(component) {
		previous, ok := PreviousLine(component, line)
		if !ok {
			return "", fmt.Errorf("%w: line %s has no previous line to name releases of", ErrInvalid, line)
		}
		return previous, nil
	}
	l, ok := releasesFromLine(line, r.From)
	if !ok {
		return "", fmt.Errorf("%w: releases.from must name releases of one line, in the era of line %s and a published-line hop shape below it", ErrInvalid, line)
	}
	return l, nil
}

// SetPublishedLineComponentsForTest replaces the published-line component set
// and returns a function that restores it. Tests of a project that is not in
// the set use it; no production code calls it.
func SetPublishedLineComponentsForTest(components ...string) (restore func()) {
	previous := publishedLineComponents
	publishedLineComponents = map[string]bool{}
	for _, c := range components {
		publishedLineComponents[c] = true
	}
	return func() { publishedLineComponents = previous }
}
