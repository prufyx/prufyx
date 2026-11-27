// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// interval is [low, high), or [low, high] when closed.
type interval struct {
	low, high string
	closed    bool
}

// overlapping lists the rules that constrain the same thing as r (the
// engine's constraint key, with its set member exemption) in a region the
// candidate range of r would also match. It compares with every other rule as
// it is and with every other candidate range. Anything it cannot compare
// counts as overlapping.
func overlapping(r packRule, candidate CandidateRange, rules, candidates []packRule, proposals []Proposal) []string {
	from := interval{candidate.From.Gte, candidate.From.Lt, false}
	to := interval{candidate.To.Gte, candidate.To.Lt, false}
	hit := map[string]bool{}
	same := func(other packRule) bool {
		if other.id == r.id || other.shape.Subject.Component != r.shape.Subject.Component || other.key != r.key {
			return false
		}
		a, b := r.shape.SetCondition, other.shape.SetCondition
		if a != nil && b != nil {
			members := map[string]bool{}
			for _, m := range a.Members {
				members[m] = true
			}
			for _, m := range b.Members {
				if members[m] {
					return true
				}
			}
			return false
		}
		return true
	}
	for _, other := range rules {
		if !same(other) {
			continue
		}
		s := other.shape
		otherFrom := interval{s.Subject.From, s.Subject.From, true}
		otherTo := interval{s.Subject.To, s.Subject.To, true}
		if s.Range != nil {
			otherFrom = interval{s.Range.From.Gte, s.Range.From.Lt, false}
			otherTo = interval{s.Range.To.Gte, s.Range.To.Lt, false}
		}
		// A crossing region is not computed here, so such a rule collides.
		if len(s.Crossing) != 0 || intersects(from, otherFrom) && intersects(to, otherTo) {
			hit[other.id] = true
		}
	}
	for i, other := range candidates {
		c := proposals[i].Candidate
		if same(other) && intersects(from, interval{c.From.Gte, c.From.Lt, false}) && intersects(to, interval{c.To.Gte, c.To.Lt, false}) {
			hit[other.id] = true
		}
	}
	ids := make([]string, 0, len(hit))
	for id := range hit {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func intersects(a, b interval) bool {
	below := func(low string, other interval) bool {
		x, okX := parseVersion(constraintengine.LineFloor(low))
		y, okY := parseVersion(constraintengine.LineFloor(other.high))
		if !okX || !okY {
			return true
		}
		return x.less(y) || other.closed && x == y
	}
	return below(a.low, b) && below(b.low, a)
}
