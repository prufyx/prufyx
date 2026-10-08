// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/supersedepred"
)

// The supersede class. Removing a reviewed rule R is refused (it can turn a
// BLOCKED upgrade into a scope-complete PASS) unless the same change adds a
// mechanical rule M that replaces it: M must re-derive from the pinned
// upstream bytes, constrain exactly what R constrains (an equal engine
// constraint key and an otherwise identical predicate) and cover everything
// R covers (its match region, and for a set rule its forbidden members).
// Only the owner may make such a change, and it is never merged by the
// automation. R and M are one loosening for the limits and are not
// withdrawals for the circuit breakers.

// KindSupersede marks the removal half of a supersede pair.
const KindSupersede = "supersede"

// ProofSupersede is the proof of an admitted removal half: the owner's
// change replaces the rule with a re-derived one that covers it.
const ProofSupersede = "superseded"

// DefaultOwnerLogin is the repository owner's login (the CODEOWNERS entry).
const DefaultOwnerLogin = "airstand"

// Supersede is one R to M pair of the report.
type Supersede struct {
	Pack string `json:"pack"`
	// Old is the removed reviewed rule, New the added mechanical rule.
	Old string `json:"old"`
	New string `json:"new"`
	// OK reports whether the removal was admitted.
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// ruleFacts is what the supersede pairing reads of an entry; the predicate
// itself lives in supersedepred, shared with `extract supersede`.
type ruleFacts = supersedepred.Facts

func factsOf(e *entry) (ruleFacts, error) { return supersedepred.FactsOf(e.Raw, e.RuleID) }

// supersedes reports that m replaces r (see supersedepred.Facts.Supersedes).
func supersedes(m, r ruleFacts) bool { return m.Supersedes(r) }

// pairSupersedes links, within one pack's changes, each removal of a
// reviewed rule to the added active mechanical rule that supersedes it
// (supersedepred.Pair: one-to-one, a removal or addition that is ambiguous
// is left unpaired and so refused). Nothing here admits anything.
func pairSupersedes(changes []*Change) {
	var removals, additions []*Change
	for _, c := range changes {
		if c.Section != "" || c.Member != "" {
			continue
		}
		switch {
		case c.head == nil && c.base != nil && c.Basis == constraintengine.BasisReviewed:
			removals = append(removals, c)
		case c.base == nil && c.head != nil && c.Basis == constraintengine.BasisMechanical && c.head.Evidence.State == "active":
			additions = append(additions, c)
		}
	}
	candidate := func(c *Change) supersedepred.Candidate {
		e := c.base
		if e == nil {
			e = c.head
		}
		cand := supersedepred.Candidate{Basis: c.Basis, State: e.Evidence.State}
		if f, err := factsOf(e); err == nil {
			cand.Facts = &f
		}
		return cand
	}
	rc := make([]supersedepred.Candidate, len(removals))
	for i, c := range removals {
		rc[i] = candidate(c)
	}
	ac := make([]supersedepred.Candidate, len(additions))
	for i, c := range additions {
		ac[i] = candidate(c)
	}
	for i, j := range supersedepred.Pair(rc, ac) {
		r, m := removals[i], additions[j]
		r.supersededBy, m.supersedes = m, r
		r.SupersededBy, m.Supersedes = m.RuleID, r.RuleID
		r.Kinds = append(r.Kinds, KindSupersede)
	}
}

// isSupersede reports whether the change is half of a supersede pair.
func (c *Change) isSupersede() bool { return c.supersededBy != nil || c.supersedes != nil }

// admitSupersede decides a paired removal after the addition has been
// re-derived. Only the owner's own change is admitted: the author and the
// sender of the run must both be the owner, who is never the automation.
func admitSupersede(c *Change, opts Options) {
	m := c.supersededBy
	switch {
	case opts.Owner == "" || opts.Owner == opts.BotLogin:
		c.fail("a reviewed rule is superseded only by the owner's own change; no owner is configured apart from the automation account")
	case opts.Author != opts.Owner:
		c.fail(fmt.Sprintf("a reviewed rule is superseded only by the owner's own change: author %q is not the owner", logSafe(opts.Author)))
	case opts.Sender != opts.Owner:
		c.fail(fmt.Sprintf("a reviewed rule is superseded only by the owner's own change: the run was triggered by %q, not the owner", logSafe(opts.Sender)))
	case len(commitListReasons(opts, opts.Owner, false, "the owner")) > 0:
		c.fail("a reviewed rule is superseded only by the owner's own commits: " + strings.Join(commitListReasons(opts, opts.Owner, false, "the owner"), "; "))
	case !m.OK || m.Proof != ProofRederived:
		c.fail(fmt.Sprintf("the superseding rule %s is not re-derived from the pinned upstream bytes: %s", logSafe(m.RuleID), logSafe(m.Detail)))
	default:
		c.OK, c.Proof = true, ProofSupersede
	}
}

// supersedeReport lists the pairs of a classification, by pack and old id.
func supersedeReport(cls *Classification) []Supersede {
	out := []Supersede{}
	for _, c := range cls.Changes {
		if c.supersededBy != nil {
			out = append(out, Supersede{Pack: c.Pack, Old: c.RuleID, New: c.supersededBy.RuleID, OK: c.OK, Detail: c.Detail})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pack != out[j].Pack {
			return out[i].Pack < out[j].Pack
		}
		return out[i].Old < out[j].Old
	})
	return out
}
