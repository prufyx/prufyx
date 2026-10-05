// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
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

// ruleFacts is what the supersede pairing reads of an entry.
type ruleFacts struct {
	project   string
	key       string
	component string
	from, to  string
	rng       *constraintengine.VersionRange
	isSet     bool
	members   []string
	// rest is the canonical form of every other part of the rule that
	// can decide a verdict: the rule without its id, evidence, reason,
	// next action, operator, range, subject versions, and the key and
	// members of its fact. Two rules are the same constraint when the
	// key, and this, are equal.
	rest []byte
}

func factsOf(e *entry) (ruleFacts, error) {
	var obj struct {
		Project string          `json:"project"`
		Rule    json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(e.Raw, &obj); err != nil || len(obj.Rule) == 0 {
		return ruleFacts{}, fmt.Errorf("rule %s: no rule object", e.RuleID)
	}
	key, err := constraintengine.ConstraintKey(obj.Rule)
	if err != nil {
		return ruleFacts{}, err
	}
	var typed struct {
		Subject struct {
			Component string `json:"component"`
			From      string `json:"from"`
			To        string `json:"to"`
		} `json:"subject"`
		Range        *constraintengine.VersionRange `json:"range"`
		SetCondition *struct {
			Members []string `json:"members"`
		} `json:"setCondition"`
	}
	if err := json.Unmarshal(obj.Rule, &typed); err != nil {
		return ruleFacts{}, err
	}
	generic, err := decodeAny(obj.Rule)
	if err != nil {
		return ruleFacts{}, err
	}
	m, ok := generic.(map[string]any)
	if !ok {
		return ruleFacts{}, fmt.Errorf("rule %s: not an object", e.RuleID)
	}
	for _, k := range []string{"id", "evidence", "reasonCode", "nextAction", "operator", "range"} {
		delete(m, k)
	}
	if s, ok := m["subject"].(map[string]any); ok {
		delete(s, "from")
		delete(s, "to")
	}
	for _, k := range []string{"condition", "setCondition", "dependency"} {
		if f, ok := m[k].(map[string]any); ok {
			for _, field := range []string{"side", "component", "factId", "members"} {
				delete(f, field)
			}
		}
	}
	f := ruleFacts{
		project: obj.Project, key: key, component: typed.Subject.Component, from: typed.Subject.From, to: typed.Subject.To,
		rng: typed.Range, rest: canonicalOf(m),
	}
	if typed.SetCondition != nil {
		f.isSet, f.members = true, typed.SetCondition.Members
	}
	return f, nil
}

// span is one side of a rule's match region: [lo, hi) for a range, or the
// single version lo for an exact anchor.
type span struct {
	lo, hi string
	point  bool
}

func (f ruleFacts) region() (span, span) {
	if f.rng != nil {
		return span{lo: f.rng.From.Gte, hi: f.rng.From.Lt}, span{lo: f.rng.To.Gte, hi: f.rng.To.Lt}
	}
	return span{lo: f.from, hi: f.from, point: true}, span{lo: f.to, hi: f.to, point: true}
}

func versionLE(a, b string) bool {
	return constraintengine.SameVersion(a, b) || constraintengine.VersionLess(a, b)
}

// covers reports a ⊇ b. A version that is not a release version covers
// nothing and is covered by nothing.
func (a span) covers(b span) bool {
	if a.point {
		return b.point && constraintengine.SameVersion(a.lo, b.lo)
	}
	if !versionLE(a.lo, b.lo) {
		return false
	}
	if b.point {
		return constraintengine.VersionLess(b.lo, a.hi)
	}
	return versionLE(b.hi, a.hi)
}

func subsetOf(inner, outer []string) bool {
	have := map[string]bool{}
	for _, m := range outer {
		have[m] = true
	}
	for _, m := range inner {
		if !have[m] {
			return false
		}
	}
	return true
}

// supersedes reports that m replaces r: the same project, component and
// constraint key, an otherwise identical predicate, a region and (for a set
// rule) a member set that include r's.
func supersedes(m, r ruleFacts) bool {
	if m.project != r.project || m.component != r.component {
		return false
	}
	if m.key != r.key {
		return false
	}
	if !bytes.Equal(m.rest, r.rest) {
		return false
	}
	if m.isSet != r.isSet || (r.isSet && !subsetOf(r.members, m.members)) {
		return false
	}
	mf, mt := m.region()
	rf, rt := r.region()
	return mf.covers(rf) && mt.covers(rt)
}

// pairSupersedes links, within one pack's changes, each removal of a
// reviewed rule to the added active mechanical rule that supersedes it. A
// pair is one-to-one: a removal that several additions could replace, or an
// addition that could replace several removals, is left unpaired and so
// refused. Nothing here admits anything.
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
	facts := map[*Change]ruleFacts{}
	for _, c := range append(append([]*Change{}, removals...), additions...) {
		e := c.base
		if e == nil {
			e = c.head
		}
		f, err := factsOf(e)
		if err != nil {
			continue
		}
		facts[c] = f
	}
	forR := map[*Change][]*Change{}
	forM := map[*Change][]*Change{}
	for _, r := range removals {
		rf, ok := facts[r]
		if !ok {
			continue
		}
		for _, m := range additions {
			if mf, ok := facts[m]; ok && supersedes(mf, rf) {
				forR[r] = append(forR[r], m)
				forM[m] = append(forM[m], r)
			}
		}
	}
	for _, r := range removals {
		if len(forR[r]) != 1 {
			continue
		}
		m := forR[r][0]
		if len(forM[m]) != 1 {
			continue
		}
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
