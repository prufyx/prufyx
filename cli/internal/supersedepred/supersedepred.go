// SPDX-License-Identifier: AGPL-3.0-only

// Package supersedepred is the one definition of when a mechanical rule M
// replaces a reviewed rule R. The knowledge gate admits a removal of R only
// when this says M replaces it, and `extract supersede` plans a replacement
// only when this says so, so the tool can never hand the owner a pairing the
// gate refuses.
//
// M replaces R when all of these hold:
//
//   - R's basis is reviewed (an absent basis is reviewed) and M's basis is
//     mechanical with state active;
//   - they are for the same project and the same component;
//   - they have an equal engine constraint key (constraintengine.ConstraintKey);
//   - the rest of the rule is identical: condition values, applies-when and
//     dependency bounds, and everything else except id, evidence, reason,
//     next action, operator, range, subject and the key and members of the
//     fact;
//   - M's match region, and for a set rule its forbidden members, include R's;
//   - the pairing is one-to-one: a removal that several additions could
//     replace, or an addition that could replace several removals, is not
//     paired.
package supersedepred

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Facts is what the pairing reads of one pack entry.
type Facts struct {
	Project   string
	Key       string
	Component string
	From, To  string
	Range     *constraintengine.VersionRange
	IsSet     bool
	Members   []string
	// Rest is the canonical form of every other part of the rule that
	// can decide a verdict.
	Rest []byte
}

// CanonicalRule is the canonical form of the predicate; a variable only so
// a test can make it fail.
var CanonicalRule = func(v any) []byte {
	raw, err := extract.Canonical(v)
	if err != nil {
		return nil
	}
	return raw
}

// FactsOf reads the facts of one pack entry (an object with a project and a
// rule). id only names the rule in an error.
func FactsOf(entryRaw []byte, id string) (Facts, error) {
	var obj struct {
		Project string          `json:"project"`
		Rule    json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(entryRaw, &obj); err != nil || len(obj.Rule) == 0 {
		return Facts{}, fmt.Errorf("rule %s: no rule object", id)
	}
	key, err := constraintengine.ConstraintKey(obj.Rule)
	if err != nil {
		return Facts{}, err
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
		return Facts{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(obj.Rule))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return Facts{}, err
	}
	m, ok := generic.(map[string]any)
	if !ok {
		return Facts{}, fmt.Errorf("rule %s: not an object", id)
	}
	for _, k := range []string{"id", "evidence", "reasonCode", "nextAction", "operator", "range", "subject"} {
		delete(m, k)
	}
	for _, k := range []string{"condition", "setCondition", "dependency"} {
		if f, ok := m[k].(map[string]any); ok {
			for _, field := range []string{"side", "component", "factId", "members"} {
				delete(f, field)
			}
		}
	}
	rest := CanonicalRule(m)
	if len(rest) == 0 {
		return Facts{}, fmt.Errorf("rule %s: no canonical form", id)
	}
	f := Facts{
		Project: obj.Project, Key: key, Component: typed.Subject.Component, From: typed.Subject.From, To: typed.Subject.To,
		Range: typed.Range, Rest: rest,
	}
	if typed.SetCondition != nil {
		f.IsSet, f.Members = true, typed.SetCondition.Members
	}
	return f, nil
}

// span is one side of a rule's match region: [lo, hi) for a range, or the
// single version lo for an exact anchor.
type span struct {
	lo, hi string
	point  bool
}

func (f Facts) region() (span, span) {
	if f.Range != nil {
		return span{lo: f.Range.From.Gte, hi: f.Range.From.Lt}, span{lo: f.Range.To.Gte, hi: f.Range.To.Lt}
	}
	return span{lo: f.From, hi: f.From, point: true}, span{lo: f.To, hi: f.To, point: true}
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

// Supersedes reports that m replaces r as far as the rules themselves go:
// the same project, component and constraint key, an otherwise identical
// predicate, a region and (for a set rule) a member set that include r's.
// Basis, state and one-to-one pairing are Pair's.
func (m Facts) Supersedes(r Facts) bool {
	if m.Project != r.Project || m.Component != r.Component {
		return false
	}
	if m.Key != r.Key {
		return false
	}
	if !bytes.Equal(m.Rest, r.Rest) {
		return false
	}
	if r.IsSet && !subsetOf(r.Members, m.Members) {
		return false
	}
	mf, mt := m.region()
	rf, rt := r.region()
	return mf.covers(rf) && mt.covers(rt)
}

// Candidate is one rule offered to Pair. Facts is nil when the entry could
// not be read; such a rule never pairs. State is the rule's evidence state.
type Candidate struct {
	Facts *Facts
	Basis string
	State string
}

// Pair links each removal to the addition that replaces it and returns the
// pairs as removal index to addition index. A removal must have a reviewed
// basis; an addition must be mechanical and active. A pair is one-to-one: a
// removal that several additions could replace, or an addition that could
// replace several removals, is left unpaired. Nothing here admits anything.
func Pair(removals, additions []Candidate) map[int]int {
	forR := map[int][]int{}
	forM := map[int][]int{}
	for i, r := range removals {
		if r.Facts == nil || constraintengine.EffectiveBasis(r.Basis) != constraintengine.BasisReviewed {
			continue
		}
		for j, m := range additions {
			if m.Facts == nil || constraintengine.EffectiveBasis(m.Basis) != constraintengine.BasisMechanical || m.State != "active" {
				continue
			}
			if m.Facts.Supersedes(*r.Facts) {
				forR[i] = append(forR[i], j)
				forM[j] = append(forM[j], i)
			}
		}
	}
	out := map[int]int{}
	for i := range removals {
		if len(forR[i]) != 1 {
			continue
		}
		j := forR[i][0]
		if len(forM[j]) != 1 {
			continue
		}
		out[i] = j
	}
	return out
}
