// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// RuleScope is where one pack rule belongs for attestation purposes: its
// subject component, the minor line of its reviewed target version, the
// families of the facts it reads, and the transitions it matches. Line is
// empty for a rule outside every family: only family rules are placed on a
// line, so a rule of another project with a version scheme that has no
// minor line never affects attestations.
type RuleScope struct {
	ID         string
	Component  string
	Line       string
	Families   []string
	Transition constraintengine.RuleTransition
}

type conditionShape struct {
	Component string `json:"component"`
	FactID    string `json:"factId"`
}

// ScopeOf reads the scope of one raw rule. A rule belongs to a family when it
// reads at least one of the family's facts (as its condition, set condition
// or an applicability condition): a rule that touches the family must be
// listed, so an attestation can never leave out a rule that could decide a
// fact of that family. The line of a family rule is the minor line of
// subject.to; the engine limits a reviewed range to one minor line per side,
// so a rule enters exactly one line. A family rule whose subject.to is not a
// release version is an error; the line of any other rule is not computed.
func ScopeOf(raw json.RawMessage) (RuleScope, error) {
	var shape struct {
		ID      string `json:"id"`
		Subject struct {
			Component string `json:"component"`
			From      string `json:"from"`
			To        string `json:"to"`
		} `json:"subject"`
		Range        *constraintengine.VersionRange `json:"range"`
		Condition    *conditionShape                `json:"condition"`
		SetCondition *conditionShape                `json:"setCondition"`
		AppliesWhen  []conditionShape               `json:"appliesWhen"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return RuleScope{}, fmt.Errorf("%w: rule: %v", ErrInvalid, err)
	}
	if shape.ID == "" {
		return RuleScope{}, fmt.Errorf("%w: a rule has no id", ErrInvalid)
	}
	conditions := append([]conditionShape(nil), shape.AppliesWhen...)
	if shape.Condition != nil {
		conditions = append(conditions, *shape.Condition)
	}
	if shape.SetCondition != nil {
		conditions = append(conditions, *shape.SetCondition)
	}
	scope := RuleScope{ID: shape.ID, Component: shape.Subject.Component,
		Transition: constraintengine.RuleTransition{Component: shape.Subject.Component, From: shape.Subject.From, To: shape.Subject.To, Range: shape.Range}}
	for _, id := range FamilyIDs() {
		f := families[id]
		if shape.Subject.Component != f.Component {
			continue
		}
		for _, c := range conditions {
			if f.Covers(c.Component, c.FactID) {
				scope.Families = append(scope.Families, id)
				break
			}
		}
	}
	if len(scope.Families) == 0 {
		return scope, nil
	}
	line, ok := LineOf(shape.Subject.To)
	if !ok {
		return RuleScope{}, fmt.Errorf("%w: rule %s reads a fact family but subject.to %q is not a release version", ErrInvalid, shape.ID, shape.Subject.To)
	}
	scope.Line = line
	return scope, nil
}

// RulesByScope maps every attestable scope that has rules to the sorted ids
// of those rules. A rule id that appears twice is an error.
func RulesByScope(rules []json.RawMessage) (map[Key][]string, map[string]RuleScope, error) {
	byKey := map[Key][]string{}
	byID := map[string]RuleScope{}
	for _, raw := range rules {
		s, err := ScopeOf(raw)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := byID[s.ID]; dup {
			return nil, nil, fmt.Errorf("%w: rule id %s appears twice", ErrInvalid, s.ID)
		}
		byID[s.ID] = s
		for _, f := range s.Families {
			k := Key{Component: s.Component, Line: s.Line, Family: f}
			byKey[k] = append(byKey[k], s.ID)
		}
	}
	for k := range byKey {
		sort.Strings(byKey[k])
	}
	return byKey, byID, nil
}

// Problem kinds.
const (
	// ProblemMissingRule: the pack holds a rule for the attestation's scope
	// that the attestation does not list.
	ProblemMissingRule = "missing-rule"
	// ProblemExtraRule: the attestation lists a rule the pack does not hold
	// for that scope.
	ProblemExtraRule = "extra-rule"
	// ProblemRuleNotLineWide: the attestation lists a rule of its scope that
	// does not match every transition into the line (Family.CoversLine), for
	// example a rule reviewed for its anchor pair only. Such a rule can be
	// silent on a real hop into the line, so the attestation could present a
	// hop as covered while no rule decides it.
	ProblemRuleNotLineWide = "rule-not-line-wide"
)

// Problem is one disagreement between an attestation and the pack.
type Problem struct {
	Key     Key
	RuleID  string
	Kind    string
	Message string
}

// CheckRuleSets compares every attestation's ruleIds with the rules the pack
// actually holds for its component, line and family. The two must be equal
// as sets: a rule the pack holds but the attestation leaves out, or a rule
// the attestation lists that the pack does not hold for that scope, is a
// problem. Rule state does not matter: a withdrawn rule is still a rule of
// the pack and must be listed.
//
// Equality alone does not make the line covered: every listed rule must also
// match every transition into the line (Family.CoversLine), or it is a
// rule-not-line-wide problem. A pack rule of the scope that is not line-wide
// therefore makes the line unattestable: listing it is a rule-not-line-wide
// problem, leaving it out a missing-rule problem.
func CheckRuleSets(atts []LineAttestation, rules []json.RawMessage) ([]Problem, error) {
	byKey, byID, err := RulesByScope(rules)
	if err != nil {
		return nil, err
	}
	var problems []Problem
	for _, a := range atts {
		k := a.Key()
		want := map[string]bool{}
		for _, id := range byKey[k] {
			want[id] = true
		}
		listed := map[string]bool{}
		for _, id := range a.RuleIDs {
			listed[id] = true
			if want[id] {
				if f, _ := LookupFamily(k.Family); !f.CoversLine(byID[id].Transition, k.Line) {
					problems = append(problems, Problem{Key: k, RuleID: id, Kind: ProblemRuleNotLineWide, Message: fmt.Sprintf("attestation for %s lists rule %s, which does not match every transition into line %s", k, id, k.Line)})
				}
				continue
			}
			msg := fmt.Sprintf("attestation for %s lists rule %s, which the pack does not hold", k, id)
			if s, ok := byID[id]; ok && len(s.Families) == 0 {
				msg = fmt.Sprintf("attestation for %s lists rule %s, which reads no fact of any family", k, id)
			} else if ok {
				msg = fmt.Sprintf("attestation for %s lists rule %s, which belongs to %s line %s families [%s]", k, id, s.Component, s.Line, strings.Join(s.Families, ","))
			}
			problems = append(problems, Problem{Key: k, RuleID: id, Kind: ProblemExtraRule, Message: msg})
		}
		for _, id := range byKey[k] {
			if !listed[id] {
				problems = append(problems, Problem{Key: k, RuleID: id, Kind: ProblemMissingRule, Message: fmt.Sprintf("the pack holds rule %s for %s, which the attestation does not list", id, k)})
			}
		}
	}
	return problems, nil
}
