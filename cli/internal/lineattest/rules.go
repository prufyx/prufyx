// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RuleScope is where one pack rule belongs for attestation purposes: its
// subject component, the minor line of its reviewed target version, and the
// families of the facts it reads.
type RuleScope struct {
	ID        string
	Component string
	Line      string
	Families  []string
}

type conditionShape struct {
	Component string `json:"component"`
	FactID    string `json:"factId"`
}

// ScopeOf reads the scope of one raw rule. A rule belongs to a family when it
// reads at least one of the family's facts (as its condition, set condition
// or an applicability condition): a rule that touches the family must be
// listed, so an attestation can never leave out a rule that could decide a
// fact of that family. The line is the minor line of subject.to; the engine
// limits a reviewed range to one minor line per side, so a rule enters
// exactly one line.
func ScopeOf(raw json.RawMessage) (RuleScope, error) {
	var shape struct {
		ID      string `json:"id"`
		Subject struct {
			Component string `json:"component"`
			To        string `json:"to"`
		} `json:"subject"`
		Condition    *conditionShape  `json:"condition"`
		SetCondition *conditionShape  `json:"setCondition"`
		AppliesWhen  []conditionShape `json:"appliesWhen"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return RuleScope{}, fmt.Errorf("%w: rule: %v", ErrInvalid, err)
	}
	line, ok := LineOf(shape.Subject.To)
	if shape.ID == "" || !ok {
		return RuleScope{}, fmt.Errorf("%w: rule %q has no valid id and subject.to", ErrInvalid, shape.ID)
	}
	conditions := append([]conditionShape(nil), shape.AppliesWhen...)
	if shape.Condition != nil {
		conditions = append(conditions, *shape.Condition)
	}
	if shape.SetCondition != nil {
		conditions = append(conditions, *shape.SetCondition)
	}
	scope := RuleScope{ID: shape.ID, Component: shape.Subject.Component, Line: line}
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
				continue
			}
			msg := fmt.Sprintf("attestation for %s lists rule %s, which the pack does not hold", k, id)
			if s, ok := byID[id]; ok {
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
