// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// A set-valued fact declares a bounded, sorted, duplicate-free list of public
// member names (for example the feature gates a component sets) together with
// a completeness statement. The forbid_set_member operator reads it:
//
//   - BLOCKED when any member the rule forbids is present, whether or not the
//     set is declared complete: presence is decisive;
//   - PASS only when the set is declared complete and no forbidden member is
//     present;
//   - UNKNOWN otherwise (fact missing or not declared, or an incomplete set
//     without a forbidden member). Absence is never inferred from a partial
//     set.
//
// Documents that use the operator carry RulesSchemaSet and are evaluated
// under their own engine contract, so binaries that predate the operator
// reject them and every document that does not use it keeps its schema,
// digest and replay bytes.

const (
	// RulesSchemaSet is carried by, and only by, a rule document holding at
	// least one forbid_set_member rule. It may also hold reviewed ranges.
	RulesSchemaSet = "prufyx.io/deterministic-constraint-rules/v1alpha3"

	// OperatorForbidSetMember is the set-membership operator.
	OperatorForbidSetMember = "forbid_set_member"

	// MaxSetMembers bounds the members of one declared set fact.
	MaxSetMembers = 256
	// MaxSetMemberBytes bounds one member name.
	MaxSetMemberBytes = 128
	// MaxForbiddenMembers bounds the members one rule may forbid.
	MaxForbiddenMembers = 64

	reasonSetFactIncomplete = "RULE_SET_FACT_INCOMPLETE"
	setMemberPolicy         = "set-members:max=256;member-bytes=128;forbidden-per-rule=64;pattern=^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"
)

var setMemberRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

// FactSet is the set-valued fact type. Its definition carries no enum tokens.
const FactSet FactType = "set"

// SetValue is a declared set fact: members in strictly ascending byte order
// and the declarer's statement that no other member exists.
type SetValue struct {
	Members  []string `json:"members"`
	Complete bool     `json:"complete"`
}

// setCondition names the set fact a forbid_set_member rule reads and the
// members it forbids, in strictly ascending byte order.
type setCondition struct {
	Side      string   `json:"side"`
	Component string   `json:"component"`
	FactID    string   `json:"factId"`
	Members   []string `json:"members"`
}

// ValidSetMember reports whether value may appear as a set member: a public
// identifier of 1 to MaxSetMemberBytes bytes over [A-Za-z0-9._/-] that starts
// with a letter or digit.
func ValidSetMember(value string) bool {
	// The pattern bounds the length: one leading and at most 127 further
	// single-byte characters, MaxSetMemberBytes in all.
	return setMemberRE.MatchString(value)
}

// canonicalMembers checks a strictly ascending, duplicate-free member list
// within [minimum, maximum] entries.
func canonicalMembers(members []string, minimum, maximum int) bool {
	if len(members) < minimum || len(members) > maximum {
		return false
	}
	for index, member := range members {
		if !ValidSetMember(member) || (index > 0 && members[index-1] >= member) {
			return false
		}
	}
	return true
}

func validateSetValue(value *SetValue) error {
	if value == nil || !canonicalMembers(value.Members, 0, MaxSetMembers) {
		return ErrInvalid
	}
	return nil
}

func validateSetCondition(condition setCondition, registry Registry) error {
	if (condition.Side != "current" && condition.Side != "proposed") || !componentRE.MatchString(condition.Component) {
		return ErrInvalid
	}
	definition, ok := registry.definition(condition.FactID)
	if !ok || definition.Component != condition.Component || definition.Type != FactSet {
		return ErrInvalid
	}
	if !canonicalMembers(condition.Members, 1, MaxForbiddenMembers) {
		return ErrInvalid
	}
	return nil
}

// validateSetValueShape gates the exact {members, complete} shape before
// struct decoding: no aliases, nulls or extra keys. Strict decoding then
// requires an array of string members and a boolean complete, and
// canonicalMembers bounds and orders them.
func validateSetValueShape(raw json.RawMessage) error {
	_, err := exactObject(raw, []string{"members", "complete"}, nil)
	return err
}

func validateSetConditionShape(raw json.RawMessage) error {
	_, err := exactObject(raw, []string{"side", "component", "factId", "members"}, nil)
	return err
}

// setMembersHit returns the forbidden members present in declared, in
// ascending order. Both lists are canonical.
func setMembersHit(declared, forbidden []string) []string {
	hits := make([]string, 0)
	i, j := 0, 0
	for i < len(declared) && j < len(forbidden) {
		switch {
		case declared[i] == forbidden[j]:
			hits = append(hits, declared[i])
			i, j = i+1, j+1
		case declared[i] < forbidden[j]:
			i++
		default:
			j++
		}
	}
	return hits
}

// evaluateSetRule decides a forbid_set_member rule whose subject matched.
func evaluateSetRule(input inputDocument, rule rule, claim Claim) Claim {
	condition := *rule.SetCondition
	fact, found := findFact(input, condition.Side, condition.Component, condition.FactID)
	if !found || fact.State != "declared" || fact.SetValue == nil {
		claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_FACT_UNAVAILABLE"
		claim.NextAction = factAction(condition.fact())
		return claim
	}
	if hits := setMembersHit(fact.SetValue.Members, condition.Members); len(hits) > 0 {
		claim.Status, claim.MatchedMembers = "BLOCKED", hits
		return claim
	}
	if fact.SetValue.Complete {
		claim.Status = "PASS"
		return claim
	}
	claim.Status, claim.ReasonCode = "UNKNOWN", reasonSetFactIncomplete
	claim.NextAction = setIncompleteAction(condition)
	return claim
}

func (c setCondition) fact() factCondition {
	return factCondition{Side: c.Side, Component: c.Component, FactID: c.FactID}
}

func setIncompleteAction(condition setCondition) string {
	return boundedAction(fmt.Sprintf("declared %s/%s %s is not complete and holds no forbidden member; supply every source and declare it complete, or retain UNKNOWN", condition.Side, condition.Component, condition.FactID), "declared set fact is not complete and holds no forbidden member; supply every source and declare it complete, or retain UNKNOWN")
}

// usesSetOperator reports whether a parsed rule needs the set contract.
// A set condition on any other operator is rejected by validateRule.
func (r rule) usesSetOperator() bool {
	return r.Operator == OperatorForbidSetMember
}

// AnySetRule reports whether any raw rule uses forbid_set_member or carries a
// set condition.
func AnySetRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape["setCondition"]; ok {
			return true, nil
		}
		var operator string
		if raw, ok := shape["operator"]; ok && json.Unmarshal(raw, &operator) == nil && operator == OperatorForbidSetMember {
			return true, nil
		}
	}
	return false, nil
}

// engineContractDigestSet identifies the contract for rule documents that
// use forbid_set_member. It extends the ranged contract with the operator,
// the set fact type, the matched-member claim disclosure and the set bounds.
// Documents without the operator keep their existing contract and digest.
func engineContractDigestSet() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchemaSet + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version\n" + OperatorForbidSetMember + "\nfact:" + string(FactSet) + "\nclaim:matchedMembers\nreason:" + reasonSetFactIncomplete + "\n" + setMemberPolicy + "\nsubject:exact\nsubject:range\nclaim:subjectMatch\n" + rangeWidthPolicy + "\n" + basisVocabulary()))
}

// EngineContractDigestSet exposes the contract identity for rule documents
// that use forbid_set_member.
func EngineContractDigestSet() string { return engineContractDigestSet() }

// validSetClaims binds the set disclosures to the set contract: only a
// forbid_set_member claim may carry matched members, it must carry them
// exactly when it is BLOCKED, and a forbid_set_member claim is legal only
// under the set contract.
func validSetClaims(report Report) bool {
	for _, claim := range report.Claims {
		setClaim := claim.Operator == OperatorForbidSetMember
		if setClaim && report.EngineContractDigest != engineContractDigestSet() {
			return false
		}
		if !setClaim {
			if claim.MatchedMembers != nil {
				return false
			}
			continue
		}
		if claim.Status == "BLOCKED" {
			if !canonicalMembers(claim.MatchedMembers, 1, MaxForbiddenMembers) {
				return false
			}
		} else if claim.MatchedMembers != nil {
			return false
		}
	}
	return true
}

// MatchedMembersLine is the one-line human statement of the forbidden set
// members a BLOCKED forbid_set_member claim found. ok is false for every
// other claim, whose human output is unchanged.
func (c Claim) MatchedMembersLine() (line string, ok bool) {
	if len(c.MatchedMembers) == 0 {
		return "", false
	}
	return "forbidden members present: " + strings.Join(c.MatchedMembers, ", "), true
}
