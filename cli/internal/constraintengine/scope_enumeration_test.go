// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"testing"
)

// TestScopeRefusesDecidedClaimsCountedOutOfScope: a decided claim (PASS,
// BLOCKED or NO_KNOWN_ISSUE) is applicable and in scope, so a report that
// counts it in outOfScopeRules instead of enumerating it is refused, under
// every contract. Before this check a BLOCKED claim moved out of scope let
// the gate re-derive a scope-complete pass.
func TestScopeRefusesDecidedClaimsCountedOutOfScope(t *testing.T) {
	registry := scopeRegistry(t)
	blockA := scopeRule("rule-a-block", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	passB := scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB))
	input := scopeInput(t, registry, true,
		componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactB, false)})
	for _, tc := range []struct {
		name, schema string
		rules        []string
		moved        string
	}{
		{"exact contract, BLOCKED moved out", RulesSchema, []string{blockA, passA, passB}, "rule-a-block"},
		{"exact contract, PASS moved out", RulesSchema, []string{passA, passB}, "rule-a-pass"},
		{"basis contract, BLOCKED consensus moved out", RulesSchemaBasis, []string{withBasis(blockA, BasisConsensus), passA, passB}, "rule-a-block"},
	} {
		rules, err := ParseRuleSet(ruleDocumentJSON(tc.schema, []string{scopeComponentA, scopeComponentB}, tc.rules...), registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Evaluate(input, rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarshalReport(report); err != nil {
			t.Fatalf("%s: baseline refused: %v", tc.name, err)
		}
		raw, _ := json.Marshal(report)
		var forged Report
		_ = json.Unmarshal(raw, &forged)
		component := &forged.ScopeCompleteness.Components[0]
		kept := []string{}
		for _, id := range component.EvaluatedRuleIDs {
			if id != tc.moved {
				kept = append(kept, id)
			}
		}
		if len(kept) == len(component.EvaluatedRuleIDs) {
			t.Fatalf("%s: %s not evaluated: %+v", tc.name, tc.moved, component)
		}
		component.EvaluatedRuleIDs = kept
		forged.ScopeCompleteness.OutOfScopeRules++
		forged.ScopeCompleteness.Resolved, forged.ScopeCompleteness.UnresolvedReason = true, ""
		forged.Assessment, forged.Omissions = AssessmentScopeCompletePass, requiredOmissions(AssessmentScopeCompletePass)
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("%s: forged scope-complete pass accepted", tc.name)
		}
	}
}
