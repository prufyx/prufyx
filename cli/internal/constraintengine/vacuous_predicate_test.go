// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"errors"
	"testing"
)

const vacuousEnumFact = "component.example.mode"

func vacuousRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := NewRegistry([]FactDefinition{
		{ID: scopeFactA, Component: scopeComponentA, Type: FactBool},
		{ID: vacuousEnumFact, Component: scopeComponentA, Type: FactEnum, EnumTokens: []string{"legacy", "modern", "off"}},
		{ID: "component.example.guard_enabled", Component: scopeComponentA, Type: FactBool},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func boolCondition(side, fact string, value bool) string {
	return `{"side":"` + side + `","component":"` + scopeComponentA + `","factId":"` + fact + `","boolValue":` + boolToken(value) + `}`
}

func enumCondition(side, value string) string {
	return `{"side":"` + side + `","component":"` + scopeComponentA + `","factId":"` + vacuousEnumFact + `","enumValue":"` + value + `"}`
}

func predicateRule(condition string, appliesWhen ...string) string {
	extra := `,"condition":` + condition
	if len(appliesWhen) > 0 {
		extra += `,"appliesWhen":[`
		for index, entry := range appliesWhen {
			if index > 0 {
				extra += ","
			}
			extra += entry
		}
		extra += `]`
	}
	return scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, extra)
}

func parsePredicateRule(t *testing.T, registry Registry, rule string) error {
	t.Helper()
	raw := `{"schema":"` + RulesSchema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + rule + `],"corpus":{"completeness":"` + CorpusAttestation + `","components":["` + scopeComponentA + `"]}}`
	_, err := ParseRuleSet([]byte(raw), registry)
	return err
}

// TestVacuousPredicateRuleIsRejected: a forbid_predicate_value rule whose
// appliesWhen pins the condition's own fact to a different value is
// applicable only when the condition cannot match. It could never block, yet
// it would PASS and alone make a component scope-complete. The parser
// refuses it, for bool and enum facts and on either side.
func TestVacuousPredicateRuleIsRejected(t *testing.T) {
	registry := vacuousRegistry(t)
	for name, rule := range map[string]string{
		"bool proposed": predicateRule(boolCondition("proposed", scopeFactA, true), boolCondition("proposed", scopeFactA, false)),
		"bool current":  predicateRule(boolCondition("current", scopeFactA, false), boolCondition("current", scopeFactA, true)),
		"enum proposed": predicateRule(enumCondition("proposed", "legacy"), enumCondition("proposed", "modern")),
		"enum current":  predicateRule(enumCondition("current", "off"), enumCondition("current", "legacy")),
		"among other guards": predicateRule(boolCondition("proposed", scopeFactA, true),
			boolCondition("proposed", "component.example.guard_enabled", true), boolCondition("proposed", scopeFactA, false)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := parsePredicateRule(t, registry, rule); !errors.Is(err, ErrInvalid) {
				t.Fatalf("contradictory appliesWhen/condition admitted: err=%v", err)
			}
		})
	}
}

// TestVacuousPredicateRejectionIsNarrow: rules that can block stay admitted.
func TestVacuousPredicateRejectionIsNarrow(t *testing.T) {
	registry := vacuousRegistry(t)
	for name, rule := range map[string]string{
		"no appliesWhen":          predicateRule(boolCondition("proposed", scopeFactA, true)),
		"same value":              predicateRule(boolCondition("proposed", scopeFactA, true), boolCondition("proposed", scopeFactA, true)),
		"same enum value":         predicateRule(enumCondition("proposed", "legacy"), enumCondition("proposed", "legacy")),
		"same fact, other side":   predicateRule(boolCondition("proposed", scopeFactA, true), boolCondition("current", scopeFactA, false)),
		"enum fact, other side":   predicateRule(enumCondition("proposed", "legacy"), enumCondition("current", "modern")),
		"guard on a different id": predicateRule(boolCondition("proposed", scopeFactA, true), boolCondition("proposed", "component.example.guard_enabled", false)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := parsePredicateRule(t, registry, rule); err != nil {
				t.Fatalf("blocking rule refused: %v", err)
			}
		})
	}
}

// TestPredicateWithoutContradictingGuardStillBlocks: the vacuous rule is
// refused, and the same rule without its contradicting guard parses and
// blocks on the forbidden value.
func TestPredicateWithoutContradictingGuardStillBlocks(t *testing.T) {
	registry := vacuousRegistry(t)
	rule := predicateRule(boolCondition("proposed", scopeFactA, true), boolCondition("proposed", scopeFactA, false))
	if err := parsePredicateRule(t, registry, rule); err == nil {
		t.Fatal("vacuous rule parsed")
	}
	// The same rule without its contradicting guard can block, and does.
	blocking := scopeRuleSet(t, registry, []string{scopeComponentA}, predicateRule(boolCondition("proposed", scopeFactA, true)))
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, true)})
	report, err := Evaluate(input, blocking, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Claims[0].Status != "BLOCKED" {
		t.Fatalf("claim=%+v", report.Claims[0])
	}
}
