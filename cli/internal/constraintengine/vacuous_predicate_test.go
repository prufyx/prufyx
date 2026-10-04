// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"errors"
	"math/rand"
	"strings"
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

// TestPredicateRuleAdmittedIffSatisfiable: for random forbid_predicate_value
// rules over bool and enum facts on both sides, the parser admits a rule
// exactly when some declared input satisfies its condition and every guard
// together, found by brute force over all fact values. An admitted rule
// then blocks on that witness input, so no admitted rule is unblockable.
func TestPredicateRuleAdmittedIffSatisfiable(t *testing.T) {
	registry := vacuousRegistry(t)
	type key struct{ side, fact string }
	values := map[string][]string{scopeFactA: {"true", "false"}, "component.example.guard_enabled": {"true", "false"}, vacuousEnumFact: {"legacy", "modern", "off"}}
	facts := []string{scopeFactA, "component.example.guard_enabled", vacuousEnumFact}
	var keys []key
	for _, side := range []string{"current", "proposed"} {
		for _, fact := range facts {
			keys = append(keys, key{side, fact})
		}
	}
	render := func(k key, value string) string {
		if k.fact == vacuousEnumFact {
			return enumCondition(k.side, value)
		}
		return boolCondition(k.side, k.fact, value == "true")
	}
	declared := func(fact, value string) string {
		if fact == vacuousEnumFact {
			return `{"id":"` + fact + `","state":"declared","enumValue":"` + value + `"}`
		}
		return `{"id":"` + fact + `","state":"declared","boolValue":` + value + `}`
	}
	// assignments enumerates every value of every key.
	var assignments []map[key]string
	var walk func(index int, current map[key]string)
	walk = func(index int, current map[key]string) {
		if index == len(keys) {
			copyOf := map[key]string{}
			for k, v := range current {
				copyOf[k] = v
			}
			assignments = append(assignments, copyOf)
			return
		}
		for _, value := range values[keys[index].fact] {
			current[keys[index]] = value
			walk(index+1, current)
		}
	}
	walk(0, map[key]string{})

	random := rand.New(rand.NewSource(7))
	admitted, rejected := 0, 0
	for iteration := 0; iteration < 3000; iteration++ {
		conditionKey := keys[random.Intn(len(keys))]
		conditionValue := values[conditionKey.fact][random.Intn(len(values[conditionKey.fact]))]
		required := map[key][]string{conditionKey: {conditionValue}}
		var guards []string
		for _, index := range random.Perm(len(keys))[:random.Intn(4)] {
			k := keys[index]
			value := values[k.fact][random.Intn(len(values[k.fact]))]
			guards = append(guards, render(k, value))
			required[k] = append(required[k], value)
		}
		var witness map[key]string
		for _, assignment := range assignments {
			holds := true
			for k, wanted := range required {
				for _, value := range wanted {
					holds = holds && assignment[k] == value
				}
			}
			if holds {
				witness = assignment
				break
			}
		}
		rule := predicateRule(render(conditionKey, conditionValue), guards...)
		err := parsePredicateRule(t, registry, rule)
		if (err == nil) != (witness != nil) {
			t.Fatalf("iteration %d: satisfiable=%v but parse err=%v\n%s", iteration, witness != nil, err, rule)
		}
		if err != nil {
			rejected++
			continue
		}
		admitted++
		sides := map[string][]string{}
		for _, k := range keys {
			sides[k.side] = append(sides[k.side], declared(k.fact, witness[k]))
		}
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[{"component":"` + scopeComponentA + `","version":"1.0.0","facts":[` + strings.Join(sides["current"], ",") + `]}]},"proposed":{"components":[{"component":"` + scopeComponentA + `","version":"2.0.0","facts":[` + strings.Join(sides["proposed"], ",") + `]}]}}`
		input, err := ParseInput([]byte(raw), registry)
		if err != nil {
			t.Fatalf("iteration %d: witness input: %v", iteration, err)
		}
		ruleSet := scopeRuleSet(t, registry, nil, rule)
		report, err := Evaluate(input, ruleSet, testNow(t))
		if err != nil || report.Claims[0].Status != "BLOCKED" {
			t.Fatalf("iteration %d: admitted rule does not block on its witness: err=%v claim=%+v", iteration, err, report.Claims[0])
		}
	}
	if admitted == 0 || rejected == 0 {
		t.Fatalf("admitted=%d rejected=%d", admitted, rejected)
	}
	t.Logf("admitted %d, rejected %d", admitted, rejected)
}
