// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestEvaluationInputsAreValidatedAtParse guards two facts the evaluator
// relies on without re-checking: every rule time parses (it discards the
// parse error), and every side is "current" or "proposed" (any other value
// would silently read the current side).
func TestEvaluationInputsAreValidatedAtParse(t *testing.T) {
	registry := scopeRegistry(t)
	valid := scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	dependency := scopeRule("rule-a", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, `,"dependency":{"side":"proposed","component":"`+scopeComponentB+`","comparison":"gte","version":"1.0.0"}`)
	guarded := scopeRule("rule-a", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, `,"appliesWhen":[{"side":"proposed","component":"`+scopeComponentA+`","factId":"`+scopeFactA+`","boolValue":true}]`)
	for _, rule := range []string{valid, dependency, guarded} {
		scopeRuleSet(t, registry, nil, rule)
	}
	for name, rule := range map[string]string{
		"reviewedAt not a time":    strings.Replace(valid, `"reviewedAt":"2026-01-01T00:00:00Z"`, `"reviewedAt":"2026-01-01"`, 1),
		"reviewedAt not UTC":       strings.Replace(valid, `"reviewedAt":"2026-01-01T00:00:00Z"`, `"reviewedAt":"2026-01-01T00:00:00+01:00"`, 1),
		"validUntil not a time":    strings.Replace(valid, `"validUntil":"`+activeUntil+`"`, `"validUntil":"soon"`, 1),
		"validUntil empty":         strings.Replace(valid, `"validUntil":"`+activeUntil+`"`, `"validUntil":""`, 1),
		"condition side":           strings.Replace(valid, `"condition":{"side":"proposed"`, `"condition":{"side":"Proposed"`, 1),
		"condition side empty":     strings.Replace(valid, `"condition":{"side":"proposed"`, `"condition":{"side":""`, 1),
		"appliesWhen side":         strings.Replace(guarded, `"appliesWhen":[{"side":"proposed"`, `"appliesWhen":[{"side":"target"`, 1),
		"dependency side":          strings.Replace(dependency, `"dependency":{"side":"proposed"`, `"dependency":{"side":"both"`, 1),
		"dependency side as a key": strings.Replace(dependency, `"dependency":{"side":"proposed"`, `"dependency":{"side":"current "`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			raw := `{"schema":"` + RulesSchema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + rule + `]}`
			if rule == valid || rule == dependency || rule == guarded {
				t.Fatal("fixture replacement did not apply")
			}
			if _, err := ParseRuleSet([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

// TestApplicabilityAgreesWithClaims guards the duplicated subject and
// appliesWhen logic in ruleApplicability and evaluateMatchedRule: a rule the
// scope calls APPLICABLE never carries an exclusion reason in its claim, and
// a NOT_APPLICABLE rule always does. A drift between the two copies would
// make the scope validator refuse honest reports.
func TestApplicabilityAgreesWithClaims(t *testing.T) {
	registry := scopeRegistry(t)
	random := rand.New(rand.NewSource(20261004))
	components := []string{scopeComponentA, scopeComponentB}
	facts := map[string]string{scopeComponentA: scopeFactA, scopeComponentB: scopeFactB}
	pick := func(values ...string) string { return values[random.Intn(len(values))] }
	render := func(id, component string) string {
		extra := ""
		if random.Intn(2) == 0 {
			extra = `,"appliesWhen":[{"side":"` + pick("current", "proposed") + `","component":"` + component + `","factId":"` + facts[component] + `","boolValue":` + pick("true", "false") + `}]`
		}
		to := pick("2.0.0", "2.0.0", "3.0.0")
		state, until := pick("active", "active", "withdrawn"), pick(activeUntil, activeUntil, expiredUntil)
		switch random.Intn(3) {
		case 0:
			// A guard on the condition's own side and fact must agree with
			// it: the parser refuses a contradicting one.
			condition := `,"condition":{"side":"proposed","component":"` + component + `","factId":"` + facts[component] + `","boolValue":true}`
			extra = strings.Replace(extra, `"side":"proposed","component":"`+component+`","factId":"`+facts[component]+`","boolValue":false`, `"side":"proposed","component":"`+component+`","factId":"`+facts[component]+`","boolValue":true`, 1)
			return scopeRule(id, "forbid_predicate_value", component, "1.0.0", to, state, until, condition+extra)
		case 1:
			return scopeRule(id, "forbid_target_version", component, "1.0.0", to, state, until, extra)
		default:
			return scopeRule(id, "require_component_version", component, "1.0.0", to, state, until, `,"dependency":{"side":"proposed","component":"`+pick(components...)+`","comparison":"`+pick("gte", "lt")+`","version":"2.0.0"}`+extra)
		}
	}
	tally := map[string]int{}
	for iteration := 0; iteration < 1500; iteration++ {
		var rules []string
		for index := 0; index < 1+random.Intn(4); index++ {
			rules = append(rules, render(fmt.Sprintf("rule-%02d", index), pick(components...)))
		}
		ruleSet := scopeRuleSet(t, registry, nil, rules...)
		var inputs []componentInput
		for _, component := range components {
			fact := ""
			switch random.Intn(3) {
			case 0:
				fact = declaredFact(facts[component], true)
			case 1:
				fact = declaredFact(facts[component], false)
			}
			inputs = append(inputs, componentInput{Component: component, From: pick("1.0.0", "1.0.0", "1.5.0"), To: pick("2.0.0", "3.0.0"), Fact: fact})
		}
		input := scopeInput(t, registry, true, inputs...)
		report, err := Evaluate(input, ruleSet, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		scope := map[string]struct{}{scopeComponentA: {}, scopeComponentB: {}}
		for index, candidate := range ruleSet.document.Rules {
			applicability, reason := ruleApplicability(input.document, scope, candidate)
			claim := report.Claims[index]
			_, exclusion := exclusionReasons[claim.ReasonCode]
			tally[applicability]++
			switch applicability {
			case ApplicabilityApplicable:
				if exclusion {
					t.Fatalf("iteration %d: applicable rule %s carries exclusion reason %s", iteration, candidate.ID, claim.ReasonCode)
				}
			case ApplicabilityNotApplicable:
				if _, ok := exclusionReasons[reason]; !ok {
					t.Fatalf("iteration %d: not-applicable rule %s with non-exclusion reason %s", iteration, candidate.ID, reason)
				}
			}
		}
	}
	for _, applicability := range []string{ApplicabilityApplicable, ApplicabilityNotApplicable, ApplicabilityUndetermined} {
		if tally[applicability] == 0 {
			t.Fatalf("no rule was %s: %v", applicability, tally)
		}
	}
}
