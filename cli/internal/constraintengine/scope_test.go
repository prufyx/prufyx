// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	scopeComponentA = "pkg:oci/example/controller"
	scopeComponentB = "pkg:oci/example/sidecar"
	scopeFactA      = "component.example.feature_enabled"
	scopeFactB      = "component.sidecar.feature_enabled"
	activeUntil     = "2027-01-01T00:00:00Z"
	expiredUntil    = "2026-05-01T00:00:00Z"
)

// TestAbsentScopeIsByteIdenticalAndStaysUnknown pins the compatibility
// property the whole change rests on: with no scope declaration the engine
// emits exactly what it emitted before, so every issued digest and replay
// holds.
func TestAbsentScopeIsByteIdenticalAndStaysUnknown(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, nil, scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)))
	input := scopeInput(t, registry, false, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentUnknown || report.ScopeCompleteness != nil {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
	}
	if report.Omissions[1] != omissionWholeUpgradeNotChecked {
		t.Fatalf("omissions=%v", report.Omissions)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "scopeCompleteness") || strings.Contains(string(raw), "SCOPE_COMPLETE") {
		t.Fatalf("unscoped report carried scope fields: %s", raw)
	}
	if _, err := Replay(input, rules, testNow(t), raw); err != nil {
		t.Fatal(err)
	}
}

// TestScopeCompletePassEnumeratesWhatWasNotEvaluated is the product claim:
// all applicable constraints passed, and everything skipped is named.
func TestScopeCompletePassEnumeratesWhatWasNotEvaluated(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, []string{scopeComponentA},
		scopeRule("rule-a-applicable", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		scopeRule("rule-b-other-pair", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, ""),
	)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
	}
	scope := report.ScopeCompleteness
	if scope == nil || !scope.Resolved || scope.UnresolvedReason != "" || scope.ContractDigest != ScopeContractDigest() {
		t.Fatalf("scope=%+v", scope)
	}
	if len(scope.Components) != 1 || len(scope.Components[0].EvaluatedRuleIDs) != 1 || scope.Components[0].EvaluatedRuleIDs[0] != "rule-a-applicable" {
		t.Fatalf("evaluated=%+v", scope.Components)
	}
	skipped := scope.Components[0].NotEvaluated
	if len(skipped) != 1 || skipped[0].RuleID != "rule-b-other-pair" || skipped[0].Applicability != ApplicabilityNotApplicable || skipped[0].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("notEvaluated=%+v", skipped)
	}
	if report.Omissions[1] != omissionWholeUpgradeScoped {
		t.Fatalf("omissions=%v", report.Omissions)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(input, rules, testNow(t), raw); err != nil {
		t.Fatal(err)
	}
}

// TestApplicableBlockerOutranksIncompleteness mirrors ReduceDecision's
// precedence: a decided applicable blocker is positive evidence, and an
// unresolved remainder does not erase it.
func TestApplicableBlockerOutranksIncompleteness(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, []string{scopeComponentA},
		scopeRule("rule-a-blocked", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		scopeRule("rule-b-stale", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, ""),
	)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, true)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentBlocked {
		t.Fatalf("assessment=%q", report.Assessment)
	}
	if report.ScopeCompleteness.Resolved || report.ScopeCompleteness.UnresolvedReason != unresolvedApplicability {
		t.Fatalf("scope=%+v", report.ScopeCompleteness)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

// TestIncompleteScopeStaysUnknown covers every way the applicable set can fail
// to resolve. None of them may produce a completeness claim.
func TestIncompleteScopeStaysUnknown(t *testing.T) {
	registry := scopeRegistry(t)
	passRuleA := scopeRule("rule-a-applicable", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	cases := []struct {
		name, want string
		rules      RuleSet
		input      Input
	}{
		{
			name: "applicable rule with an undeclared fact", want: unresolvedApplicability,
			rules: scopeRuleSet(t, registry, []string{scopeComponentA}, passRuleA),
			input: scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: `{"id":"` + scopeFactA + `","state":"missing"}`}),
		},
		{
			name: "applicable rule with stale evidence", want: unresolvedApplicability,
			rules: scopeRuleSet(t, registry, []string{scopeComponentA}, scopeRule("rule-a-stale", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, "")),
			input: scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}),
		},
		{
			name: "applicable rule with withdrawn evidence", want: unresolvedApplicability,
			rules: scopeRuleSet(t, registry, []string{scopeComponentA}, scopeRule("rule-a-withdrawn", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "withdrawn", activeUntil, "")),
			input: scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}),
		},
		{
			name: "no rule applies to the declared transition", want: unresolvedNoApplicableRule,
			rules: scopeRuleSet(t, registry, []string{scopeComponentA}, scopeRule("rule-a-other-pair", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, "")),
			input: scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}),
		},
		{
			name: "scoped component outside the attested corpus", want: unresolvedComponentNotAttested,
			rules: scopeRuleSet(t, registry, []string{scopeComponentA}, passRuleA),
			input: scopeInput(t, registry, true,
				componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)},
				componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactB, false)}),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			report, err := Evaluate(testCase.input, testCase.rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment != AssessmentUnknown {
				t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
			}
			if report.ScopeCompleteness.Resolved || report.ScopeCompleteness.UnresolvedReason != testCase.want {
				t.Fatalf("scope=%+v", report.ScopeCompleteness)
			}
			if report.Omissions[1] != omissionWholeUpgradeNotChecked {
				t.Fatalf("an unresolved scope claimed a scoped omission: %v", report.Omissions)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Replay(testCase.input, testCase.rules, testNow(t), raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestStaleRuleOutsideTheDeclaredTransitionDoesNotBlockCompleteness pins the
// judgment in ruleApplicability: excluding a rule about a different version
// pair rests on declared versions, not on that rule's evidence being current.
func TestStaleRuleOutsideTheDeclaredTransitionDoesNotBlockCompleteness(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, []string{scopeComponentA},
		scopeRule("rule-a-applicable", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		scopeRule("rule-b-stale-other-pair", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", expiredUntil, ""),
	)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
	}
	skipped := report.ScopeCompleteness.Components[0].NotEvaluated
	if len(skipped) != 1 || skipped[0].Applicability != ApplicabilityNotApplicable {
		t.Fatalf("notEvaluated=%+v", skipped)
	}
}

// TestOutOfScopeRulesAreCountedNotEnumerated keeps rules about components the
// operator does not run out of the per-component enumeration while still
// accounting for every rule in the document.
func TestOutOfScopeRulesAreCountedNotEnumerated(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, []string{scopeComponentA},
		scopeRule("rule-a-applicable", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		scopeRule("rule-b-other-component", "forbid_target_version", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, ""),
	)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentScopeCompletePass || report.ScopeCompleteness.OutOfScopeRules != 1 {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
	}
	if len(report.ScopeCompleteness.Components[0].NotEvaluated) != 0 {
		t.Fatalf("out-of-scope rule leaked into the enumeration: %+v", report.ScopeCompleteness.Components[0])
	}
}

// TestMarshalReportRefusesAnUnsupportedAggregate is the integrity gate. A
// non-UNKNOWN aggregate must be re-derivable from the enumerated evidence.
func TestMarshalReportRefusesAnUnsupportedAggregate(t *testing.T) {
	registry := scopeRegistry(t)
	unscoped := scopeRuleSet(t, registry, nil, scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)))
	passing := scopeRuleSet(t, registry, []string{scopeComponentA},
		scopeRule("rule-a-applicable", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		scopeRule("rule-b-undetermined", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, ""),
	)
	declared := declaredFact(scopeFactA, false)
	cases := map[string]struct {
		rules  RuleSet
		scoped bool
		forge  func(*Report)
	}{
		"no evidence block at all": {rules: unscoped, forge: func(report *Report) {}},
		"evidence block removed after the fact": {rules: passing, scoped: true, forge: func(report *Report) {
			report.ScopeCompleteness = nil
		}},
		"undetermined rule dropped from the enumeration": {rules: passing, scoped: true, forge: func(report *Report) {
			report.ScopeCompleteness.Components[0].NotEvaluated = nil
			report.ScopeCompleteness.Resolved, report.ScopeCompleteness.UnresolvedReason = true, ""
		}},
		"unresolved remainder relabelled as not applicable": {rules: passing, scoped: true, forge: func(report *Report) {
			report.ScopeCompleteness.Components[0].NotEvaluated[0].Applicability = ApplicabilityNotApplicable
			report.ScopeCompleteness.Resolved, report.ScopeCompleteness.UnresolvedReason = true, ""
		}},
		"exclusion reason attached to an unresolved rule": {rules: passing, scoped: true, forge: func(report *Report) {
			report.ScopeCompleteness.Components[0].NotEvaluated[0].ReasonCode = "RULE_TRANSITION_NOT_REVIEWED"
			report.ScopeCompleteness.Resolved, report.ScopeCompleteness.UnresolvedReason = true, ""
		}},
		"contract digest replaced": {rules: passing, scoped: true, forge: func(report *Report) {
			report.ScopeCompleteness.ContractDigest = "sha256:" + strings.Repeat("c", 64)
		}},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			input := scopeInput(t, registry, testCase.scoped, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declared})
			report, err := Evaluate(input, testCase.rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			testCase.forge(&report)
			report.Assessment = AssessmentScopeCompletePass
			report.Omissions = requiredOmissions(AssessmentScopeCompletePass)
			if _, err := MarshalReport(issueReport(report)); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("forged aggregate accepted: %v", err)
			}
		})
	}
}

// TestScopeDeclarationMustMatchTheBundle keeps the declaration falsifiable: a
// caller cannot assert a component set the bundle does not carry.
func TestScopeDeclarationMustMatchTheBundle(t *testing.T) {
	registry := scopeRegistry(t)
	component := `{"component":"` + scopeComponentA + `","version":"1.0.0","facts":[]}`
	proposed := `{"component":"` + scopeComponentA + `","version":"2.0.0","facts":[]}`
	both := `"` + scopeComponentA + `","` + scopeComponentB + `"`
	for name, raw := range map[string]string{
		"scope names a component absent from the bundle": `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `]},"proposed":{"components":[` + proposed + `]},"scope":{"declaration":"` + ScopeDeclaration + `","components":[` + both + `]}}`,
		"bundle carries a component absent from scope":   `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `,{"component":"` + scopeComponentB + `","version":"1.0.0","facts":[]}]},"proposed":{"components":[` + proposed + `,{"component":"` + scopeComponentB + `","version":"2.0.0","facts":[]}]},"scope":{"declaration":"` + ScopeDeclaration + `","components":["` + scopeComponentA + `"]}}`,
		"unknown declaration token":                      `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `]},"proposed":{"components":[` + proposed + `]},"scope":{"declaration":"EVERYTHING_IS_FINE","components":["` + scopeComponentA + `"]}}`,
		"empty declared component set":                   `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `]},"proposed":{"components":[` + proposed + `]},"scope":{"declaration":"` + ScopeDeclaration + `","components":[]}}`,
		"unordered declared component set":               `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `]},"proposed":{"components":[` + proposed + `]},"scope":{"declaration":"` + ScopeDeclaration + `","components":["` + scopeComponentA + `","` + scopeComponentA + `"]}}`,
		"unknown field in the scope block":               `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component + `]},"proposed":{"components":[` + proposed + `]},"scope":{"declaration":"` + ScopeDeclaration + `","components":["` + scopeComponentA + `"],"trustMe":true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

// TestCorpusAttestationCannotBeVacuous closes the "we found no applicable rule
// so everything passes" hole at its source.
func TestCorpusAttestationCannotBeVacuous(t *testing.T) {
	registry := scopeRegistry(t)
	rule := scopeRule("rule-a", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	for name, corpus := range map[string]string{
		"attests a component with no reviewed rule": `"corpus":{"completeness":"` + CorpusAttestation + `","components":["` + scopeComponentA + `","` + scopeComponentB + `"]}`,
		"unknown attestation token":                 `"corpus":{"completeness":"MOSTLY_COMPLETE","components":["` + scopeComponentA + `"]}`,
		"empty attested component set":              `"corpus":{"completeness":"` + CorpusAttestation + `","components":[]}`,
		"unknown field in the corpus block":         `"corpus":{"completeness":"` + CorpusAttestation + `","components":["` + scopeComponentA + `"],"trustMe":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := `{"schema":"` + RulesSchema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + rule + `],` + corpus + `}`
			if _, err := ParseRuleSet([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

// TestDeclaredScopeWithoutAnAttestedCorpusStaysUnknown: one declaration alone
// never establishes an applicable set.
func TestDeclaredScopeWithoutAnAttestedCorpusStaysUnknown(t *testing.T) {
	registry := scopeRegistry(t)
	rules := scopeRuleSet(t, registry, nil, scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)))
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentUnknown || report.ScopeCompleteness != nil {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.ScopeCompleteness)
	}
}

// componentInput is one component of a scoped input: Fact is its proposed
// fact (or empty), CurrentFact its current fact (or empty).
type componentInput struct{ Component, From, To, Fact, CurrentFact string }

func scopeRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := NewRegistry([]FactDefinition{
		{ID: scopeFactA, Component: scopeComponentA, Type: FactBool},
		{ID: scopeFactB, Component: scopeComponentB, Type: FactBool},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func declaredFact(id string, value bool) string {
	return `{"id":"` + id + `","state":"declared","boolValue":` + boolToken(value) + `}`
}

func forbidFact(component, id string) string {
	return `,"condition":{"side":"proposed","component":"` + component + `","factId":"` + id + `","boolValue":true}`
}

func boolToken(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func scopeInput(t *testing.T, registry Registry, withScope bool, components ...componentInput) Input {
	t.Helper()
	current, proposed, names := make([]string, 0, len(components)), make([]string, 0, len(components)), make([]string, 0, len(components))
	for _, component := range components {
		current = append(current, `{"component":"`+component.Component+`","version":"`+component.From+`","facts":[`+component.CurrentFact+`]}`)
		proposed = append(proposed, `{"component":"`+component.Component+`","version":"`+component.To+`","facts":[`+component.Fact+`]}`)
		names = append(names, `"`+component.Component+`"`)
	}
	scope := ""
	if withScope {
		scope = `,"scope":{"declaration":"` + ScopeDeclaration + `","components":[` + strings.Join(names, ",") + `]}`
	}
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + strings.Join(current, ",") + `]},"proposed":{"components":[` + strings.Join(proposed, ",") + `]}` + scope + `}`
	if !json.Valid([]byte(raw)) {
		t.Fatalf("fixture is not valid JSON: %s", raw)
	}
	input, err := ParseInput([]byte(raw), registry)
	if err != nil {
		t.Fatalf("parse input %s: %v", raw, err)
	}
	return input
}

func scopeRule(id, operator, component, from, to, state, validUntil, extra string) string {
	evidence := `"evidence":{"state":"` + state + `","reviewedAt":"2026-01-01T00:00:00Z","validUntil":"` + validUntil + `","sources":[{"id":"upstream-doc","url":"https://github.com/example/controller/blob/` + testRevision + `/docs/upgrade.md","revision":"` + testRevision + `","contentDigest":"` + testDigest + `","startLine":10,"endLine":12}]}`
	return `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"` + component + `","from":"` + from + `","to":"` + to + `"}` + extra + `,` + evidence + `,"reasonCode":"FEATURE_REMOVED","nextAction":"remove the reviewed feature before upgrade"}`
}

func scopeRuleSet(t *testing.T, registry Registry, corpus []string, rules ...string) RuleSet {
	t.Helper()
	attestation := ""
	if len(corpus) > 0 {
		quoted := make([]string, 0, len(corpus))
		for _, component := range corpus {
			quoted = append(quoted, `"`+component+`"`)
		}
		attestation = `,"corpus":{"completeness":"` + CorpusAttestation + `","components":[` + strings.Join(quoted, ",") + `]}`
	}
	raw := `{"schema":"` + RulesSchema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + strings.Join(rules, ",") + `]` + attestation + `}`
	if !json.Valid([]byte(raw)) {
		t.Fatalf("fixture is not valid JSON: %s", raw)
	}
	parsed, err := ParseRuleSet([]byte(raw), registry)
	if err != nil {
		t.Fatalf("parse rules %s: %v", raw, err)
	}
	return parsed
}
