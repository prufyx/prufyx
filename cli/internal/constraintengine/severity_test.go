// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	supportRangeReason = "ADDON_KUBERNETES_SUPPORT_RANGE"
	supportRangeAction = "upgrade the add-on to a release line whose documented support range includes the target"

	pinnedEngineContractDigestBasis    = "sha256:b2bc43865925103acf09920828dd893f8ba95c3cfd3044dbb77a80152c1b31b2"
	pinnedScopeContractDigestBasis     = "sha256:e4550f0c5c1ad51a1fca120d7a36b0d0f9c0a3994412597a1b0d7d92c06b2115"
	pinnedEngineContractDigestSeverity = "sha256:3b8146f6998a99e4e7deef93d892b489d1b1b9f3df8de6b37895e77c5379e6be"
	pinnedScopeContractDigestSeverity  = "sha256:c21d15e38ae7cb7e07faa85f132d1baa5e3d073aa33d01b4e382112a75c75503"
)

// dependencyOn renders a require_component_version dependency.
func dependencyOn(component, comparison, version string) string {
	return `,"dependency":{"side":"proposed","component":"` + component + `","comparison":"` + comparison + `","version":"` + version + `"}`
}

// withSeverity declares a severity on a rendered rule and gives it the
// support-range reason and next action.
func withSeverity(raw, severity string) string {
	raw = strings.Replace(raw, `"evidence":{`, `"severity":"`+severity+`","evidence":{`, 1)
	raw = strings.Replace(raw, `"reasonCode":"FEATURE_REMOVED"`, `"reasonCode":"`+supportRangeReason+`"`, 1)
	return strings.Replace(raw, `"nextAction":"remove the reviewed feature before upgrade"`, `"nextAction":"`+supportRangeAction+`"`, 1)
}

// supportRule is a support-range rule on component A that requires
// component B at or above 2.0.0.
func supportRule(id, state, validUntil, extra string) string {
	return withSeverity(scopeRule(id, "require_component_version", scopeComponentA, "1.0.0", "2.0.0", state, validUntil, dependencyOn(scopeComponentB, "gte", "2.0.0")+extra), SeverityUnsupported)
}

func parseSeverity(t *testing.T, corpus []string, rules ...string) RuleSet {
	t.Helper()
	parsed, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaSeverity, corpus, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse severity rules: %v", err)
	}
	return parsed
}

func TestSeverityStructure(t *testing.T) {
	registry := scopeRegistry(t)
	support := supportRule("rule-a-support", "active", activeUntil, "")
	blocking := scopeRule("rule-a-blocking", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "2.0.0"))
	notice := noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	consensus := withBasis(scopeRule("rule-b-consensus", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, ""), BasisConsensus)
	rangedSpec := defaultRangeSpec()
	rangedSpec.id = "rule-ranged"
	ranged := rangedSpec.ruleJSON()
	rangedSupportSpec := defaultRangeSpec()
	rangedSupportSpec.id, rangedSupportSpec.operator, rangedSupportSpec.extra = "rule-ranged-support", "require_component_version", dependencyOn(scopeComponentB, "gte", "2.0.0")
	rangedSupport := withSeverity(rangedSupportSpec.ruleJSON(), SeverityUnsupported)
	accepted := map[string][]string{
		"support-range rule":              {support},
		"beside a blocking rule":          {blocking, support},
		"beside notice and consensus":     {notice, support, consensus},
		"empirical support-range rule":    {withBasis(support, BasisEmpirical)},
		"ranged support-range rule":       {rangedSupport},
		"support-range rule beside range": {ranged, support},
	}
	for name, rules := range accepted {
		sort.Slice(rules, func(i, j int) bool { return ruleIDOf(rules[i]) < ruleIDOf(rules[j]) })
		parsed, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaSeverity, nil, rules...), registry)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if parsed.engineDigest() != EngineContractDigestSeverity() {
			t.Fatalf("%s: contract %s", name, parsed.engineDigest())
		}
		raws := make([]json.RawMessage, 0, len(rules))
		for _, rule := range rules {
			raws = append(raws, json.RawMessage(rule))
		}
		if schema, err := RulesSchemaFor(raws); err != nil || schema != RulesSchemaSeverity {
			t.Fatalf("%s: RulesSchemaFor=%s err=%v", name, schema, err)
		}
	}
	// A document without a severity keeps its schema and contract.
	if parsed, err := ParseRuleSet(ruleDocumentJSON(RulesSchema, nil, blocking), registry); err != nil || parsed.engineDigest() != EngineContractDigest() {
		t.Fatalf("blocking rule alone: %v", err)
	}
	if schema, _ := RulesSchemaFor([]json.RawMessage{json.RawMessage(blocking)}); schema != RulesSchema {
		t.Fatalf("blocking rule schema %s", schema)
	}
	onOperator := func(operator, extra string) string {
		return withSeverity(scopeRule("rule-a-other", operator, scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, extra), SeverityUnsupported)
	}
	withReason := func(reason string) string {
		return strings.Replace(support, `"reasonCode":"`+supportRangeReason+`"`, `"reasonCode":"`+reason+`"`, 1)
	}
	rejected := map[string][]byte{
		"under the basis schema":            ruleDocumentJSON(RulesSchemaBasis, nil, support),
		"under the notice schema":           ruleDocumentJSON(RulesSchemaNotice, nil, notice, support),
		"under the set schema":              ruleDocumentJSON(RulesSchemaSet, nil, support),
		"under the ranged schema":           ruleDocumentJSON(RulesSchemaRanged, nil, ranged, support),
		"under the exact schema":            ruleDocumentJSON(RulesSchema, nil, support),
		"severity schema without severity":  ruleDocumentJSON(RulesSchemaSeverity, nil, blocking),
		"unknown schema level":              ruleDocumentJSON("prufyx.io/deterministic-constraint-rules/v1alpha7", nil, support),
		"other severity value":              ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":"blocking"`, 1)),
		"severity in another case":          ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":"Unsupported"`, 1)),
		"empty severity":                    ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":""`, 1)),
		"empty severity, exact schema":      ruleDocumentJSON(RulesSchema, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":""`, 1)),
		"numeric severity":                  ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":1`, 1)),
		"null severity":                     ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":null`, 1)),
		"severity key alias":                ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"Severity":"unsupported"`, 1)),
		"duplicate severity key":            ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(support, `"severity":"unsupported"`, `"severity":"unsupported","severity":"unsupported"`, 1)),
		"on forbid_predicate_value":         ruleDocumentJSON(RulesSchemaSeverity, nil, onOperator("forbid_predicate_value", forbidFact(scopeComponentA, scopeFactA))),
		"on forbid_target_version":          ruleDocumentJSON(RulesSchemaSeverity, nil, onOperator("forbid_target_version", "")),
		"on require_intermediate_version":   ruleDocumentJSON(RulesSchemaSeverity, nil, onOperator("require_intermediate_version", `,"intermediate":"1.5.0"`)),
		"on a one-way notice":               ruleDocumentJSON(RulesSchemaSeverity, nil, strings.Replace(notice, `"evidence":{`, `"severity":"unsupported","evidence":{`, 1)),
		"on a lead":                         ruleDocumentJSON(RulesSchemaSeverity, nil, withBasis(support, BasisLead)),
		"on a consensus rule":               ruleDocumentJSON(RulesSchemaSeverity, nil, withBasis(support, BasisConsensus)),
		"engine reason RULE_":               ruleDocumentJSON(RulesSchemaSeverity, nil, withReason("RULE_DEPENDENCY_COMPONENT_MISSING")),
		"exclusion reason":                  ruleDocumentJSON(RulesSchemaSeverity, nil, withReason("RULE_TRANSITION_NOT_REVIEWED")),
		"unresolved reason":                 ruleDocumentJSON(RulesSchemaSeverity, nil, withReason(UnresolvedUnsupportedCombination)),
		"consensus reason":                  ruleDocumentJSON(RulesSchemaSeverity, nil, withReason(ReasonConsensusNoKnownIssue)),
		"one-way reason":                    ruleDocumentJSON(RulesSchemaSeverity, nil, withReason(ReasonOneWayTransition)),
		"malformed reason":                  ruleDocumentJSON(RulesSchemaSeverity, nil, withReason("addon_range")),
		"support-range rule without a dep.": ruleDocumentJSON(RulesSchemaSeverity, nil, withSeverity(scopeRule("rule-a-nodep", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), SeverityUnsupported)),
	}
	for name, raw := range rejected {
		if _, err := ParseRuleSet(raw, registry); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := RulesSchemaFor([]json.RawMessage{json.RawMessage(`[`)}); err == nil {
		t.Fatal("malformed raw rule accepted by RulesSchemaFor")
	}
}

func supportInput(t *testing.T, withScope bool, dependencyVersion string) Input {
	t.Helper()
	components := []componentInput{{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}}
	if dependencyVersion != "" {
		components = append(components, componentInput{Component: scopeComponentB, From: "1.0.0", To: dependencyVersion, Fact: declaredFact(scopeFactB, false)})
	}
	return scopeInput(t, scopeRegistry(t), withScope, components...)
}

// evaluateSealed evaluates, marshals and replays one report.
func evaluateSealed(t *testing.T, input Input, rules RuleSet) Report {
	t.Helper()
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatalf("report refused: %v %+v", err, report)
	}
	if _, err := Replay(input, rules, testNow(t), raw); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return report
}

func TestSeverityEvaluation(t *testing.T) {
	support := parseSeverity(t, nil, supportRule("rule-a-support", "active", activeUntil, ""))
	for _, tc := range []struct {
		name, dependency, status, reason string
	}{
		{"outside the documented range", "1.5.0", StatusUnsupported, supportRangeReason},
		{"inside the documented range", "2.0.0", "PASS", supportRangeReason},
		{"above the bound", "3.0.0", "PASS", supportRangeReason},
		{"dependency missing", "", "UNKNOWN", "RULE_DEPENDENCY_COMPONENT_MISSING"},
	} {
		report := evaluateSealed(t, supportInput(t, false, tc.dependency), support)
		claim := report.Claims[0]
		if claim.Status != tc.status || claim.ReasonCode != tc.reason || claim.Severity != SeverityUnsupported || report.Assessment != AssessmentUnknown {
			t.Fatalf("%s: %+v", tc.name, claim)
		}
		if tc.status == StatusUnsupported && (claim.NextAction != supportRangeAction || !claim.IsUnsupported()) {
			t.Fatalf("%s: next action %q", tc.name, claim.NextAction)
		}
	}
	// The same rule without the severity blocks: the field never changes a
	// rule that lacks it.
	blocking := scopeRuleSet(t, scopeRegistry(t), nil, scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "2.0.0")))
	if claim := evaluateSealed(t, supportInput(t, false, "1.5.0"), blocking).Claims[0]; claim.Status != "BLOCKED" || claim.Severity != "" {
		t.Fatalf("blocking rule: %+v", claim)
	}
	paths := map[string]struct {
		rule, reason string
	}{
		"stale":                     {supportRule("rule-a-support", "active", expiredUntil, ""), "RULE_EVIDENCE_STALE"},
		"withdrawn":                 {supportRule("rule-a-support", "withdrawn", activeUntil, ""), "RULE_EVIDENCE_WITHDRAWN"},
		"applicability not matched": {supportRule("rule-a-support", "active", activeUntil, appliesWhenA(true)), "RULE_APPLICABILITY_NOT_MATCHED"},
		"other transition":          {withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "2.0.0")), SeverityUnsupported), "RULE_TRANSITION_NOT_REVIEWED"},
	}
	for name, tc := range paths {
		claim := evaluateSealed(t, supportInput(t, false, "1.5.0"), parseSeverity(t, nil, tc.rule)).Claims[0]
		if claim.Status != "UNKNOWN" || claim.ReasonCode != tc.reason || claim.Severity != SeverityUnsupported {
			t.Fatalf("%s: %+v", name, claim)
		}
	}
	// Through a range the claim discloses the range like every other.
	spec := defaultRangeSpec()
	spec.id, spec.operator, spec.extra = "rule-ranged-support", "require_component_version", dependencyOn(scopeComponentB, "gte", "2.0.0")
	rangedRules := parseSeverity(t, nil, withSeverity(spec.ruleJSON(), SeverityUnsupported))
	rangedInput := scopeInput(t, scopeRegistry(t), false,
		componentInput{Component: scopeComponentA, From: "1.24.5", To: "1.25.3"},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: "1.5.0"})
	claim := evaluateSealed(t, rangedInput, rangedRules).Claims[0]
	if claim.Status != StatusUnsupported || claim.SubjectMatch == nil {
		t.Fatalf("ranged: %+v", claim)
	}
	// A document without a severity keeps its report bytes: the claim has
	// no severity key.
	raw, _ := MarshalReport(evaluateSealed(t, supportInput(t, false, "1.5.0"), blocking))
	if strings.Contains(string(raw), `"severity"`) {
		t.Fatal("severity key in a report without a severity rule")
	}
}

// supportScope is a scoped document over A and B: a PASS rule on each, a
// support-range rule on A, and optionally more rules.
func supportScope(t *testing.T, extra ...string) RuleSet {
	t.Helper()
	rules := append([]string{
		scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		supportRule("rule-a-support", "active", activeUntil, ""),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB)),
	}, extra...)
	sort.Slice(rules, func(i, j int) bool { return ruleIDOf(rules[i]) < ruleIDOf(rules[j]) })
	return parseSeverity(t, []string{scopeComponentA, scopeComponentB}, rules...)
}

func scopedSupportInput(t *testing.T, dependency string, blockA bool) Input {
	t.Helper()
	return scopeInput(t, scopeRegistry(t), true,
		componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, blockA)},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: dependency, Fact: declaredFact(scopeFactB, false)})
}

func TestUnsupportedAggregate(t *testing.T) {
	// Control: inside the range everything passes.
	if report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), supportScope(t)); report.Assessment != AssessmentScopeCompletePass {
		t.Fatalf("control: %s", report.Assessment)
	}
	// All PASS and one UNSUPPORTED: UNKNOWN, never a pass and never BLOCKED.
	// (B's own transition 1.0.0 -> 1.5.0 is not reviewed by rule-b-pass, so
	// give B the reviewed pair and move the dependency through A's rule.)
	rules := parseSeverity(t, []string{scopeComponentA, scopeComponentB},
		scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB)))
	report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), rules)
	scope := report.ScopeCompleteness
	if report.Assessment != AssessmentUnknown || scope == nil || scope.Resolved || scope.UnresolvedReason != UnresolvedUnsupportedCombination {
		t.Fatalf("PASS + UNSUPPORTED: %s %+v", report.Assessment, scope)
	}
	want := []NotEvaluatedRule{{RuleID: "rule-a-support", Applicability: ApplicabilityApplicable, ReasonCode: supportRangeReason}}
	if !reflect.DeepEqual(scope.Components[0].NotEvaluated, want) || !reflect.DeepEqual(scope.Components[0].EvaluatedRuleIDs, []string{"rule-a-pass"}) || scope.ContractDigest != ScopeContractDigestSeverity() {
		t.Fatalf("enumeration: %+v", scope.Components[0])
	}
	// BLOCKED beside UNSUPPORTED stays BLOCKED.
	blocked := evaluateSealed(t, scopedSupportInput(t, "2.0.0", true), rules)
	if blocked.Assessment != AssessmentBlocked {
		t.Fatalf("BLOCKED + UNSUPPORTED: %s", blocked.Assessment)
	}
	// Only UNSUPPORTED claims: never BLOCKED.
	only := parseSeverity(t, []string{scopeComponentA}, withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported))
	onlyInput := scopeInput(t, scopeRegistry(t), true,
		componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0"},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0"})
	if report := evaluateSealed(t, onlyInput, only); report.Assessment != AssessmentUnknown {
		t.Fatalf("only UNSUPPORTED: %s", report.Assessment)
	}
	// The unsupported reason outranks an undetermined rule, and stays below
	// an unattested component.
	undetermined := parseSeverity(t, []string{scopeComponentA, scopeComponentB},
		scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", expiredUntil, forbidFact(scopeComponentB, scopeFactB)))
	if report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), undetermined); report.ScopeCompleteness.UnresolvedReason != UnresolvedUnsupportedCombination {
		t.Fatalf("precedence over undetermined: %+v", report.ScopeCompleteness)
	}
	unattested := parseSeverity(t, []string{scopeComponentA},
		scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB)))
	if report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), unattested); report.ScopeCompleteness.UnresolvedReason != unresolvedComponentNotAttested {
		t.Fatalf("unattested first: %+v", report.ScopeCompleteness)
	}
	// Consensus no-issue and unsupported together: unsupported is named.
	both := parseSeverity(t, []string{scopeComponentA, scopeComponentB},
		withBasis(scopeRule("rule-a-consensus", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)), BasisConsensus),
		withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB)))
	if report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), both); report.Assessment != AssessmentUnknown || report.ScopeCompleteness.UnresolvedReason != UnresolvedUnsupportedCombination {
		t.Fatalf("consensus + unsupported: %s %+v", report.Assessment, report.ScopeCompleteness)
	}
}

// TestSeverityProperty: for random rule documents, adding severity to
// require_component_version rules changes a claim only from BLOCKED to
// UNSUPPORTED, so removing it can only turn UNSUPPORTED into BLOCKED; no
// claim and no aggregate becomes PASS by adding it, and a scope-complete
// pass holds with the severity exactly when it holds without it.
func TestSeverityProperty(t *testing.T) {
	registry := scopeRegistry(t)
	random := rand.New(rand.NewSource(20261006))
	components := []string{scopeComponentA, scopeComponentB}
	facts := map[string]string{scopeComponentA: scopeFactA, scopeComponentB: scopeFactB}
	pick := func(values ...string) string { return values[random.Intn(len(values))] }
	schemaOf := func(rules []string) string {
		raws := make([]json.RawMessage, 0, len(rules))
		for _, rule := range rules {
			raws = append(raws, json.RawMessage(rule))
		}
		schema, err := RulesSchemaFor(raws)
		if err != nil {
			t.Fatal(err)
		}
		return schema
	}
	cases, tally, claimTally := 0, map[string]int{}, map[string]int{}
	for iteration := 0; cases < 2000; iteration++ {
		if iteration > 40000 {
			t.Fatalf("only %d usable cases", cases)
		}
		var base, with []string
		severities := 0
		for index := 0; index < 1+random.Intn(5); index++ {
			component := pick(components...)
			state, until := pick("active", "active", "active", "withdrawn"), pick(activeUntil, activeUntil, activeUntil, expiredUntil)
			id := fmt.Sprintf("rule-%02d", index)
			to := pick("2.0.0", "2.0.0", "3.0.0")
			extra := ""
			if random.Intn(4) == 0 {
				extra = `,"appliesWhen":[{"side":"proposed","component":"` + component + `","factId":"` + facts[component] + `","boolValue":` + boolToken(random.Intn(2) == 0) + `}]`
			}
			var rule string
			dependencyRule := false
			switch operator := random.Intn(10); {
			case operator < 3:
				rule = scopeRule(id, "forbid_predicate_value", component, "1.0.0", to, state, until, forbidFact(component, facts[component])+extra)
			case operator < 4:
				rule = scopeRule(id, "forbid_target_version", component, "1.0.0", to, state, until, extra)
			default:
				dependencyRule = true
				rule = scopeRule(id, "require_component_version", component, "1.0.0", to, state, until, dependencyOn(pick(components...), pick("gte", "lt", "eq", "lte"), pick("2.0.0", "3.0.0"))+extra)
			}
			consensus := random.Intn(5) == 0
			if consensus {
				rule = withBasis(rule, BasisConsensus)
			}
			base = append(base, rule)
			// A consensus rule cannot carry a severity.
			if dependencyRule && !consensus && random.Intn(3) != 0 {
				severities++
				rule = strings.Replace(rule, `"evidence":{`, `"severity":"unsupported","evidence":{`, 1)
			}
			with = append(with, rule)
		}
		if severities == 0 {
			continue
		}
		subjects := map[string]bool{}
		for _, raw := range base {
			subjects[subjectOf(raw)] = true
		}
		var corpus []string
		for _, component := range components {
			if subjects[component] && random.Intn(5) != 0 {
				corpus = append(corpus, component)
			}
		}
		var inputs []componentInput
		for _, component := range components {
			fact := ""
			switch random.Intn(4) {
			case 0:
				fact = declaredFact(facts[component], true)
			case 1, 2:
				fact = declaredFact(facts[component], false)
			}
			inputs = append(inputs, componentInput{Component: component, From: "1.0.0", To: pick("2.0.0", "2.0.0", "3.0.0"), Fact: fact})
		}
		if random.Intn(3) == 0 {
			random.Int31() // keeps the seeded stream identical to the former Intn(1) draw
			inputs = inputs[:1]
		}
		baseRules, err := ParseRuleSet(ruleDocumentJSON(schemaOf(base), corpus, base...), registry)
		if err != nil {
			continue // a random document the parser refuses proves nothing
		}
		withRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaSeverity, corpus, with...), registry)
		if err != nil {
			t.Fatalf("severity document refused although its base parsed: %v", err)
		}
		input := scopeInput(t, registry, random.Intn(4) != 0, inputs...)
		baseReport := evaluateSealedProperty(t, input, baseRules)
		withReport := evaluateSealedProperty(t, input, withRules)
		for index, w := range withReport.Claims {
			b := baseReport.Claims[index]
			switch {
			case w.Status == b.Status:
			case b.Status == "BLOCKED" && w.Status == StatusUnsupported && w.Severity == SeverityUnsupported:
			default:
				t.Fatalf("case %d: claim %s %s became %s", cases, b.RuleID, b.Status, w.Status)
			}
			if w.Status == "PASS" && b.Status != "PASS" || w.Status == StatusUnsupported && b.Status != "BLOCKED" {
				t.Fatalf("case %d: claim %s", cases, w.RuleID)
			}
			claimTally[b.Status+"->"+w.Status]++
		}
		if (withReport.Assessment == AssessmentScopeCompletePass) != (baseReport.Assessment == AssessmentScopeCompletePass) {
			t.Fatalf("case %d: scope-complete pass %s -> %s", cases, baseReport.Assessment, withReport.Assessment)
		}
		if withReport.Assessment == AssessmentBlocked && baseReport.Assessment != AssessmentBlocked {
			t.Fatalf("case %d: BLOCKED created", cases)
		}
		if withReport.ScopeCompleteness != nil && withReport.ScopeCompleteness.UnresolvedReason == UnresolvedUnsupportedCombination {
			tally["unresolved:"+UnresolvedUnsupportedCombination]++
		}
		tally[baseReport.Assessment+"->"+withReport.Assessment]++
		cases++
	}
	t.Logf("aggregates over %d cases: %v; claims: %v", cases, tally, claimTally)
	for _, key := range []string{"BLOCKED->UNKNOWN", "SCOPE_COMPLETE_PASS->SCOPE_COMPLETE_PASS", "BLOCKED->BLOCKED", "unresolved:" + UnresolvedUnsupportedCombination} {
		if tally[key] == 0 {
			t.Fatalf("no case reached %s: %v", key, tally)
		}
	}
	if claimTally["BLOCKED->"+StatusUnsupported] == 0 || claimTally["PASS->PASS"] == 0 {
		t.Fatalf("claim tally %v", claimTally)
	}
}

func evaluateSealedProperty(t *testing.T, input Input, rules RuleSet) Report {
	t.Helper()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	report, err := Evaluate(input, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("report refused: %+v", report)
	}
	return report
}

func TestUnsupportedIntegrity(t *testing.T) {
	rules := parseSeverity(t, []string{scopeComponentA, scopeComponentB},
		scopeRule("rule-a-blocking", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "1.0.0")),
		scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)),
		withSeverity(scopeRule("rule-a-support", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "3.0.0")), SeverityUnsupported),
		scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB)))
	report := evaluateSealed(t, scopedSupportInput(t, "2.0.0", false), rules)
	if report.Claims[0].Status != "PASS" || report.Claims[2].Status != StatusUnsupported || report.Assessment != AssessmentUnknown {
		t.Fatalf("baseline: %+v", report)
	}
	clone := func(source Report) Report {
		raw, _ := json.Marshal(source)
		var copied Report
		_ = json.Unmarshal(raw, &copied)
		return copied
	}
	toPass := func(r *Report) {
		r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
		r.Assessment, r.Omissions = AssessmentScopeCompletePass, requiredOmissions(AssessmentScopeCompletePass)
	}
	forgeries := map[string]func(*Report){
		"severity disclosure removed": func(r *Report) { r.Claims[2].Severity = "" },
		"UNSUPPORTED from a rule without severity": func(r *Report) {
			r.Claims[0].Status, r.Claims[0].ReasonCode = StatusUnsupported, supportRangeReason
		},
		"severity claim BLOCKED":       func(r *Report) { r.Claims[2].Status = "BLOCKED" },
		"severity claim NOTICE":        func(r *Report) { r.Claims[2].Status = StatusNotice },
		"severity on another operator": func(r *Report) { r.Claims[1].Severity = SeverityUnsupported },
		"severity of another value":    func(r *Report) { r.Claims[2].Severity = "blocking" },
		"severity on a lead":           func(r *Report) { r.Claims[2].EvidenceBasis, r.Claims[2].EvidenceDerivedAt = BasisLead, basisDerivedAt },
		"severity on a consensus claim": func(r *Report) {
			r.Claims[2].EvidenceBasis, r.Claims[2].EvidenceDerivedAt = BasisConsensus, basisDerivedAt
		},
		"UNSUPPORTED on stale evidence": func(r *Report) { r.Claims[2].EvidenceFreshness = "stale" },
		"UNSUPPORTED with engine reason": func(r *Report) {
			r.Claims[2].ReasonCode = "RULE_DEPENDENCY_COMPONENT_MISSING"
			r.ScopeCompleteness.Components[0].NotEvaluated[0].ReasonCode = "RULE_DEPENDENCY_COMPONENT_MISSING"
		},
		"UNSUPPORTED counted as verified": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{}
			r.ScopeCompleteness.Components[0].EvaluatedRuleIDs = []string{"rule-a-blocking", "rule-a-pass", "rule-a-support"}
			toPass(r)
		},
		"UNSUPPORTED as not applicable": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated[0] = NotEvaluatedRule{RuleID: "rule-a-support", Applicability: ApplicabilityNotApplicable, ReasonCode: "RULE_TRANSITION_NOT_REVIEWED"}
			toPass(r)
		},
		"UNSUPPORTED as undetermined": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated[0].Applicability = ApplicabilityUndetermined
			r.ScopeCompleteness.UnresolvedReason = unresolvedApplicability
		},
		"UNSUPPORTED entry with another reason": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated[0].ReasonCode = ReasonConsensusNoKnownIssue
		},
		"UNSUPPORTED dropped from scope": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{}
			r.ScopeCompleteness.OutOfScopeRules = 1
			toPass(r)
		},
		"unresolved reason erased":  toPass,
		"unresolved reason renamed": func(r *Report) { r.ScopeCompleteness.UnresolvedReason = unresolvedApplicability },
		"aggregate BLOCKED": func(r *Report) {
			r.Assessment, r.Omissions = AssessmentBlocked, requiredOmissions(AssessmentBlocked)
		},
		"under the basis contract": func(r *Report) {
			r.EngineContractDigest, r.ScopeCompleteness.ContractDigest = EngineContractDigestBasis(), ScopeContractDigestBasis()
		},
		"under the notice contract": func(r *Report) {
			r.EngineContractDigest, r.ScopeCompleteness.ContractDigest = EngineContractDigestNotice(), ScopeContractDigestNotice()
		},
		"under the exact contract": func(r *Report) {
			r.EngineContractDigest, r.ScopeCompleteness.ContractDigest = EngineContractDigest(), ScopeContractDigest()
		},
		"severity scope under the basis engine contract": func(r *Report) { r.EngineContractDigest = EngineContractDigestBasis() },
		"basis scope under the severity engine contract": func(r *Report) { r.ScopeCompleteness.ContractDigest = ScopeContractDigestBasis() },
		"under the basis contract without scope": func(r *Report) {
			r.ScopeCompleteness, r.Assessment, r.Omissions = nil, AssessmentUnknown, requiredOmissions(AssessmentUnknown)
			r.EngineContractDigest = EngineContractDigestBasis()
		},
		"severity disclosure under the basis contract": func(r *Report) {
			r.ScopeCompleteness, r.Assessment, r.Omissions = nil, AssessmentUnknown, requiredOmissions(AssessmentUnknown)
			r.EngineContractDigest = EngineContractDigestBasis()
			r.Claims[2].Status, r.Claims[2].ReasonCode = "UNKNOWN", "RULE_EVIDENCE_STALE"
		},
	}
	for name, forge := range forgeries {
		forged := clone(report)
		forge(&forged)
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("forgery accepted: %s", name)
		}
	}
	if _, err := MarshalReport(reseal(clone(report))); err != nil {
		t.Fatalf("unforged clone refused: %v", err)
	}
	// Relabelling the UNSUPPORTED claim as PASS is the same forgery class as
	// relabelling any BLOCKED claim as PASS: a support-range rule may pass,
	// so the structural gate cannot tell it from an honest report without
	// the rule document. Replay re-evaluates and refuses it.
	relabelled := clone(report)
	relabelled.Claims[2].Status = "PASS"
	relabelled.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{}
	relabelled.ScopeCompleteness.Components[0].EvaluatedRuleIDs = []string{"rule-a-blocking", "rule-a-pass", "rule-a-support"}
	toPass(&relabelled)
	if raw, err := MarshalReport(reseal(relabelled)); err == nil {
		if _, err := Replay(scopedSupportInput(t, "2.0.0", false), rules, testNow(t), raw); err == nil {
			t.Fatal("replay accepted a relabelled UNSUPPORTED claim")
		}
	}
	// Without scope, a severity claim is never BLOCKED.
	plainBlocked := clone(evaluateSealed(t, supportInput(t, false, "1.5.0"), parseSeverity(t, nil, supportRule("rule-a-support", "active", activeUntil, ""))))
	plainBlocked.Claims[0].Status = "BLOCKED"
	if _, err := MarshalReport(reseal(plainBlocked)); err == nil {
		t.Fatal("BLOCKED severity claim accepted without scope")
	}
	// Without scope, an UNSUPPORTED claim is still bound to the contract.
	plain := evaluateSealed(t, supportInput(t, false, "1.5.0"), parseSeverity(t, nil, supportRule("rule-a-support", "active", activeUntil, "")))
	forged := clone(plain)
	forged.EngineContractDigest = EngineContractDigestRanged()
	if _, err := MarshalReport(reseal(forged)); err == nil {
		t.Fatal("UNSUPPORTED under the ranged contract accepted")
	}
}

func TestSeverityContractDigests(t *testing.T) {
	if EngineContractDigestBasis() != pinnedEngineContractDigestBasis || ScopeContractDigestBasis() != pinnedScopeContractDigestBasis {
		t.Fatalf("basis contracts changed: %s %s", EngineContractDigestBasis(), ScopeContractDigestBasis())
	}
	engine, scope := EngineContractDigestSeverity(), ScopeContractDigestSeverity()
	if engine != pinnedEngineContractDigestSeverity || scope != pinnedScopeContractDigestSeverity {
		t.Fatalf("severity contracts changed: %s %s", engine, scope)
	}
	for _, existing := range []string{pinnedEngineContractDigest, pinnedEngineContractDigestRanged, pinnedEngineContractDigestSet, pinnedEngineContractDigestNotice, pinnedEngineContractDigestBasis} {
		if engine == existing {
			t.Fatal("severity contract is not distinct")
		}
	}
	for _, existing := range []string{pinnedScopeContractDigest, pinnedScopeContractDigestRanged, pinnedScopeContractDigestNotice, pinnedScopeContractDigestBasis} {
		if scope == existing {
			t.Fatal("severity scope contract is not distinct")
		}
	}
	if scopeDigestFor(engine) != scope || scopeDigestFor(pinnedEngineContractDigestBasis) != pinnedScopeContractDigestBasis {
		t.Fatal("severity scope contract is not paired")
	}
}

func TestUnsupportedNote(t *testing.T) {
	unsupported := Claim{Status: StatusUnsupported}
	if _, ok := UnsupportedNote([]Claim{{Status: "PASS"}, {Status: "BLOCKED"}, {Status: StatusNoKnownIssue}}); ok {
		t.Fatal("note without UNSUPPORTED")
	}
	one, ok := UnsupportedNote([]Claim{{Status: "PASS"}, unsupported})
	if !ok || one != "1 component combination is outside its documented support range (not verified, not shown to be broken)" {
		t.Fatalf("one: %q", one)
	}
	two, _ := UnsupportedNote([]Claim{unsupported, unsupported})
	if !strings.HasPrefix(two, "2 component combinations are outside their documented support range") {
		t.Fatalf("two: %q", two)
	}
	for _, note := range []string{one, two} {
		lower := strings.ToLower(note)
		if len(note) > maxStringBytes || strings.Contains(lower, "safe") || strings.Contains(lower, "compatible") {
			t.Fatalf("note wording: %q", note)
		}
	}
}
