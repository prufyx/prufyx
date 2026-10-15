// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

const (
	pinnedEngineContractDigestChart = "sha256:f66dca6c7a0bc26f66c19ca68ee6c9ebae5da7a32f2454a5d030c9e0329de095"
	pinnedScopeContractDigestChart  = "sha256:eeba188a872355a112ff8259fa8fedbb79363ecbe310602913d808d5509fee8e"

	chartSource      = "https://charts.example.io"
	chartName        = "controller"
	chartValuesFact  = "component.example.chart_controller_values_paths_set"
	chartTestNowDate = "2026-06-01T00:00:00Z"
)

func chartRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := NewRegistry([]FactDefinition{
		{ID: testFact, Component: testComponent, Type: FactBool},
		{ID: chartValuesFact, Component: testComponent, Type: FactSet},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func chartJSON(source, name string) string {
	return `{"source":"` + source + `","name":"` + name + `"}`
}

// chartInputRaw is one component on both sides, 1.0.0 -> 2.0.0, with an
// optional chart per side, an optional proposed fact and an optional scope.
func chartInputRaw(currentChart, proposedChart, proposedFact string, scope bool) string {
	component := func(version, chart, fact string) string {
		out := `{"component":"` + testComponent + `","version":"` + version + `",`
		if chart != "" {
			out += `"chart":` + chart + `,`
		}
		return out + `"facts":[` + fact + `]}`
	}
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[` + component("1.0.0", currentChart, "") + `]},"proposed":{"components":[` + component("2.0.0", proposedChart, proposedFact) + `]}`
	if scope {
		raw += `,"scope":{"declaration":"` + ScopeDeclaration + `","components":["` + testComponent + `"]}`
	}
	return raw + `}`
}

func chartInput(t *testing.T, registry Registry, chart, fact string, scope bool) Input {
	t.Helper()
	input, err := ParseInput([]byte(chartInputRaw(chart, chart, fact, scope)), registry)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func valuesSetFact(members []string, complete bool) string {
	raw, _ := json.Marshal(members)
	if members == nil {
		raw = []byte("[]")
	}
	return `{"id":"` + chartValuesFact + `","state":"declared","setValue":{"members":` + string(raw) + `,"complete":` + boolToken(complete) + `}}`
}

// chartRuleDocument is one rule under the chart schema; subjectChart is raw
// JSON or "" for an application rule; corpus attests the component.
func chartRuleDocument(t *testing.T, operator, subjectChart, extra string, corpus bool) map[string]any {
	t.Helper()
	document := testRuleDocument(operator, extra)
	document["schema"] = RulesSchemaChart
	rule := document["rules"].([]any)[0].(map[string]any)
	if subjectChart != "" {
		var chart map[string]any
		if err := json.Unmarshal([]byte(subjectChart), &chart); err != nil {
			t.Fatal(err)
		}
		rule["subject"].(map[string]any)["chart"] = chart
	}
	if corpus {
		document["corpus"] = map[string]any{"completeness": CorpusAttestation, "components": []any{testComponent}}
	}
	return document
}

func parseChartRules(t *testing.T, registry Registry, document map[string]any) RuleSet {
	t.Helper()
	raw, _ := json.Marshal(document)
	rules, err := ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func requireConditionJSON(members ...string) string {
	raw, _ := json.Marshal(members)
	return `"setCondition":{"side":"proposed","component":"` + testComponent + `","factId":"` + chartValuesFact + `","members":` + string(raw) + `}`
}

func evaluateAndSeal(t *testing.T, input Input, rules RuleSet) (Report, []byte) {
	t.Helper()
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Replay(input, rules, testNow(t), raw); err != nil {
		t.Fatal(err)
	}
	return report, raw
}

func TestChartContractDigestsArePinnedAndDistinct(t *testing.T) {
	if EngineContractDigestChart() != pinnedEngineContractDigestChart || ScopeContractDigestChart() != pinnedScopeContractDigestChart {
		t.Fatalf("chart contract digests moved: %s %s", EngineContractDigestChart(), ScopeContractDigestChart())
	}
	// Every earlier contract keeps the identity its reports were issued
	// under.
	for got, want := range map[string]string{
		EngineContractDigest(): pinnedEngineContractDigest, ScopeContractDigest(): pinnedScopeContractDigest,
		EngineContractDigestRanged(): pinnedEngineContractDigestRanged, ScopeContractDigestRanged(): pinnedScopeContractDigestRanged,
		EngineContractDigestSet(): pinnedEngineContractDigestSet, EngineContractDigestNotice(): pinnedEngineContractDigestNotice,
		ScopeContractDigestNotice(): pinnedScopeContractDigestNotice, EngineContractDigestBasis(): pinnedEngineContractDigestBasis,
		ScopeContractDigestBasis(): pinnedScopeContractDigestBasis, EngineContractDigestSeverity(): pinnedEngineContractDigestSeverity,
		ScopeContractDigestSeverity(): pinnedScopeContractDigestSeverity, EngineContractDigestCrossing(): pinnedEngineContractDigestCrossing,
		ScopeContractDigestCrossing(): pinnedScopeContractDigestCrossing,
	} {
		if got != want {
			t.Fatalf("an earlier contract digest moved: %s != %s", got, want)
		}
	}
	if scopeDigestFor(EngineContractDigestChart()) != ScopeContractDigestChart() || EngineContractDigestChart() == EngineContractDigestCrossing() {
		t.Fatal("chart contract pairing")
	}
}

func TestRequireSetMemberTruthTable(t *testing.T) {
	registry := chartRegistry(t)
	cases := []struct {
		name, basis, fact, status, reason string
		missing                           []string
	}{
		{"complete with every member passes", "", valuesSetFact([]string{"a.b", "c", "z"}, true), "PASS", "FEATURE_REMOVED", nil},
		{"complete with one absent blocks", "", valuesSetFact([]string{"a.b", "z"}, true), "BLOCKED", "FEATURE_REMOVED", []string{"c"}},
		{"complete empty set blocks with both", "", valuesSetFact(nil, true), "BLOCKED", "FEATURE_REMOVED", []string{"a.b", "c"}},
		{"incomplete with every member is unknown", "", valuesSetFact([]string{"a.b", "c"}, false), "UNKNOWN", reasonSetFactIncomplete, nil},
		{"incomplete with one absent is unknown", "", valuesSetFact([]string{"a.b"}, false), "UNKNOWN", reasonSetFactIncomplete, nil},
		{"missing fact is unknown", "", `{"id":"` + chartValuesFact + `","state":"missing"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"conflicting fact is unknown", "", `{"id":"` + chartValuesFact + `","state":"conflict"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"undeclared fact is unknown", "", "", "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"member match is case sensitive", "", valuesSetFact([]string{"A.B", "c"}, true), "BLOCKED", "FEATURE_REMOVED", []string{"a.b"}},
		{"lead that would block is a notice without members", BasisLead, valuesSetFact([]string{"a.b"}, true), StatusNotice, ReasonLeadNotVerified, nil},
		{"consensus that would pass finds no known issue", BasisConsensus, valuesSetFact([]string{"a.b", "c"}, true), StatusNoKnownIssue, ReasonConsensusNoKnownIssue, nil},
		{"consensus that would block blocks", BasisConsensus, valuesSetFact([]string{"c"}, true), "BLOCKED", "FEATURE_REMOVED", []string{"a.b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a.b", "c"), false)
			if tc.basis != "" {
				evidence := document["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
				evidence["basis"], evidence["derivedAt"] = tc.basis, "2026-01-01T00:00:00Z"
			}
			rules := parseChartRules(t, registry, document)
			report, raw := evaluateAndSeal(t, chartInput(t, registry, chartJSON(chartSource, chartName), tc.fact, false), rules)
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || strings.Join(claim.MissingMembers, ",") != strings.Join(tc.missing, ",") || (tc.missing == nil) != (claim.MissingMembers == nil) || claim.MatchedMembers != nil {
				t.Fatalf("claim=%+v", claim)
			}
			if report.EngineContractDigest != EngineContractDigestChart() || report.Assessment != AssessmentUnknown {
				t.Fatalf("report=%+v", report)
			}
			if tc.missing == nil && strings.Contains(string(raw), "missingMembers") {
				t.Fatalf("missing members on a claim that is not BLOCKED: %s", raw)
			}
			if strings.Contains(string(raw), `"z"`) {
				t.Fatalf("report disclosed a declared member the rule does not name: %s", raw)
			}
			line, ok := claim.MissingMembersLine()
			if ok != (tc.missing != nil) || ok && line != "required members absent: "+strings.Join(tc.missing, ", ") {
				t.Fatalf("line %q %v", line, ok)
			}
		})
	}
}

func TestChartRuleNeverDecidesAnApplicationHop(t *testing.T) {
	registry := chartRegistry(t)
	// Same numbers as the rule's anchor, but the input declares no chart,
	// or another chart.
	for name, inputChart := range map[string]string{
		"application version": "",
		"other chart name":    chartJSON(chartSource, "other"),
		"other chart source":  chartJSON("oci://registry.example.io/charts", chartName),
	} {
		t.Run(name, func(t *testing.T) {
			rules := parseChartRules(t, registry, chartRuleDocument(t, "forbid_target_version", chartJSON(chartSource, chartName), "", true))
			report, _ := evaluateAndSeal(t, chartInput(t, registry, inputChart, "", true), rules)
			claim := report.Claims[0]
			if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonSubjectChartNotDeclared {
				t.Fatalf("claim=%+v", claim)
			}
			scope := report.ScopeCompleteness
			if scope == nil || len(scope.Components[0].NotEvaluated) != 1 || scope.Components[0].NotEvaluated[0].Applicability != ApplicabilityNotApplicable || len(scope.Components[0].EvaluatedRuleIDs) != 0 {
				t.Fatalf("scope=%+v", scope)
			}
			// Nothing was evaluated, so the aggregate cannot pass.
			if report.Assessment != AssessmentUnknown || scope.UnresolvedReason != unresolvedNoApplicableRule {
				t.Fatalf("assessment %s %s", report.Assessment, scope.UnresolvedReason)
			}
		})
	}
	// The same chart decides it.
	rules := parseChartRules(t, registry, chartRuleDocument(t, "forbid_target_version", chartJSON(chartSource, chartName), "", true))
	report, _ := evaluateAndSeal(t, chartInput(t, registry, chartJSON(chartSource, chartName), "", true), rules)
	if report.Claims[0].Status != "BLOCKED" || report.Assessment != AssessmentBlocked || report.ScopeCompleteness.Components[0].Chart == nil || *report.ScopeCompleteness.Components[0].Chart != (ChartRef{Source: chartSource, Name: chartName}) {
		t.Fatalf("report=%+v", report)
	}
}

func TestApplicationRuleNeverDecidesAChartHop(t *testing.T) {
	registry := chartRegistry(t)
	// An application rule in a chart document (so the chart contract is
	// in force), anchored on the same numbers the chart hop declares.
	application := testRuleDocument("forbid_target_version", "")["rules"].([]any)[0].(map[string]any)
	application["id"] = "app-rule"
	document := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), true)
	chartRule := document["rules"].([]any)[0].(map[string]any)
	chartRule["id"] = "chart-rule"
	document["rules"] = []any{application, chartRule}
	rules := parseChartRules(t, registry, document)
	report, _ := evaluateAndSeal(t, chartInput(t, registry, chartJSON(chartSource, chartName), valuesSetFact([]string{"a"}, true), true), rules)
	statuses := map[string]Claim{}
	for _, claim := range report.Claims {
		statuses[claim.RuleID] = claim
	}
	if c := statuses["app-rule"]; c.Status != "UNKNOWN" || c.ReasonCode != ReasonAppVersionNotDeclared {
		t.Fatalf("application claim=%+v", c)
	}
	if c := statuses["chart-rule"]; c.Status != "PASS" {
		t.Fatalf("chart claim=%+v", c)
	}
	// The application rule is undetermined, never excluded: no complete
	// pass over a chart hop that leaves an application rule unread.
	scope := report.ScopeCompleteness
	if report.Assessment != AssessmentUnknown || scope.UnresolvedReason != unresolvedApplicability {
		t.Fatalf("assessment %s %+v", report.Assessment, scope)
	}
	found := false
	for _, skipped := range scope.Components[0].NotEvaluated {
		if skipped.RuleID == "app-rule" {
			found = skipped.Applicability == ApplicabilityUndetermined && skipped.ReasonCode == ReasonAppVersionNotDeclared
		}
	}
	if !found {
		t.Fatalf("scope=%+v", scope)
	}
}

func TestDependencyOnAChartHopIsUnknown(t *testing.T) {
	registry := chartRegistry(t)
	dependency := `"dependency":{"side":"proposed","component":"` + testComponent + `","comparison":"gte","version":"1.0.0"}`
	document := chartRuleDocument(t, "require_component_version", "", dependency, false)
	// A require_set_member rule puts the document under the chart contract.
	extra := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), false)["rules"].([]any)[0].(map[string]any)
	extra["id"] = "zz-chart-rule"
	document["rules"] = append(document["rules"].([]any), extra)
	rules := parseChartRules(t, registry, document)
	// The rule's subject is an application rule, so it is already
	// undetermined on a chart hop; the dependency itself never reads a
	// chart version either.
	report, _ := evaluateAndSeal(t, chartInput(t, registry, chartJSON(chartSource, chartName), "", false), rules)
	if c := report.Claims[0]; c.Status != "UNKNOWN" || c.ReasonCode != ReasonAppVersionNotDeclared {
		t.Fatalf("claim=%+v", c)
	}
	input := inputDocument{Current: inputSide{Components: []inputComponent{{Component: testComponent, Version: "1.0.0", Chart: &ChartRef{Source: chartSource, Name: chartName}}}}, Proposed: inputSide{Components: []inputComponent{{Component: testComponent, Version: "9.0.0", Chart: &ChartRef{Source: chartSource, Name: chartName}}}}}
	rule := rules.document.Rules[0]
	claim := evaluateMatchedRule(input, rule, Claim{RuleID: rule.ID})
	if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonAppVersionNotDeclared {
		t.Fatalf("dependency claim=%+v", claim)
	}
}

func TestChartInputValidation(t *testing.T) {
	registry := chartRegistry(t)
	good := chartJSON(chartSource, chartName)
	for name, raw := range map[string]string{
		"chart on the current side only":  chartInputRaw(good, "", "", false),
		"chart on the proposed side only": chartInputRaw("", good, "", false),
		"different chart names":           chartInputRaw(good, chartJSON(chartSource, "other"), "", false),
		"upper-case host":                 chartInputRaw(chartJSON("https://Charts.example.io", chartName), chartJSON("https://Charts.example.io", chartName), "", false),
		"trailing slash":                  chartInputRaw(chartJSON(chartSource+"/", chartName), chartJSON(chartSource+"/", chartName), "", false),
		"trailing .git":                   chartInputRaw(chartJSON(chartSource+"/x.git", chartName), chartJSON(chartSource+"/x.git", chartName), "", false),
		"http scheme":                     chartInputRaw(chartJSON("http://charts.example.io", chartName), chartJSON("http://charts.example.io", chartName), "", false),
		"query":                           chartInputRaw(chartJSON(chartSource+"?a=b", chartName), chartJSON(chartSource+"?a=b", chartName), "", false),
		"dot segment":                     chartInputRaw(chartJSON(chartSource+"/a/../b", chartName), chartJSON(chartSource+"/a/../b", chartName), "", false),
		"userinfo":                        chartInputRaw(chartJSON("https://u@charts.example.io", chartName), chartJSON("https://u@charts.example.io", chartName), "", false),
		"bad name":                        chartInputRaw(chartJSON(chartSource, "Controller"), chartJSON(chartSource, "Controller"), "", false),
		"unknown chart key":               chartInputRaw(`{"source":"`+chartSource+`","name":"`+chartName+`","version":"1"}`, `{"source":"`+chartSource+`","name":"`+chartName+`","version":"1"}`, "", false),
		"null chart":                      strings.ReplaceAll(chartInputRaw(good, good, "", false), good, "null"),
		"chart with a distribution":       strings.Replace(chartInputRaw(good, good, "", false), `"chart":`, `"distribution":"upstream","chart":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := ParseInput([]byte(chartInputRaw(chartJSON("oci://registry.example.io:5000/charts/x", chartName), chartJSON("oci://registry.example.io:5000/charts/x", chartName), "", false)), registry); err != nil {
		t.Fatalf("normal oci source refused: %v", err)
	}
	// A chart input is evaluated only under the chart contract.
	input := chartInput(t, registry, good, "", false)
	if _, err := Evaluate(input, testRules(t, registry, "forbid_target_version", ""), testNow(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chart input evaluated under the exact-only contract: %v", err)
	}
	// An input without a chart marshals exactly as before.
	plain := testInput(t, registry, "", "2.0.0")
	raw, _ := json.Marshal(plain.document)
	if strings.Contains(string(raw), "chart") {
		t.Fatalf("plain input carries a chart key: %s", raw)
	}
}

func TestChartRuleStructure(t *testing.T) {
	registry := chartRegistry(t)
	chart := chartJSON(chartSource, chartName)
	rangeJSON := `"range":{"from":{"gte":"1.0.0","lt":"1.1.0"},"to":{"gte":"2.0.0","lt":"2.1.0"},"bounds":[{"bound":"from.gte","basis":"ANCHOR_ONLY","sourceId":"upstream-doc"},{"bound":"from.lt","basis":"UPGRADE_FROM_SERIES","sourceId":"upstream-doc"},{"bound":"to.gte","basis":"TARGET_SERIES","sourceId":"upstream-doc"},{"bound":"to.lt","basis":"TARGET_SERIES","sourceId":"upstream-doc"}]}`
	refused := map[string]map[string]any{
		"chart rule with a range":              chartRuleDocument(t, "forbid_target_version", chart, rangeJSON, false),
		"chart rule requiring its own version": chartRuleDocument(t, "require_component_version", chart, `"dependency":{"side":"proposed","component":"`+testComponent+`","comparison":"gte","version":"1.0.0"}`, false),
		"chart rule with a severity":           chartRuleDocument(t, "require_component_version", chart, `"severity":"unsupported","dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.0.0"}`, false),
		"chart rule with an unnormal source":   chartRuleDocument(t, "forbid_target_version", chartJSON(chartSource+"/", chartName), "", false),
		"chart rule with an extra chart key":   chartRuleDocument(t, "forbid_target_version", `{"source":"`+chartSource+`","name":"`+chartName+`","x":"y"}`, "", false),
		"require without a set condition":      chartRuleDocument(t, OperatorRequireSetMember, chart, "", false),
		"require on a bool fact":               chartRuleDocument(t, OperatorRequireSetMember, chart, `"setCondition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","members":["a"]}`, false),
		"require with unordered members":       chartRuleDocument(t, OperatorRequireSetMember, chart, requireConditionJSON("b", "a"), false),
		"require with a range and no chart":    chartRuleDocument(t, OperatorRequireSetMember, "", requireConditionJSON("a")+","+rangeJSON, false),
		"require with a condition":             chartRuleDocument(t, OperatorRequireSetMember, chart, requireConditionJSON("a")+`,"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","boolValue":true}`, false),
		"rule claiming the chart reason code":  chartRuleDocument(t, "forbid_target_version", chart, `"reasonCode":"`+ReasonSubjectChartNotDeclared+`"`, false),
		"rule claiming the app reason code":    chartRuleDocument(t, "forbid_target_version", "", `"reasonCode":"`+ReasonAppVersionNotDeclared+`"`, false),
	}
	for name, document := range refused {
		t.Run(name, func(t *testing.T) {
			if name == "rule claiming the app reason code" {
				// An application rule alone is not a chart document; the
				// reason is refused under every schema.
				document["schema"] = RulesSchema
			}
			raw, _ := json.Marshal(document)
			if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// Schema must match in both directions.
	chartDocument := chartRuleDocument(t, "forbid_target_version", chart, "", false)
	chartDocument["schema"] = RulesSchemaCrossing
	if raw, _ := json.Marshal(chartDocument); func() error { _, err := ParseRuleSet(raw, registry); return err }() == nil {
		t.Fatal("chart rule under the crossing schema accepted")
	}
	plain := testRuleDocument("forbid_target_version", "")
	plain["schema"] = RulesSchemaChart
	if raw, _ := json.Marshal(plain); func() error { _, err := ParseRuleSet(raw, registry); return err }() == nil {
		t.Fatal("chart schema without a chart rule accepted")
	}
	// The raw-rule counterpart agrees.
	for _, document := range []map[string]any{chartRuleDocument(t, "forbid_target_version", chart, "", false), chartRuleDocument(t, OperatorRequireSetMember, "", requireConditionJSON("a"), false)} {
		raw, _ := json.Marshal(document["rules"].([]any)[0])
		if schema, err := RulesSchemaFor([]json.RawMessage{raw}); err != nil || schema != RulesSchemaChart {
			t.Fatalf("RulesSchemaFor %s %v", schema, err)
		}
	}
	// A rule without a chart marshals and digests exactly as before.
	rules := testRules(t, registry, "forbid_target_version", "")
	raw, _ := json.Marshal(rules.document)
	if strings.Contains(string(raw), "chart") {
		t.Fatalf("plain rule carries a chart key: %s", raw)
	}
}

func TestForbidAndRequireContradictionRefused(t *testing.T) {
	registry := chartRegistry(t)
	chart := chartJSON(chartSource, chartName)
	build := func(forbid, require []string) []byte {
		document := chartRuleDocument(t, OperatorRequireSetMember, chart, requireConditionJSON(require...), false)
		forbidRule := chartRuleDocument(t, OperatorForbidSetMember, chart, requireConditionJSON(forbid...), false)["rules"].([]any)[0].(map[string]any)
		forbidRule["id"] = "forbid-rule"
		document["rules"] = append([]any{document["rules"].([]any)[0]}, forbidRule)
		document["rules"].([]any)[0].(map[string]any)["id"] = "a-require-rule"
		raw, _ := json.Marshal(document)
		return raw
	}
	if _, err := ParseRuleSet(build([]string{"a"}, []string{"a"}), registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("contradiction accepted: %v", err)
	}
	if _, err := ParseRuleSet(build([]string{"a"}, []string{"b"}), registry); err != nil {
		t.Fatalf("disjoint members refused: %v", err)
	}
}

func TestChartClaimsBoundToTheChartContract(t *testing.T) {
	registry := chartRegistry(t)
	rules := parseChartRules(t, registry, chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a", "b"), false))
	input := chartInput(t, registry, chartJSON(chartSource, chartName), valuesSetFact([]string{"a"}, true), false)
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil || report.Claims[0].Status != "BLOCKED" {
		t.Fatalf("%+v %v", report, err)
	}
	forge := func(edit func(*Report)) error {
		forged := report
		forged.Claims = append([]Claim(nil), report.Claims...)
		edit(&forged)
		_, err := MarshalReport(issueReport(forged))
		return err
	}
	for name, edit := range map[string]func(*Report){
		"stripped missing members":     func(r *Report) { r.Claims[0].MissingMembers = nil },
		"unordered missing members":    func(r *Report) { r.Claims[0].MissingMembers = []string{"b", "a"} },
		"missing members on a pass":    func(r *Report) { r.Claims[0].Status = "PASS" },
		"matched members on a require": func(r *Report) { r.Claims[0].MatchedMembers = []string{"b"} },
		"require under crossing":       func(r *Report) { r.EngineContractDigest = EngineContractDigestCrossing() },
		"missing members on another operator": func(r *Report) {
			r.Claims[0].Operator = OperatorForbidSetMember
		},
		"chart reason under crossing": func(r *Report) {
			r.EngineContractDigest = EngineContractDigestCrossing()
			r.Claims[0] = Claim{RuleID: r.Claims[0].RuleID, RuleDigest: r.Claims[0].RuleDigest, Operator: "forbid_target_version", Status: "UNKNOWN", ReasonCode: ReasonSubjectChartNotDeclared, NextAction: "x", EvidenceReviewedAt: r.Claims[0].EvidenceReviewedAt, EvidenceValidUntil: r.Claims[0].EvidenceValidUntil, EvidenceFreshness: "current", RequiredFacts: []RequiredFact{}, Sources: r.Claims[0].Sources}
		},
		"chart reason on a blocked claim": func(r *Report) { r.Claims[0].ReasonCode = ReasonAppVersionNotDeclared },
	} {
		if err := forge(edit); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: sealed: %v", name, err)
		}
	}
	if err := forge(func(*Report) {}); err != nil {
		t.Fatalf("unforged report refused: %v", err)
	}
}

func TestChartScopeBlockBoundToTheChartContract(t *testing.T) {
	registry := chartRegistry(t)
	rules := parseChartRules(t, registry, chartRuleDocument(t, "forbid_target_version", chartJSON(chartSource, chartName), "", true))
	report, err := Evaluate(chartInput(t, registry, "", "", true), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	forged := report
	scope := *report.ScopeCompleteness
	scope.ContractDigest = ScopeContractDigestCrossing()
	forged.ScopeCompleteness, forged.EngineContractDigest = &scope, EngineContractDigestCrossing()
	if _, err := MarshalReport(issueReport(forged)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("chart exclusion sealed under the crossing scope: %v", err)
	}
}

func TestChartSelectionHelpers(t *testing.T) {
	rule := `{"id":"r","operator":"forbid_target_version","subject":{"component":"` + testComponent + `","chart":` + chartJSON(chartSource, chartName) + `,"from":"1.0.0","to":"2.0.0"}}`
	subject, err := RuleTransitionOf([]byte(rule))
	if err != nil || subject.Chart == nil {
		t.Fatalf("%+v %v", subject, err)
	}
	if subject.AdmitsChart(nil) || !subject.AdmitsChart(&ChartRef{Source: chartSource, Name: chartName}) || subject.AdmitsChart(&ChartRef{Source: chartSource, Name: "x"}) {
		t.Fatal("AdmitsChart")
	}
	app, _ := RuleTransitionOf([]byte(`{"subject":{"component":"` + testComponent + `","from":"1.0.0","to":"2.0.0"}}`))
	if !app.AdmitsChart(nil) || app.AdmitsChart(&ChartRef{Source: chartSource, Name: chartName}) {
		t.Fatal("AdmitsChart for an application rule")
	}
	// The constraint key of a chart rule carries the chart; an application
	// rule's key is unchanged.
	chartKey, _ := ConstraintKey([]byte(rule))
	appKey, _ := ConstraintKey([]byte(`{"operator":"forbid_target_version","subject":{"component":"` + testComponent + `","from":"1.0.0","to":"2.0.0"}}`))
	if appKey != "forbid_target_version" || chartKey == appKey || !strings.Contains(chartKey, chartSource) {
		t.Fatalf("keys %q %q", chartKey, appKey)
	}
	if any, err := AnyChartRule([]json.RawMessage{[]byte(rule)}); err != nil || !any {
		t.Fatal("AnyChartRule missed a chart subject")
	}
	if any, err := AnyChartRule([]json.RawMessage{[]byte(`{"operator":"forbid_set_member","subject":{"component":"x"}}`)}); err != nil || any {
		t.Fatal("AnyChartRule flagged a plain set rule")
	}
}

// TestChartApplicabilityAgreesWithClaims mixes chart and application rules
// over chart and application hops at random: the scope partition agrees with
// every claim, every report seals and replays, a chart rule is decided only
// on its own chart, and an application rule never on a chart hop.
func TestChartApplicabilityAgreesWithClaims(t *testing.T) {
	registry := chartRegistry(t)
	random := rand.New(rand.NewSource(20261011))
	pick := func(values ...string) string { return values[random.Intn(len(values))] }
	charts := []string{"", chartJSON(chartSource, chartName), chartJSON(chartSource, "other")}
	for iteration := 0; iteration < 600; iteration++ {
		var rules []any
		for index := 0; index < 1+random.Intn(4); index++ {
			operator := pick("forbid_target_version", OperatorRequireSetMember, "forbid_predicate_value")
			subjectChart := pick(charts...)
			extra := ""
			switch operator {
			case OperatorRequireSetMember:
				extra = requireConditionJSON(pick("a", "b"))
			case "forbid_predicate_value":
				extra = `"condition":{"side":"proposed","component":"` + testComponent + `","factId":"` + testFact + `","boolValue":true}`
			}
			rule := chartRuleDocument(t, operator, subjectChart, extra, false)["rules"].([]any)[0].(map[string]any)
			rule["id"] = fmt.Sprintf("rule-%02d", index)
			rule["subject"].(map[string]any)["to"] = pick("2.0.0", "2.0.0", "3.0.0")
			rules = append(rules, rule)
		}
		document := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), true)
		document["rules"] = rules
		raw, _ := json.Marshal(document)
		ruleSet, err := ParseRuleSet(raw, registry)
		if err != nil {
			// Only a document without any chart rule may be refused (it then
			// carries the wrong schema); never a well-formed chart document.
			if chart, _ := AnyChartRule(rawRules(t, rules)); chart {
				t.Fatalf("iteration %d: %v", iteration, err)
			}
			continue
		}
		inputChart := pick(charts...)
		facts := []string{}
		switch random.Intn(3) {
		case 0:
			facts = append(facts, declaredFact(testFact, random.Intn(2) == 0))
		}
		facts = append(facts, valuesSetFact([]string{pick("a", "b")}, random.Intn(2) == 0))
		inputRaw := chartInputRaw(inputChart, inputChart, strings.Join(sortedFacts(facts), ","), true)
		input, err := ParseInput([]byte(inputRaw), registry)
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		report, err := Evaluate(input, ruleSet, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := MarshalReport(report)
		if err != nil {
			t.Fatalf("iteration %d: seal: %v", iteration, err)
		}
		if _, err := Replay(input, ruleSet, testNow(t), sealed); err != nil {
			t.Fatal(err)
		}
		scope := map[string]struct{}{testComponent: {}}
		appRuleOnChartHop := false
		for index, candidate := range ruleSet.document.Rules {
			claim := report.Claims[index]
			applicability, reason := ruleApplicability(input.document, scope, candidate)
			decided := claim.Status == "PASS" || claim.Status == "BLOCKED"
			sameChartHop := sameChart(candidate.Subject.Chart, input.document.Current.Components[0].Chart)
			if decided && !sameChartHop {
				t.Fatalf("iteration %d: %s decided across chart identities: %+v", iteration, candidate.ID, claim)
			}
			if !sameChartHop {
				want := ReasonSubjectChartNotDeclared
				if candidate.Subject.Chart == nil {
					want, appRuleOnChartHop = ReasonAppVersionNotDeclared, true
				}
				if claim.ReasonCode != want || reason != want {
					t.Fatalf("iteration %d: %s reason %s/%s, want %s", iteration, candidate.ID, claim.ReasonCode, reason, want)
				}
				wantApplicability := ApplicabilityNotApplicable
				if want == ReasonAppVersionNotDeclared {
					wantApplicability = ApplicabilityUndetermined
				}
				if applicability != wantApplicability {
					t.Fatalf("iteration %d: %s applicability %s", iteration, candidate.ID, applicability)
				}
			}
		}
		if appRuleOnChartHop && report.Assessment == AssessmentScopeCompletePass {
			t.Fatalf("iteration %d: complete pass with an application rule unread on a chart hop", iteration)
		}
	}
}

func rawRules(t *testing.T, rules []any) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, 0, len(rules))
	for _, rule := range rules {
		raw, _ := json.Marshal(rule)
		out = append(out, raw)
	}
	return out
}

// sortedFacts orders fact objects by id, as the input requires.
func sortedFacts(facts []string) []string {
	sort.Slice(facts, func(i, j int) bool { return factID(facts[i]) < factID(facts[j]) })
	return facts
}

func factID(fact string) string {
	var shape struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(fact), &shape)
	return shape.ID
}

// TestChartRuleRequiresKubernetesVersion: a chart rule may require the
// version of another component (the Kubernetes version a kubeVersion
// constraint names), declared as an application version next to the chart
// hop.
func TestChartRuleRequiresKubernetesVersion(t *testing.T) {
	registry := chartRegistry(t)
	const kubernetes = "pkg:github/kubernetes/kubernetes"
	rules := parseChartRules(t, registry, chartRuleDocument(t, "require_component_version", chartJSON(chartSource, chartName), `"dependency":{"side":"proposed","component":"`+kubernetes+`","comparison":"gte","version":"1.22.0"}`, false))
	input := func(k8s string) Input {
		t.Helper()
		chart := `"chart":` + chartJSON(chartSource, chartName) + `,`
		side := func(version string) string {
			out := `{"components":[`
			if k8s != "" {
				out += `{"component":"` + kubernetes + `","version":"` + k8s + `","facts":[]},`
			}
			return out + `{"component":"` + testComponent + `","version":"` + version + `",` + chart + `"facts":[]}]}`
		}
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":` + side("1.0.0") + `,"proposed":` + side("2.0.0") + `}`
		parsed, err := ParseInput([]byte(raw), registry)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	for k8s, want := range map[string]string{"1.21.9": "BLOCKED", "1.22.0": "PASS", "1.30.1": "PASS", "": "UNKNOWN"} {
		report, _ := evaluateAndSeal(t, input(k8s), rules)
		if claim := report.Claims[0]; claim.Status != want || want == "UNKNOWN" && claim.ReasonCode != "RULE_DEPENDENCY_COMPONENT_MISSING" {
			t.Fatalf("kubernetes %q: %+v", k8s, claim)
		}
	}
}
