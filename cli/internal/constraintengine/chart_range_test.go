// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

const (
	pinnedEngineContractDigestChartRanged = "sha256:46efac8da1c1aad39ea6bda66e873f9a07088ba8e8caa1e180450b736d208719"
	pinnedScopeContractDigestChartRanged  = "sha256:8bed4826bcb80f4331ee69e849d67cef6207900f06f170b75f81ae7e339dfc16"

	chartRangeKubernetes = "pkg:github/kubernetes/kubernetes"
)

// chartLineRange is the range JSON of a chart rule over two lines, in one
// of the two line shapes or with explicit bases.
func chartLineRange(fromGte, fromLt, toGte, toLt string, bases ...string) string {
	names := []string{"from.gte", "from.lt", "to.gte", "to.lt"}
	bounds := make([]string, len(bases))
	for i, basis := range bases {
		bounds[i] = `{"bound":"` + names[i] + `","basis":"` + basis + `","sourceId":"upstream-doc"}`
	}
	return `"range":{"from":{"gte":"` + fromGte + `","lt":"` + fromLt + `"},"to":{"gte":"` + toGte + `","lt":"` + toLt + `"},"bounds":[` + strings.Join(bounds, ",") + `]}`
}

// consecutiveRange is the release-boundary shape 2.15 -> 2.16.
func consecutiveRange(release string) string {
	return chartLineRange("2.15.0", "2.16.0", "2.16.0", "2.17.0", BasisPreviousMinorLine, release, release, BasisTargetSeries)
}

// wholeLineRange is the whole-line shape between two lines.
func wholeLineRange(fromGte, fromLt, toGte, toLt string) string {
	return chartLineRange(fromGte, fromLt, toGte, toLt, BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries)
}

// rangedChartDocument is one chart rule from..to with extra fields under
// the given schema.
func rangedChartDocument(t *testing.T, schema, operator, from, to, extra string, corpus bool) map[string]any {
	t.Helper()
	document := chartRuleDocument(t, operator, chartJSON(chartSource, chartName), extra, corpus)
	document["schema"] = schema
	subject := document["rules"].([]any)[0].(map[string]any)["subject"].(map[string]any)
	subject["from"], subject["to"] = from, to
	return document
}

// chartHopInput is a chart hop from -> to of the test component, with an
// optional proposed values set fact, an optional Kubernetes version on both
// sides and an optional complete scope.
func chartHopInput(t *testing.T, registry Registry, from, to, fact, kubernetes string, scope bool) Input {
	t.Helper()
	side := func(version, fact string) string {
		out := `{"components":[`
		if kubernetes != "" {
			out += `{"component":"` + chartRangeKubernetes + `","version":"` + kubernetes + `","facts":[]},`
		}
		return out + `{"component":"` + testComponent + `","version":"` + version + `","chart":` + chartJSON(chartSource, chartName) + `,"facts":[` + fact + `]}]}`
	}
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":` + side(from, "") + `,"proposed":` + side(to, fact) + ``
	if scope {
		components := `"` + testComponent + `"`
		if kubernetes != "" {
			components = `"` + chartRangeKubernetes + `",` + components
		}
		raw += `,"scope":{"declaration":"` + ScopeDeclaration + `","components":[` + components + `]}`
	}
	input, err := ParseInput([]byte(raw+`}`), registry)
	if err != nil {
		t.Fatalf("input %s -> %s: %v", from, to, err)
	}
	return input
}

func parseErr(registry Registry, document map[string]any) error {
	raw, _ := json.Marshal(document)
	_, err := ParseRuleSet(raw, registry)
	return err
}

func TestChartRangeContractDigestsArePinnedAndDistinct(t *testing.T) {
	if EngineContractDigestChartRanged() != pinnedEngineContractDigestChartRanged || ScopeContractDigestChartRanged() != pinnedScopeContractDigestChartRanged {
		t.Fatalf("ranged chart contract digests moved: %s %s", EngineContractDigestChartRanged(), ScopeContractDigestChartRanged())
	}
	// The chart (v1alpha8) and chart notice (v1alpha9) contracts keep the
	// identity their reports were issued under.
	for got, want := range map[string]string{
		EngineContractDigestChart(): pinnedEngineContractDigestChart, ScopeContractDigestChart(): pinnedScopeContractDigestChart,
		EngineContractDigestChartNotice(): pinnedEngineContractDigestChartNotice, ScopeContractDigestChartNotice(): pinnedScopeContractDigestChartNotice,
		EngineContractDigestCrossing(): pinnedEngineContractDigestCrossing, ScopeContractDigestCrossing(): pinnedScopeContractDigestCrossing,
	} {
		if got != want {
			t.Fatalf("an earlier contract digest moved: %s != %s", got, want)
		}
	}
	// The v1alpha8 semantics text is a digest input: it keeps saying
	// anchor-only.
	if !strings.Contains(chartSemantics, ";chart-rule:anchor-only:no-range:no-crossing:no-severity:") {
		t.Fatal("the v1alpha8 chart semantics literal changed")
	}
	if scopeDigestFor(EngineContractDigestChartRanged()) != ScopeContractDigestChartRanged() || EngineContractDigestChartRanged() == EngineContractDigestChartNotice() || ScopeContractDigestChartRanged() == ScopeContractDigestChartNotice() {
		t.Fatal("ranged chart contract pairing")
	}
}

// TestChartRangeAdmission: a chart rule takes a range only under the
// ranged chart schema, only in the two line shapes, and only on the three
// operators a chart derivation produces.
func TestChartRangeAdmission(t *testing.T) {
	registry := chartRegistry(t)
	dependency := `"dependency":{"side":"proposed","component":"` + chartRangeKubernetes + `","comparison":"gte","version":"1.30.0"}`
	set := requireConditionJSON("a.b")
	accepted := map[string]map[string]any{
		"require_set_member consecutive":          rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"forbid_set_member consecutive removed":   rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisRemovedInRelease), false),
		"forbid_set_member consecutive changed":   rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"kube version consecutive":                rangedChartDocument(t, RulesSchemaChartRanged, "require_component_version", "2.15.0", "2.16.0", dependency+","+consecutiveRange(BasisChangedInRelease), false),
		"whole line over a gap":                   rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.17.0", set+","+wholeLineRange("2.15.0", "2.16.0", "2.17.0", "2.18.0"), false),
		"whole line over a new major":             rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "1.9.0", "2.0.0", set+","+wholeLineRange("1.9.0", "1.10.0", "2.0.0", "2.1.0"), false),
		"anchor inside the line, not its start":   rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.1", "2.16.2", set+","+consecutiveRange(BasisChangedInRelease), false),
		"ranged require with a scope attestation": rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), true),
	}
	for name, document := range accepted {
		if err := parseErr(registry, document); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	refused := map[string]map[string]any{
		"range under the v1alpha8 schema":           rangedChartDocument(t, RulesSchemaChart, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"range under the v1alpha9 schema":           rangedChartDocument(t, RulesSchemaChartNotice, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"range under the crossing schema":           rangedChartDocument(t, RulesSchemaCrossing, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"ranged chart schema without a chart range": rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set, false),
		"severity on a ranged chart rule":           rangedChartDocument(t, RulesSchemaChartRanged, "require_component_version", "2.15.0", "2.16.0", `"severity":"unsupported",`+dependency+","+consecutiveRange(BasisChangedInRelease), false),
		"ANCHOR_ONLY bound":                         rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+chartLineRange("2.15.0", "2.15.1", "2.16.0", "2.17.0", BasisAnchorOnly, BasisAnchorOnly, BasisTargetSeries, BasisTargetSeries), false),
		"ANCHOR_ONLY bound on a whole line":         rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.17.0", set+","+chartLineRange("2.15.0", "2.16.0", "2.17.0", "2.18.0", BasisAnchorOnly, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries), false),
		"RESTORED_IN_RELEASE bound":                 rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+chartLineRange("2.15.0", "2.16.0", "2.16.0", "2.17.0", BasisPreviousMinorLine, BasisRemovedInRelease, BasisRemovedInRelease, BasisRestoredInRelease), false),
		"REVIEWED_THROUGH_MINOR_LINE bound":         rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+chartLineRange("2.15.0", "2.16.0", "2.16.0", "2.17.0", BasisPreviousMinorLine, BasisRemovedInRelease, BasisRemovedInRelease, BasisReviewedThroughMinorLine), false),
		"mixed release bases":                       rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+chartLineRange("2.15.0", "2.16.0", "2.16.0", "2.17.0", BasisPreviousMinorLine, BasisRemovedInRelease, BasisChangedInRelease, BasisTargetSeries), false),
		"whole-line shape on consecutive lines":     rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+wholeLineRange("2.15.0", "2.16.0", "2.16.0", "2.17.0"), false),
		"boundary shape over a gap":                 rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.17.0", set+","+chartLineRange("2.15.0", "2.16.0", "2.17.0", "2.18.0", BasisPreviousMinorLine, BasisChangedInRelease, BasisChangedInRelease, BasisTargetSeries), false),
		"range excluding its anchor":                rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.14.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false),
		"forbid_target_version with a range":        rangedChartDocument(t, RulesSchemaChartRanged, "forbid_target_version", "2.15.0", "2.16.0", consecutiveRange(BasisChangedInRelease), false),
		"require_intermediate_version with a range": rangedChartDocument(t, RulesSchemaChartRanged, "require_intermediate_version", "2.15.0", "2.17.0", `"intermediate":"2.16.0",`+wholeLineRange("2.15.0", "2.16.0", "2.17.0", "2.18.0"), false),
		"forbid_predicate_value with a range":       rangedChartDocument(t, RulesSchemaChartRanged, "forbid_predicate_value", "2.15.0", "2.16.0", `"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","boolValue":true},`+consecutiveRange(BasisChangedInRelease), false),
		"set notice with a range":                   rangedChartDocument(t, RulesSchemaChartRanged, OperatorNoticeSetMemberPresent, "2.15.0", "2.16.0", set+`,"reasonCode":"HELM_VALUES_KEY_NOT_REFERENCED","nextAction":"review the listed keys",`+consecutiveRange(BasisChangedInRelease), false),
		"bound citing a source the rule lacks":      rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+strings.Replace(consecutiveRange(BasisChangedInRelease), `"sourceId":"upstream-doc"`, `"sourceId":"other-doc"`, 1), false),
	}
	// A range on require_set_member without a chart subject is refused
	// under every schema.
	for _, schema := range []string{RulesSchemaChart, RulesSchemaChartNotice, RulesSchemaChartRanged} {
		document := chartRuleDocument(t, OperatorRequireSetMember, "", set+","+consecutiveRange(BasisChangedInRelease), false)
		document["schema"] = schema
		refused["require range without a chart under "+schema] = document
	}
	// A crossing on a chart rule is refused under every schema.
	crossing := `"crossing":{"change":{"version":"2.16.0","basis":"REMOVED_IN_RELEASE","sourceId":"upstream-doc"},"horizon":{"lt":"2.18.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"upstream-doc"}}`
	// The same crossing is admitted on the rule without a chart subject, so
	// the refusals below are about the chart.
	plain := rangedChartDocument(t, RulesSchemaCrossing, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+crossing, false)
	delete(plain["rules"].([]any)[0].(map[string]any)["subject"].(map[string]any), "chart")
	if err := parseErr(registry, plain); err != nil {
		t.Fatalf("crossing without a chart refused: %v", err)
	}
	for _, schema := range []string{RulesSchemaCrossing, RulesSchemaChart, RulesSchemaChartNotice, RulesSchemaChartRanged} {
		refused["crossing under "+schema] = rangedChartDocument(t, schema, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+crossing, false)
		refused["crossing and range under "+schema] = rangedChartDocument(t, schema, OperatorForbidSetMember, "2.15.0", "2.16.0", set+","+crossing+","+consecutiveRange(BasisRemovedInRelease), false)
	}
	for name, document := range refused {
		if err := parseErr(registry, document); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	// The raw-rule counterpart names the ranged chart schema exactly when
	// a chart rule carries a range.
	for name, want := range map[string]struct {
		document map[string]any
		schema   string
	}{
		"ranged chart rule": {rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", set+","+consecutiveRange(BasisChangedInRelease), false), RulesSchemaChartRanged},
		"anchor chart rule": {rangedChartDocument(t, RulesSchemaChart, OperatorRequireSetMember, "2.15.0", "2.16.0", set, false), RulesSchemaChart},
		"ranged app rule":   {testRuleDocument("forbid_target_version", wholeLineRange("1.0.0", "1.1.0", "2.0.0", "2.1.0")), RulesSchemaRanged},
	} {
		raw, _ := json.Marshal(want.document["rules"].([]any)[0])
		if schema, err := RulesSchemaFor([]json.RawMessage{raw}); err != nil || schema != want.schema {
			t.Errorf("%s: RulesSchemaFor %s %v", name, schema, err)
		}
	}
}

// TestChartRangeBoundaryHopIsUndetermined: a hop that crosses the release
// boundary of a consecutive-line chart range from outside the range is not
// reviewed, never not applicable; a whole-line range knows no boundary.
func TestChartRangeBoundaryHopIsUndetermined(t *testing.T) {
	registry := chartRegistry(t)
	fact := valuesSetFact([]string{"a.b"}, true)
	rules := parseChartRules(t, registry, rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisChangedInRelease), true))
	for _, hop := range [][2]string{{"2.14.3", "2.16.0"}, {"2.14.0", "2.17.1"}, {"1.9.0", "2.16.4"}} {
		report, _ := evaluateAndSeal(t, chartHopInput(t, registry, hop[0], hop[1], fact, "", true), rules)
		claim := report.Claims[0]
		if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed || claim.SubjectMatch != nil {
			t.Fatalf("%v: %+v", hop, claim)
		}
		if report.Assessment != AssessmentUnknown || report.EngineContractDigest != EngineContractDigestChartRanged() {
			t.Fatalf("%v: %+v", hop, report)
		}
		skipped := report.ScopeCompleteness.Components[0].NotEvaluated
		if len(skipped) != 1 || skipped[0].Applicability != ApplicabilityUndetermined {
			t.Fatalf("%v: boundary hop not undetermined in scope: %+v", hop, report.ScopeCompleteness)
		}
	}
	// A hop that does not reach the boundary is outside the rule.
	report, _ := evaluateAndSeal(t, chartHopInput(t, registry, "2.14.0", "2.15.3", fact, "", true), rules)
	if claim := report.Claims[0]; claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("%+v", claim)
	}
	// A whole-line range has no boundary: a hop outside it is excluded.
	whole := parseChartRules(t, registry, rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.17.0", requireConditionJSON("a.b")+","+wholeLineRange("2.15.0", "2.16.0", "2.17.0", "2.18.0"), true))
	report, _ = evaluateAndSeal(t, chartHopInput(t, registry, "2.14.3", "2.17.0", fact, "", true), whole)
	if claim := report.Claims[0]; claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("%+v", claim)
	}
}

// TestChartRangeMatchDiscloses: a hop inside the range is decided with a
// subjectMatch disclosure and can never be a scope-complete pass; the
// anchor hop can.
func TestChartRangeMatchDiscloses(t *testing.T) {
	registry := chartRegistry(t)
	rules := parseChartRules(t, registry, rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b", "c")+","+consecutiveRange(BasisChangedInRelease), true))
	for _, tc := range []struct {
		from, to, fact, status, assessment string
		ranged                             bool
	}{
		{"2.15.4", "2.16.2", valuesSetFact([]string{"a.b", "c"}, true), "PASS", AssessmentUnknown, true},
		{"2.15.4", "2.16.2", valuesSetFact([]string{"a.b"}, true), "BLOCKED", AssessmentBlocked, true},
		{"2.15.0", "2.16.9", valuesSetFact([]string{"a.b"}, false), "UNKNOWN", AssessmentUnknown, true},
		{"2.15.0", "2.16.0", valuesSetFact([]string{"a.b", "c"}, true), "PASS", AssessmentScopeCompletePass, false},
	} {
		report, raw := evaluateAndSeal(t, chartHopInput(t, registry, tc.from, tc.to, tc.fact, "", true), rules)
		claim := report.Claims[0]
		if claim.Status != tc.status || report.Assessment != tc.assessment || (claim.SubjectMatch != nil) != tc.ranged {
			t.Fatalf("%s -> %s: %+v %s", tc.from, tc.to, claim, report.Assessment)
		}
		if !tc.ranged {
			continue
		}
		match := claim.SubjectMatch
		if match.Mode != subjectMatchModeRange || match.AnchorFrom != "2.15.0" || match.AnchorTo != "2.16.0" || match.From.Gte != "2.15.0" || match.To.Lt != "2.17.0" || tc.status == "PASS" && !strings.Contains(claim.NextAction, "matched by reviewed range") || !strings.Contains(string(raw), `"subjectMatch"`) {
			t.Fatalf("%s -> %s: disclosure %+v %q", tc.from, tc.to, match, claim.NextAction)
		}
		if tc.status == "PASS" && report.ScopeCompleteness.UnresolvedReason != unresolvedTransitionNotAnchor {
			t.Fatalf("range pass not marked as not anchor-reviewed: %+v", report.ScopeCompleteness)
		}
	}
}

// TestChartRangeClaimsBoundToTheContract: a range disclosure on a chart
// claim seals only under the ranged chart contract.
func TestChartRangeClaimsBoundToTheContract(t *testing.T) {
	registry := chartRegistry(t)
	rules := parseChartRules(t, registry, rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisChangedInRelease), false))
	report, err := Evaluate(chartHopInput(t, registry, "2.15.3", "2.16.1", valuesSetFact([]string{"a.b"}, true), "", false), rules, testNow(t))
	if err != nil || report.Claims[0].SubjectMatch == nil {
		t.Fatalf("%+v %v", report, err)
	}
	for _, digest := range []string{EngineContractDigestChart(), EngineContractDigestChartNotice()} {
		forged := report
		forged.EngineContractDigest = digest
		if _, err := MarshalReport(issueReport(forged)); !errors.Is(err, ErrIntegrity) {
			t.Errorf("range disclosure on a require claim sealed under %s: %v", digest, err)
		}
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("unforged report refused: %v", err)
	}
	// A chart hop is still refused by a document without a chart rule.
	plain := testRules(t, registry, "forbid_target_version", "")
	if _, err := Evaluate(chartHopInput(t, registry, "2.15.0", "2.16.0", "", "", false), plain, testNow(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chart hop under the exact-only contract: %v", err)
	}
}

// TestChartRangeWithSetNotice: a document holding a ranged chart rule and an
// anchor-only set notice is evaluated under the ranged chart contract, and
// the notice behaves as under the chart notice contract.
func TestChartRangeWithSetNotice(t *testing.T) {
	registry := chartRegistry(t)
	document := rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisChangedInRelease), false)
	notice := setNoticeRule(t, "z-notice", OperatorNoticeSetMemberPresent, "old.key")
	notice["subject"].(map[string]any)["from"], notice["subject"].(map[string]any)["to"] = "2.15.0", "2.16.0"
	document["rules"] = append(document["rules"].([]any), notice)
	rules := parseChartRules(t, registry, document)
	report, _ := evaluateAndSeal(t, chartHopInput(t, registry, "2.15.0", "2.16.0", valuesSetFact([]string{"a.b", "old.key"}, true), "", false), rules)
	if report.EngineContractDigest != EngineContractDigestChartRanged() || report.Claims[0].Status != "PASS" || report.Claims[1].Status != StatusNotice {
		t.Fatalf("%+v", report)
	}
	// The notice stays anchor-only: inside the range it does not match.
	report, _ = evaluateAndSeal(t, chartHopInput(t, registry, "2.15.2", "2.16.1", valuesSetFact([]string{"a.b", "old.key"}, true), "", false), rules)
	if report.Claims[0].Status != "PASS" || report.Claims[0].SubjectMatch == nil || report.Claims[1].Status != "UNKNOWN" || report.Claims[1].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("%+v", report.Claims)
	}
}

// TestChartRangeHopsAgreeWithTheAnchor: for each ranged chart rule kind,
// every hop inside the range evaluates exactly as the anchor pair does on
// the same facts, apart from the range disclosure.
func TestChartRangeHopsAgreeWithTheAnchor(t *testing.T) {
	registry := chartRegistry(t)
	dependency := `"dependency":{"side":"proposed","component":"` + chartRangeKubernetes + `","comparison":"gte","version":"1.30.0"}`
	documents := []map[string]any{
		rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b", "c")+","+consecutiveRange(BasisChangedInRelease), true),
		rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b", "c")+","+consecutiveRange(BasisRemovedInRelease), true),
		rangedChartDocument(t, RulesSchemaChartRanged, "require_component_version", "2.15.0", "2.16.0", dependency+","+consecutiveRange(BasisChangedInRelease), true),
	}
	members := []string{"a.b", "c", "d"}
	rng := rand.New(rand.NewSource(20261015))
	for _, document := range documents {
		rules := parseChartRules(t, registry, document)
		for i := 0; i < 200; i++ {
			var held []string
			for _, m := range members {
				if rng.Intn(2) == 0 {
					held = append(held, m)
				}
			}
			fact := ""
			if rng.Intn(6) != 0 {
				fact = valuesSetFact(held, rng.Intn(3) != 0)
			}
			kubernetes := []string{"", "1.29.9", "1.30.0", "1.31.2"}[rng.Intn(4)]
			from, to := fmt.Sprintf("2.15.%d", rng.Intn(40)), fmt.Sprintf("2.16.%d", rng.Intn(40))
			anchor, _ := evaluateAndSeal(t, chartHopInput(t, registry, "2.15.0", "2.16.0", fact, kubernetes, true), rules)
			hop, _ := evaluateAndSeal(t, chartHopInput(t, registry, from, to, fact, kubernetes, true), rules)
			a, h := anchor.Claims[0], hop.Claims[0]
			if a.SubjectMatch != nil || (h.SubjectMatch != nil) != (from != "2.15.0" || to != "2.16.0") {
				t.Fatalf("disclosure: anchor %+v hop %+v", a.SubjectMatch, h.SubjectMatch)
			}
			if a.Status != h.Status || a.ReasonCode != h.ReasonCode || strings.Join(a.MissingMembers, ",") != strings.Join(h.MissingMembers, ",") || strings.Join(a.MatchedMembers, ",") != strings.Join(h.MatchedMembers, ",") || !strings.HasPrefix(h.NextAction, strings.TrimSuffix(a.NextAction, ".")) {
				t.Fatalf("%s -> %s differs from the anchor: %+v vs %+v", from, to, h, a)
			}
			// Only the anchor hop may reach a scope-complete pass.
			if hop.Assessment == AssessmentScopeCompletePass && h.SubjectMatch != nil {
				t.Fatalf("range hop reached a scope-complete pass: %+v", hop)
			}
			if a.Status == "BLOCKED" && hop.Assessment != AssessmentBlocked {
				t.Fatalf("anchor blocks, hop assessment %s", hop.Assessment)
			}
		}
	}
}

// TestChartRangeClaimsOfEveryOperatorBound: a range disclosure on a
// forbid_set_member or require_component_version chart-rule claim seals
// only under the ranged chart contract too, not just on require_set_member.
func TestChartRangeClaimsOfEveryOperatorBound(t *testing.T) {
	registry := chartRegistry(t)
	dependency := `"dependency":{"side":"proposed","component":"` + chartRangeKubernetes + `","comparison":"gte","version":"1.30.0"}`
	for name, tc := range map[string]struct {
		document   map[string]any
		kubernetes string
	}{
		"forbid_set_member":         {rangedChartDocument(t, RulesSchemaChartRanged, OperatorForbidSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisRemovedInRelease), true), ""},
		"require_component_version": {rangedChartDocument(t, RulesSchemaChartRanged, "require_component_version", "2.15.0", "2.16.0", dependency+","+consecutiveRange(BasisChangedInRelease), true), "1.31.0"},
	} {
		rules := parseChartRules(t, registry, tc.document)
		report, _ := evaluateAndSeal(t, chartHopInput(t, registry, "2.15.3", "2.16.1", valuesSetFact([]string{"c"}, true), tc.kubernetes, true), rules)
		if report.Claims[0].SubjectMatch == nil || report.ScopeCompleteness == nil {
			t.Fatalf("%s: no range match: %+v", name, report)
		}
		pairs := map[string]string{EngineContractDigestChart(): ScopeContractDigestChart(), EngineContractDigestChartNotice(): ScopeContractDigestChartNotice()}
		for engine, scope := range pairs {
			forged := report
			forged.EngineContractDigest = engine
			forgedScope := *report.ScopeCompleteness
			forgedScope.ContractDigest = scope
			forged.ScopeCompleteness = &forgedScope
			if _, err := MarshalReport(issueReport(forged)); !errors.Is(err, ErrIntegrity) {
				t.Errorf("%s: range disclosure sealed under %s: %v", name, engine, err)
			}
			// The chart claim check itself refuses it: the claim is a
			// chart-rule claim because the scope lists it under a chart hop.
			if validChartClaims(forged) {
				t.Errorf("%s: chart claim check admits a range disclosure under %s", name, engine)
			}
		}
	}
}

// TestChartRangeOverlapsRefused: a ranged chart rule may not overlap a
// sibling that constrains the same set members, nor a forbid rule that
// contradicts it on one member.
func TestChartRangeOverlapsRefused(t *testing.T) {
	registry := chartRegistry(t)
	base := func() map[string]any {
		return rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisChangedInRelease), false)
	}
	sibling := func(id, operator, from, to string, members []string, ranged bool) map[string]any {
		extra := requireConditionJSON(members...)
		if ranged {
			extra += "," + consecutiveRange(BasisChangedInRelease)
		}
		rule := rangedChartDocument(t, RulesSchemaChartRanged, operator, from, to, extra, false)["rules"].([]any)[0].(map[string]any)
		rule["id"] = id
		return rule
	}
	with := func(rule map[string]any) map[string]any {
		document := base()
		document["rules"] = append(document["rules"].([]any), rule)
		return document
	}
	refused := map[string]map[string]any{
		"exact require on the anchor":     with(sibling("z-require", OperatorRequireSetMember, "2.15.0", "2.16.0", []string{"a.b"}, false)),
		"exact require inside the range":  with(sibling("z-require", OperatorRequireSetMember, "2.15.4", "2.16.2", []string{"a.b"}, false)),
		"second ranged require":           with(sibling("z-require", OperatorRequireSetMember, "2.15.2", "2.16.3", []string{"a.b", "c"}, true)),
		"forbid inside the range":         with(sibling("z-forbid", OperatorForbidSetMember, "2.15.4", "2.16.2", []string{"a.b"}, false)),
		"ranged forbid on the same lines": with(sibling("z-forbid", OperatorForbidSetMember, "2.15.0", "2.16.0", []string{"a.b"}, true)),
	}
	for name, document := range refused {
		if err := parseErr(registry, document); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	accepted := map[string]map[string]any{
		"require of another member": with(sibling("z-require", OperatorRequireSetMember, "2.15.4", "2.16.2", []string{"c"}, false)),
		"forbid of another member":  with(sibling("z-forbid", OperatorForbidSetMember, "2.15.4", "2.16.2", []string{"c"}, true)),
		"require on the next lines": with(sibling("z-require", OperatorRequireSetMember, "2.16.0", "2.17.0", []string{"a.b"}, false)),
	}
	for name, document := range accepted {
		if err := parseErr(registry, document); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}
