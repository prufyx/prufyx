// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"
)

// goldenOldSchemaReports pin the sealed report bytes of fixed documents under
// the schemas that predate the boundary-covered one. They were taken before
// that schema existed: a change to these hashes means an old document no
// longer replays byte for byte.
var goldenOldSchemaReports = map[string]string{
	RulesSchemaRanged: "30a60ee99cd053e154f639c450449df69f5d9b8eb5b8061ee3524cf7c6cade4e",
	RulesSchemaNotice: "1f21020de58cc79cd49be7778faa4102a5090c1a331fc65c1f39f3d020718810",
}

func goldenReportHash(t *testing.T, schema string) string {
	t.Helper()
	ranged := defaultRangeSpec()
	ranged.id = "r-range"
	exact := defaultRangeSpec()
	exact.id, exact.from, exact.to, exact.noRange = "e-exact", "1.21.0", "1.30.0", true
	rules := []string{ranged.ruleJSON(), exact.ruleJSON()}
	if schema == RulesSchemaNotice {
		rules = append(rules, noticeRule("n-notice", scopeComponentA, "1.40.0", "1.41.0", "active", activeUntil, ""))
	}
	sort.Slice(rules, func(i, j int) bool { return ruleIDOf(rules[i]) < ruleIDOf(rules[j]) })
	parsed, err := ParseRuleSet(rangeDocument(schema, true, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("%s: %v", schema, err)
	}
	report, err := Evaluate(xInput(t, "1.21.0", "1.30.0", "", "", true), parsed, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestOldSchemaReportsReplayByteIdentically(t *testing.T) {
	for schema, want := range goldenOldSchemaReports {
		got := goldenReportHash(t, schema)
		if want == "" {
			t.Logf("GOLDEN %s %s", schema, got)
		}
		if got != want {
			t.Errorf("%s: report hash %s, want %s", schema, got, want)
		}
	}
}

// goldenChartRangedBoundary is the sealed report of a hop that reaches a
// release-boundary UNKNOWN claim under the chart range schema. Taken before
// the boundary-covered schema existed.
const goldenChartRangedBoundary = "14c28defeccf8d75cd84a0f49f6b398aa48f1f0926d86b139bc1c882b4e2f38f"

func chartRangedBoundaryHash(t *testing.T) string {
	t.Helper()
	registry := chartRegistry(t)
	fact := valuesSetFact([]string{"a.b"}, true)
	rules := parseChartRules(t, registry, rangedChartDocument(t, RulesSchemaChartRanged, OperatorRequireSetMember, "2.15.0", "2.16.0", requireConditionJSON("a.b")+","+consecutiveRange(BasisChangedInRelease), true))
	report, raw := evaluateAndSeal(t, chartHopInput(t, registry, "2.14.3", "2.16.0", fact, "", true), rules)
	if claim := report.Claims[0]; claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed {
		t.Fatalf("fixture does not reach a boundary claim: %+v", claim)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestChartRangedBoundaryReportReplaysByteIdentically(t *testing.T) {
	got := chartRangedBoundaryHash(t)
	if goldenChartRangedBoundary == "" {
		t.Logf("GOLDEN chart-ranged %s", got)
	}
	if got != goldenChartRangedBoundary {
		t.Errorf("chart-ranged boundary report hash %s, want %s", got, goldenChartRangedBoundary)
	}
}
