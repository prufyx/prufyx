// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestBasisSemanticsOverRangesAndSets: the basis rewrite does not depend on
// how the subject matched or which operator decided. A range-matched or
// forbid_set_member consensus rule never passes and still blocks (with its
// matched members); a lead set rule never blocks and drops its members.
func TestBasisSemanticsOverRangesAndSets(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		registry := setRegistry(t)
		for _, tc := range []struct {
			basis, fact, status, reason string
			matched                     []string
		}{
			{BasisConsensus, setFactJSON([]string{"Kept", "RemovedGateA"}, true), "BLOCKED", "FEATURE_REMOVED", []string{"RemovedGateA"}},
			{BasisConsensus, setFactJSON([]string{"Kept"}, true), StatusNoKnownIssue, ReasonConsensusNoKnownIssue, nil},
			{BasisLead, setFactJSON([]string{"RemovedGateA"}, true), StatusNotice, ReasonLeadNotVerified, nil},
			{BasisLead, setFactJSON([]string{"Kept"}, true), StatusNoKnownIssue, ReasonLeadNoKnownIssue, nil},
		} {
			document := setRuleDocument(setConditionJSON("RemovedGateA"))
			document["schema"] = RulesSchemaBasis
			evidence := document["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
			evidence["basis"], evidence["derivedAt"] = tc.basis, "2026-01-01T00:00:00Z"
			raw, _ := json.Marshal(document)
			rules, err := ParseRuleSet(raw, registry)
			if err != nil {
				t.Fatal(err)
			}
			report, err := Evaluate(testInput(t, registry, tc.fact, "2.0.0"), rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || !reflect.DeepEqual(claim.MatchedMembers, tc.matched) {
				t.Fatalf("%s %s: claim=%+v", tc.basis, tc.fact, claim)
			}
			if _, err := MarshalReport(report); err != nil {
				t.Fatalf("%s: report refused: %v", tc.basis, err)
			}
		}
	})
	t.Run("range", func(t *testing.T) {
		for _, tc := range []struct {
			basis              string
			fact               bool
			status, assessment string
			unresolved         string
		}{
			{BasisConsensus, false, StatusNoKnownIssue, AssessmentUnknown, unresolvedConsensusOnlyScope},
			{BasisConsensus, true, "BLOCKED", AssessmentBlocked, unresolvedTransitionNotAnchor},
			{BasisLead, true, StatusNotice, AssessmentUnknown, unresolvedNoApplicableRule},
			{BasisLead, false, StatusNoKnownIssue, AssessmentUnknown, unresolvedNoApplicableRule},
		} {
			rule := withBasis(defaultRangeSpec().ruleJSON(), tc.basis)
			corpus := tc.basis == BasisConsensus
			rules, err := ParseRuleSet(rangeDocument(RulesSchemaBasis, corpus, rule), scopeRegistry(t))
			if err != nil {
				t.Fatal(err)
			}
			if !corpus {
				// A lead cannot back an attestation; add a verdict rule for
				// another pair so the component stays attested.
				other := defaultRangeSpec()
				other.id, other.noRange, other.from, other.to = "range-rule-other", true, "1.20.0", "1.21.0"
				rules, err = ParseRuleSet(rangeDocument(RulesSchemaBasis, true, rule, other.ruleJSON()), scopeRegistry(t))
				if err != nil {
					t.Fatal(err)
				}
			}
			report, err := Evaluate(rangeInput(t, "1.24.2", "1.25.3", declaredFact(scopeFactA, tc.fact), true), rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.SubjectMatch == nil {
				t.Fatalf("%s fact=%v: claim=%+v", tc.basis, tc.fact, claim)
			}
			if report.Assessment != tc.assessment || report.ScopeCompleteness == nil || report.ScopeCompleteness.UnresolvedReason != tc.unresolved {
				t.Fatalf("%s fact=%v: assessment=%s scope=%+v", tc.basis, tc.fact, report.Assessment, report.ScopeCompleteness)
			}
			if _, err := MarshalReport(report); err != nil {
				t.Fatalf("%s: report refused: %v", tc.basis, err)
			}
		}
	})
}
