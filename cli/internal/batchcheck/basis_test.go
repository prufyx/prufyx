// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestBatchBasisOutcomes: a lead never decides a batch item, and a
// consensus NO_KNOWN_ISSUE is never a pass.
func TestBatchBasisOutcomes(t *testing.T) {
	lead := constraintengine.Claim{RuleID: "lead", Operator: "forbid_target_version", Status: constraintengine.StatusNotice, ReasonCode: constraintengine.ReasonLeadNotVerified, EvidenceBasis: constraintengine.BasisLead, EvidenceFreshness: "current"}
	leadQuiet := constraintengine.Claim{RuleID: "lead-quiet", Operator: "forbid_predicate_value", Status: constraintengine.StatusNoKnownIssue, ReasonCode: constraintengine.ReasonLeadNoKnownIssue, EvidenceBasis: constraintengine.BasisLead, EvidenceFreshness: "current"}
	consensus := constraintengine.Claim{RuleID: "consensus", Operator: "forbid_predicate_value", Status: constraintengine.StatusNoKnownIssue, ReasonCode: constraintengine.ReasonConsensusNoKnownIssue, EvidenceBasis: constraintengine.BasisConsensus, EvidenceFreshness: "current"}
	pass := constraintengine.Claim{RuleID: "pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current"}
	blocked := constraintengine.Claim{RuleID: "blocked", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", EvidenceBasis: constraintengine.BasisConsensus, EvidenceFreshness: "current"}
	base := ItemResult{Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	for _, tc := range []struct {
		name     string
		claims   []constraintengine.Claim
		category string
	}{
		{"only leads", []constraintengine.Claim{lead, leadQuiet}, "UNKNOWN_CLAIM"},
		{"pass and leads", []constraintengine.Claim{pass, lead, leadQuiet}, "PASS"},
		{"pass and consensus NO_KNOWN_ISSUE", []constraintengine.Claim{pass, consensus}, "UNKNOWN_CLAIM"},
		{"consensus blocker", []constraintengine.Claim{pass, blocked}, "BLOCKED"},
	} {
		result := fromClaims(base, cncfClaimViews(tc.claims))
		if result.Category != tc.category {
			t.Fatalf("%s: category=%s", tc.name, result.Category)
		}
		if _, exit := aggregate([]ItemResult{result}); (tc.category == "PASS") != (exit == 0) {
			t.Fatalf("%s: exit=%d", tc.name, exit)
		}
	}
}
