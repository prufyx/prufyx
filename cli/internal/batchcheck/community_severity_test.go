// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestBatchCommunityClaimOutcomes: a community-project item treats claims as
// a CNCF item does. UNSUPPORTED is neither a pass nor a blocker, and a
// one-way notice is informational: it never turns a pass into an unknown and
// never makes an item with nothing else a pass.
func TestBatchCommunityClaimOutcomes(t *testing.T) {
	unsupported := constraintengine.Claim{RuleID: "support", Operator: "require_component_version", Status: constraintengine.StatusUnsupported, ReasonCode: "ADDON_KUBERNETES_SUPPORT_RANGE", Severity: constraintengine.SeverityUnsupported, EvidenceFreshness: "current"}
	pass := constraintengine.Claim{RuleID: "pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "REVIEWED_SOURCE_CONSTRAINT", EvidenceFreshness: "current"}
	blocked := constraintengine.Claim{RuleID: "blocked", Operator: "forbid_predicate_value", Status: "BLOCKED", ReasonCode: "REVIEWED_SOURCE_CONSTRAINT", EvidenceFreshness: "current"}
	notice := constraintengine.Claim{RuleID: "notice", Operator: constraintengine.OperatorNoticeOneWay, Status: constraintengine.StatusNotice, ReasonCode: constraintengine.ReasonOneWayTransition, EvidenceFreshness: "current"}
	base := ItemResult{Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	for _, tc := range []struct {
		name     string
		claims   []constraintengine.Claim
		category string
		exit     int
	}{
		{"pass", []constraintengine.Claim{pass}, "PASS", 0},
		{"pass and a notice", []constraintengine.Claim{pass, notice}, "PASS", 0},
		{"only a notice", []constraintengine.Claim{notice}, "UNKNOWN_CLAIM", 11},
		{"pass and UNSUPPORTED", []constraintengine.Claim{pass, unsupported}, "UNKNOWN_CLAIM", 11},
		{"UNSUPPORTED and a notice", []constraintengine.Claim{unsupported, notice}, "UNKNOWN_CLAIM", 11},
		{"blocker, UNSUPPORTED and a notice", []constraintengine.Claim{blocked, unsupported, notice}, "BLOCKED", 10},
	} {
		result := fromClaims(base, communityClaimViews(tc.claims))
		if result.Category != tc.category || (result.Outcome == "PASS") != (tc.category == "PASS") {
			t.Fatalf("%s: category=%s outcome=%s", tc.name, result.Category, result.Outcome)
		}
		if _, exit := aggregate([]ItemResult{result}); exit != tc.exit {
			t.Fatalf("%s: exit=%d want %d", tc.name, exit, tc.exit)
		}
	}
}
