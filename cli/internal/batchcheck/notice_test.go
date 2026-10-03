// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestBatchIgnoresNotices: one-way notices never decide a batch item. Only
// notices leave the item UNKNOWN; beside a pass or a blocker they change
// nothing.
func TestBatchIgnoresNotices(t *testing.T) {
	notice := constraintengine.Claim{RuleID: "notice", Operator: constraintengine.OperatorNoticeOneWay, Status: constraintengine.StatusNotice, ReasonCode: constraintengine.ReasonOneWayTransition, EvidenceFreshness: "current"}
	pass := constraintengine.Claim{RuleID: "pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current"}
	blocked := constraintengine.Claim{RuleID: "blocked", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current"}
	base := ItemResult{Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	for _, tc := range []struct {
		name     string
		claims   []constraintengine.Claim
		category string
	}{
		{"only a notice", []constraintengine.Claim{notice}, "UNKNOWN_CLAIM"},
		{"pass and a notice", []constraintengine.Claim{pass, notice}, "PASS"},
		{"blocker and a notice", []constraintengine.Claim{blocked, notice}, "BLOCKED"},
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
