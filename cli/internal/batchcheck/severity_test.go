// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestBatchUnsupportedOutcomes: an UNSUPPORTED claim is never a pass and
// never a blocker in a batch item.
func TestBatchUnsupportedOutcomes(t *testing.T) {
	unsupported := constraintengine.Claim{RuleID: "support", Operator: "require_component_version", Status: constraintengine.StatusUnsupported, ReasonCode: "ADDON_KUBERNETES_SUPPORT_RANGE", Severity: constraintengine.SeverityUnsupported, EvidenceFreshness: "current"}
	pass := constraintengine.Claim{RuleID: "pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current"}
	blocked := constraintengine.Claim{RuleID: "blocked", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current"}
	base := ItemResult{Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	for _, tc := range []struct {
		name     string
		claims   []constraintengine.Claim
		category string
		exit     int
	}{
		{"pass and UNSUPPORTED", []constraintengine.Claim{pass, unsupported}, "UNKNOWN_CLAIM", 11},
		{"only UNSUPPORTED", []constraintengine.Claim{unsupported}, "UNKNOWN_CLAIM", 11},
		{"blocker and UNSUPPORTED", []constraintengine.Claim{pass, blocked, unsupported}, "BLOCKED", 10},
	} {
		result := fromClaims(base, cncfClaimViews(tc.claims))
		if result.Category != tc.category || result.Outcome == "PASS" {
			t.Fatalf("%s: category=%s outcome=%s", tc.name, result.Category, result.Outcome)
		}
		if tc.category == "UNKNOWN_CLAIM" && result.ReasonCode != "ADDON_KUBERNETES_SUPPORT_RANGE" {
			t.Fatalf("%s: reason=%s", tc.name, result.ReasonCode)
		}
		if _, exit := aggregate([]ItemResult{result}); exit != tc.exit {
			t.Fatalf("%s: exit=%d", tc.name, exit)
		}
	}
}
