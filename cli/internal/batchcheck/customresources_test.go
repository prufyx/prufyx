// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestBatchNeverPassesCustomResourceRules: a CNCF batch item evaluates every
// rule of its project. A pass of a rule that reads a custom-resource version
// set counts as unknown, so such an item never passes and the batch never
// exits 0 for it; a blocker over the set still blocks.
func TestBatchNeverPassesCustomResourceRules(t *testing.T) {
	setFact := []constraintengine.RequiredFact{{Side: "proposed", Component: "pkg:github/strimzi/strimzi-kafka-operator", FactID: "component.strimzi.custom_resource_versions_set"}}
	otherFact := []constraintengine.RequiredFact{{Side: "proposed", Component: "pkg:github/strimzi/strimzi-kafka-operator", FactID: "component.strimzi.kafka_v1beta2_api_present"}}
	kafka := constraintengine.Claim{RuleID: "kafka", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED", EvidenceFreshness: "current", RequiredFacts: otherFact}
	setPass := constraintengine.Claim{RuleID: "set", Operator: "forbid_set_member", Status: "PASS", ReasonCode: "CRD_VERSION_NOT_SERVED", EvidenceFreshness: "current", RequiredFacts: setFact}
	setBlocked := setPass
	setBlocked.Status = "BLOCKED"
	base := ItemResult{Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	for _, tc := range []struct {
		name              string
		claims            []constraintengine.Claim
		category, outcome string
		reason            string
		exit              int
	}{
		{"other rule passes", []constraintengine.Claim{kafka}, "PASS", "PASS", "SCOPED_CLAIMS_PASS", 0},
		{"set rule passes", []constraintengine.Claim{setPass}, "UNKNOWN_CLAIM", "UNKNOWN", "SCOPED_CLAIM_UNKNOWN", 11},
		{"both pass", []constraintengine.Claim{kafka, setPass}, "UNKNOWN_CLAIM", "UNKNOWN", "SCOPED_CLAIM_UNKNOWN", 11},
		{"set rule blocks", []constraintengine.Claim{kafka, setBlocked}, "BLOCKED", "BLOCKED", "CRD_VERSION_NOT_SERVED", 10},
	} {
		result := fromClaims(base, cncfClaimViews(tc.claims))
		if result.Category != tc.category || result.Outcome != tc.outcome || result.ReasonCode != tc.reason {
			t.Fatalf("%s: %s/%s/%s", tc.name, result.Category, result.Outcome, result.ReasonCode)
		}
		if _, exit := aggregate([]ItemResult{result}); exit != tc.exit {
			t.Fatalf("%s: exit=%d", tc.name, exit)
		}
	}
}
