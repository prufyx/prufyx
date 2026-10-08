// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

func TestKubernetesFlowControlReviewClock_BoundsStaticRule(t *testing.T) {
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.31.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.32.0","facts":[{"id":"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present","state":"declared","boolValue":false}]}]}}`)
	// The bounds are the rule's own: one second before its review, and its
	// expiry instant.
	const id = "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0"
	reviewed, until := ruleEvidenceBounds(t, supersedeids.ID(id))
	for _, test := range []struct {
		name   string
		now    time.Time
		reason string
	}{
		{"before review", reviewed.Add(-time.Second), "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW"},
		{"at expiry", until, "RULE_EVIDENCE_STALE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := test.now
			// Select the flow-control rule itself: other rules on the same
			// transition need other evidence and are not what this test bounds.
			report, err := CheckRule("kubernetes", supersedeids.ID(id), input, now)
			if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" || report.Check.Claims[0].ReasonCode != test.reason {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			encoded, err := MarshalReport(report)
			if err != nil || strings.Contains(string(encoded), "FlowSchema") {
				t.Fatalf("report leaked raw input or was unmarshalable: %q err=%v", encoded, err)
			}
		})
	}
}

// ruleEvidenceBounds returns the reviewedAt and validUntil of the embedded
// pack's rule.
func ruleEvidenceBounds(t *testing.T, ruleID string) (reviewed, until time.Time) {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range b.pack.Entries {
		var rule struct {
			ID       string `json:"id"`
			Evidence struct {
				ReviewedAt string `json:"reviewedAt"`
				ValidUntil string `json:"validUntil"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(entry.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		if rule.ID != ruleID {
			continue
		}
		if reviewed, err = time.Parse(time.RFC3339, rule.Evidence.ReviewedAt); err != nil {
			t.Fatal(err)
		}
		if until, err = time.Parse(time.RFC3339, rule.Evidence.ValidUntil); err != nil {
			t.Fatal(err)
		}
		return reviewed, until
	}
	t.Fatalf("rule %s is not in the pack", ruleID)
	return
}
