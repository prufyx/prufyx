// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesFlowControlReviewClock_BoundsStaticRule(t *testing.T) {
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.31.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.32.0","facts":[{"id":"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present","state":"declared","boolValue":false}]}]}}`)
	for _, test := range []struct {
		name, now, reason string
	}{
		{"before review", "2026-11-11T23:59:59Z", "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW"},
		{"at expiry", "2027-02-03T00:00:00Z", "RULE_EVIDENCE_STALE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, test.now)
			if err != nil {
				t.Fatal(err)
			}
			// Select the flow-control rule itself: other rules on the same
			// transition need other evidence and are not what this test bounds.
			report, err := CheckRule("kubernetes", "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0", input, now)
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
