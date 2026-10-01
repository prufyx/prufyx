// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

func TestPrometheusRemoteWriteHTTP2SelectedRule(t *testing.T) {
	trueValue, falseValue := true, false
	tests := []struct {
		name     string
		raw      string
		required *bool
		want     string
	}{
		{"required omitted", "remote_write:\n  - name: primary\n    url: https://example.invalid/write\n", &trueValue, "BLOCKED"},
		{"required explicit true", "remote_write:\n  - name: primary\n    enable_http2: true\n", &trueValue, "PASS"},
		{"not required explicit false", "remote_write:\n  - name: primary\n    enable_http2: false\n", &falseValue, "PASS"},
	}
	now := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := cncfprepare.PreparePrometheusRemoteWriteConfig([]byte(test.raw), "primary", cncfprepare.PrometheusRemoteWriteHTTP2From, cncfprepare.PrometheusRemoteWriteHTTP2To, true, true, test.required)
			if err != nil {
				t.Fatal(err)
			}
			report, err := CheckRule("prometheus", cncfprepare.PrometheusRemoteWriteHTTP2RuleID, prepared.CanonicalInputJSON, now)
			if err != nil {
				t.Fatal(err)
			}
			if report.SelectedRuleID != cncfprepare.PrometheusRemoteWriteHTTP2RuleID || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != test.want || len(report.Check.Claims[0].Sources) != 7 {
				t.Fatalf("selected=%q claims=%+v", report.SelectedRuleID, report.Check.Claims)
			}
		})
	}
}

func TestPrometheusRemoteWriteHTTP2BatchGuardSurvivesMissingFact(t *testing.T) {
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/prometheus/prometheus","version":"2.55.1","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/prometheus/prometheus","version":"3.14.0","facts":[{"id":"component.prometheus.scrape_classic_histograms_key","state":"declared","enumValue":"always_scrape_classic_histograms"}]}]}}`)
	report, err := Check("prometheus", input, time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range report.Check.Claims {
		if claim.RuleID == cncfprepare.PrometheusRemoteWriteHTTP2RuleID {
			if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_FACT_UNAVAILABLE" {
				t.Fatalf("unguarded batch claim: %+v", claim)
			}
			return
		}
	}
	t.Fatal("remote-write rule omitted from batch")
}
