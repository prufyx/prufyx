// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"testing"
	"time"
)

func TestPrometheusRefreshEvidenceBoundaryStaysUnknown(t *testing.T) {
	wantRules := map[string]bool{
		"prometheus.alertmanager-api-v1-removed.2-55-1-to-3-14-0":           true,
		"prometheus.scrape-classic-histograms-key-renamed.2-55-1-to-3-14-0": true,
	}
	seen := map[string]bool{}
	for _, vector := range reviewedVectors(t) {
		if !wantRules[vector.RuleID] {
			continue
		}
		var input []byte
		for _, scenario := range vector.Cases {
			if scenario.Name == "pass" {
				input = scenario.Input
				break
			}
		}
		if len(input) == 0 {
			t.Fatalf("%s has no pass input", vector.RuleID)
		}
		before := time.Date(2026, 9, 12, 17, 28, 3, 0, time.UTC)
		fresh, err := Check(vector.Project, input, before)
		if err != nil {
			t.Fatalf("%s fresh check: %v", vector.RuleID, err)
		}
		var validUntil, reviewedAt time.Time
		for _, claim := range fresh.Check.Claims {
			if claim.RuleID == vector.RuleID {
				validUntil, err = time.Parse(time.RFC3339, claim.EvidenceValidUntil)
				if err != nil {
					t.Fatalf("%s validUntil: %v", vector.RuleID, err)
				}
				reviewedAt, err = time.Parse(time.RFC3339, claim.EvidenceReviewedAt)
				if err != nil {
					t.Fatalf("%s reviewedAt: %v", vector.RuleID, err)
				}
				break
			}
		}
		if validUntil.IsZero() || reviewedAt.IsZero() {
			t.Fatalf("%s fresh claim missing evidence window", vector.RuleID)
		}
		for _, tc := range []struct {
			name   string
			now    time.Time
			reason string
		}{
			{"at-valid-until", validUntil, "RULE_EVIDENCE_STALE"},
			{"before-reviewed-at", reviewedAt.Add(-time.Second), "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW"},
		} {
			report, checkErr := Check(vector.Project, input, tc.now)
			if checkErr != nil {
				t.Fatalf("%s %s: %v", vector.RuleID, tc.name, checkErr)
			}
			found := false
			for _, claim := range report.Check.Claims {
				if claim.RuleID != vector.RuleID {
					continue
				}
				found = true
				if claim.Status != "UNKNOWN" || claim.ReasonCode != tc.reason {
					t.Fatalf("%s %s claim=%+v", vector.RuleID, tc.name, claim)
				}
			}
			if !found || report.Assessment != "UNKNOWN" || report.Check.Assessment != "UNKNOWN" {
				t.Fatalf("%s %s did not remain unknown", vector.RuleID, tc.name)
			}
		}
		seen[vector.RuleID] = true
	}
	for ruleID := range wantRules {
		if !seen[ruleID] {
			t.Fatalf("missing vector group %s", ruleID)
		}
	}
}
