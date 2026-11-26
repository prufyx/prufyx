// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// assertRangeClaim requires the report to hold exactly one claim of the
// covering rule, with the given status, matched through the rule's reviewed
// range and not its exact anchor pair.
func assertRangeClaim(t *testing.T, stdout, ruleID, status string) {
	t.Helper()
	var report struct {
		Check struct {
			Claims []struct {
				RuleID       string                         `json:"ruleId"`
				Status       string                         `json:"status"`
				SubjectMatch *constraintengine.SubjectMatch `json:"subjectMatch"`
			} `json:"claims"`
		} `json:"check"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report: %v: %s", err, stdout)
	}
	found := 0
	for _, claim := range report.Check.Claims {
		if claim.RuleID != ruleID {
			continue
		}
		found++
		if claim.Status != status || claim.SubjectMatch == nil || claim.SubjectMatch.Mode != "range" {
			t.Fatalf("rule %s is not a %s range match: %s", ruleID, status, stdout)
		}
	}
	if found != 1 {
		t.Fatalf("rule %s has %d claims, want 1: %s", ruleID, found, stdout)
	}
}
