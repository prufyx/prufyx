// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
)

// The upstream 2.15 upgrade guide covers migration from 2.12.0 and later only,
// and sends earlier installations to the guide of an earlier release. No
// transition from 2.10 or 2.11 into 2.15 may therefore be decided, whatever the
// input declares.
func TestHarborRulesDecideNothingBelowTwoFifteenSourceFloor(t *testing.T) {
	t.Parallel()
	withdrawn := map[string]string{
		"2.10.3": "harbor.installer-with-chartmuseum-flag-removed.2-10-to-2-15",
		"2.11.2": "harbor.installer-with-chartmuseum-flag-removed.2-11-to-2-15",
	}
	for _, from := range []string{"2.10.0", "2.10.3", "2.11.0", "2.11.2"} {
		for _, to := range []string{"2.15.0", "2.15.2"} {
			for _, present := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", from, to, present), func(t *testing.T) {
					report := checkHarborChartMuseum(t, from, to, present)
					if ClaimExit(report) != 11 {
						t.Fatalf("exit %d, want 11", ClaimExit(report))
					}
					ruleID := ""
					if to == "2.15.2" {
						ruleID = withdrawn[from]
					}
					found := false
					for _, claim := range report.Check.Claims {
						if claim.Status != "UNKNOWN" {
							t.Fatalf("claim %s is %s", claim.RuleID, claim.Status)
						}
						if ruleID != "" && claim.RuleID == ruleID {
							found = true
							if claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
								t.Fatalf("reason %s", claim.ReasonCode)
							}
						}
					}
					if ruleID != "" && !found {
						t.Fatal("withdrawn rule omitted from its own pair")
					}
				})
			}
		}
	}
}

// The origins the 2.15 guide does cover keep their rules.
func TestHarborRulesAtOrAboveTwoFifteenSourceFloorStillDecide(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"2.12.4", "2.13.5", "2.14.4"} {
		for present, want := range map[bool]int{false: 0, true: 10} {
			t.Run(fmt.Sprintf("%s/%t", from, present), func(t *testing.T) {
				if got := ClaimExit(checkHarborChartMuseum(t, from, "2.15.2", present)); got != want {
					t.Fatalf("exit %d, want %d", got, want)
				}
			})
		}
	}
}

func checkHarborChartMuseum(t *testing.T, from, to string, present bool) Report {
	t.Helper()
	input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/goharbor/harbor","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/goharbor/harbor","version":%q,"facts":[{"id":"component.harbor.installer_with_chartmuseum_present","state":"declared","boolValue":%t}]}]}}`, from, to, present)
	report, err := Check("harbor", []byte(input), reviewClock(t))
	if err != nil {
		t.Fatal(err)
	}
	return report
}
