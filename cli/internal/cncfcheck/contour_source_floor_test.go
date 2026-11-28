// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
)

// The upstream 1.20.0 upgrade guide requires a Contour older than 1.19.1 to be
// upgraded to 1.19.1 first. No transition from an older release into 1.20 may
// therefore be decided, whatever the input declares.
func TestContourRuleDecidesNothingBelowOneTwentySourceFloor(t *testing.T) {
	t.Parallel()
	const ruleID = "contour.gateway-v1alpha1-removed.1-19-0-to-1-20-0"
	for _, from := range []string{"1.18.3", "1.19.0"} {
		for _, present := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", from, present), func(t *testing.T) {
				input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/projectcontour/contour","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/projectcontour/contour","version":"1.20.0","facts":[{"id":"component.contour.gateway_v1alpha1_present","state":"declared","boolValue":%t}]}]}}`, from, present)
				report, err := Check("contour", []byte(input), reviewClock(t))
				if err != nil {
					t.Fatal(err)
				}
				if ClaimExit(report) != 11 {
					t.Fatalf("exit %d, want 11", ClaimExit(report))
				}
				found := false
				for _, claim := range report.Check.Claims {
					if claim.Status != "UNKNOWN" {
						t.Fatalf("claim %s is %s", claim.RuleID, claim.Status)
					}
					if claim.RuleID == ruleID {
						found = true
						if from == "1.19.0" && claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
							t.Fatalf("reason %s", claim.ReasonCode)
						}
					}
				}
				if from == "1.19.0" && !found {
					t.Fatal("withdrawn rule omitted from its own pair")
				}
			})
		}
	}
}
