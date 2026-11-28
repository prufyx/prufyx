// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
)

// The upstream upgrade guide says to update to the latest patch release of the
// current minor before an upgrade. Neither of these origins is that release, so
// no rule may decide these two pairs, whatever the input declares.
func TestCiliumRequiresRulesDecideNothingFromOlderPatches(t *testing.T) {
	t.Parallel()
	for _, pair := range []struct{ from, to, ruleID string }{
		{"1.18.6", "1.19.0", "cilium.nonempty-requires-rejected.1-19"},
		{"1.18.13", "1.19.7", "cilium.nonempty-requires-crd-maxitems.1-18-13-to-1-19-7"},
	} {
		for _, present := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/%t", pair.from, pair.to, present), func(t *testing.T) {
				input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/cilium/cilium","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/cilium/cilium","version":%q,"facts":[{"id":"component.cilium.nonempty_requires_fields","state":"declared","boolValue":%t}]}]}}`, pair.from, pair.to, present)
				report, err := Check("cilium", []byte(input), reviewClock(t))
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
					if claim.RuleID == pair.ruleID {
						found = true
						if claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
							t.Fatalf("reason %s", claim.ReasonCode)
						}
					}
				}
				if !found {
					t.Fatal("withdrawn rule omitted from its own pair")
				}
			})
		}
	}
}
