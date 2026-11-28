// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
)

// The upstream 3.6 upgrade guide requires every 3.5 member to run a later patch
// release than the one the removed v2/proxy rule was anchored to. No transition
// into 3.6 may therefore be decided by that rule, whatever the input declares.
func TestEtcdV2ProxyRuleDecidesNothingIntoThreeSix(t *testing.T) {
	t.Parallel()
	const ruleID = "etcd.v2-proxy-flags-removed.3-6"
	for _, from := range []string{"3.5.0", "3.5.17", "3.5.19", "3.5.31", "3.5.32"} {
		for _, present := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", from, present), func(t *testing.T) {
				input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/etcd-io/etcd","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/etcd-io/etcd","version":"3.6.0","facts":[{"id":"component.etcd.removed_v2_proxy_flags_present","state":"declared","boolValue":%t}]}]}}`, from, present)
				report, err := Check("etcd", []byte(input), reviewClock(t))
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
						if from == "3.5.17" && claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
							t.Fatalf("reason %s", claim.ReasonCode)
						}
					}
				}
				if from == "3.5.17" && !found {
					t.Fatal("withdrawn rule omitted from its own pair")
				}
			})
		}
	}
}
