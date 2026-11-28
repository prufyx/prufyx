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
		for _, to := range []string{"3.6.0", "3.6.5"} {
			for _, present := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", from, to, present), func(t *testing.T) {
					input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/etcd-io/etcd","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/etcd-io/etcd","version":%q,"facts":[{"id":"component.etcd.removed_v2_proxy_flags_present","state":"declared","boolValue":%t}]}]}}`, from, to, present)
					report, err := Check("etcd", []byte(input), reviewClock(t))
					if err != nil {
						t.Fatal(err)
					}
					if ClaimExit(report) != 11 {
						t.Fatalf("exit %d, want 11", ClaimExit(report))
					}
					exact := from == "3.5.17" && to == "3.6.0"
					found := false
					for _, claim := range report.Check.Claims {
						if claim.Status != "UNKNOWN" {
							t.Fatalf("claim %s is %s", claim.RuleID, claim.Status)
						}
						if claim.RuleID == ruleID {
							found = true
							if exact && claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
								t.Fatalf("reason %s", claim.ReasonCode)
							}
						}
					}
					if exact && !found {
						t.Fatal("withdrawn rule omitted from its own pair")
					}
				})
			}
		}
	}
}

// The etcd 3.7 upgrade guide requires the running cluster to be v3.6.11 or
// later. The removed-flags rule starts at its reviewed anchor, 3.6.14, so a
// source release below it never passes, even with the removed flags declared
// absent.
func TestEtcdBelowSourceFloorIsNotPass(t *testing.T) {
	const (
		component = "pkg:github/etcd-io/etcd"
		flagRule  = "etcd.experimental-flags-unsupported.3-6-14-to-3-7-1"
	)
	now := mustTime(t, "2026-11-28T00:00:00Z")
	flagsAbsent := func(from, to string) []byte {
		return scopeInput(t, []string{component},
			map[string][2]string{component: {from, to}},
			map[string][]declaredFact{component: {
				boolFact("component.etcd.experimental_flags_present", false),
			}})
	}

	// Control: at this time the same fact passes the rule at the floor, so the
	// refusals below are not an expired rule or a rejected input.
	for _, to := range []string{"3.7.1", "3.7.4"} {
		report, err := Check("etcd", flagsAbsent("3.6.14", to), now)
		if err != nil {
			t.Fatalf("floor to %s: %v", to, err)
		}
		passed := false
		for _, claim := range report.Check.Claims {
			passed = passed || (claim.RuleID == flagRule && claim.Status == "PASS")
		}
		if !passed || ClaimExit(report) != 0 {
			t.Fatalf("floor to %s: pass=%v exit=%d report=%+v", to, passed, ClaimExit(report), report)
		}
	}

	for _, pair := range [][2]string{
		{"3.6.0", "3.7.4"},
		{"3.6.10", "3.7.1"},
		{"3.6.11", "3.7.4"},
		{"3.6.13", "3.7.1"},
		{"3.6.13", "3.7.4"},
	} {
		report, err := Check("etcd", flagsAbsent(pair[0], pair[1]), now)
		if err != nil {
			t.Fatalf("%v: %v", pair, err)
		}
		for _, claim := range report.Check.Claims {
			if claim.Status == "PASS" {
				t.Fatalf("%v: claim %s passes: %+v", pair, claim.RuleID, claim)
			}
		}
		if exit := ClaimExit(report); exit != 11 {
			t.Fatalf("%v: exit=%d report=%+v", pair, exit, report)
		}
	}
}
