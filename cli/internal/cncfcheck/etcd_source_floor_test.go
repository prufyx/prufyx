package cncfcheck

import "testing"

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
