package cncfcheck

import "testing"

// The containerd shim rule covers one exact pair. A reviewed answer about the
// CRI API alone must therefore not pass an upgrade next to that pair: the CRI
// rule stays exact, so declaring only cri_api=v1 never passes off the pair.
func TestContainerdCRIOnlyOffExactPairIsNotPass(t *testing.T) {
	const criRule = "containerd.cri-v1alpha2-removed.2-0"
	now := mustTime(t, "2026-11-28T00:00:00Z")
	criOnly := func(from, to string) []byte {
		return scopeInput(t, []string{containerdComponent},
			map[string][2]string{containerdComponent: {from, to}},
			map[string][]declaredFact{containerdComponent: {
				enumFact("component.containerd.cri_api", "v1"),
			}})
	}

	// Control: at this time the same facts do pass the CRI rule on its own
	// pair, so the refusal below is not an expired rule or a rejected input.
	anchor, err := Check("containerd", criOnly("1.7.28", "2.0.0"), now)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	passed := false
	for _, claim := range anchor.Check.Claims {
		passed = passed || (claim.RuleID == criRule && claim.Status == "PASS")
	}
	if !passed || ClaimExit(anchor) == 0 {
		t.Fatalf("anchor: cri pass=%v exit=%d report=%+v", passed, ClaimExit(anchor), anchor)
	}

	report, err := Check("containerd", criOnly("1.7.30", "2.0.5"), now)
	if err != nil {
		t.Fatalf("off the pair: %v", err)
	}
	for _, claim := range report.Check.Claims {
		if claim.Status == "PASS" {
			t.Fatalf("off the pair: claim %s passes: %+v", claim.RuleID, claim)
		}
	}
	if exit := ClaimExit(report); exit != 11 {
		t.Fatalf("off the pair: exit=%d report=%+v", exit, report)
	}
}
