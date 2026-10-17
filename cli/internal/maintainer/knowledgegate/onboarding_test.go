// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"
)

func TestOnboardingBatchAdmits(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	c, ok := check(r, CheckOnboarding)
	if !ok || !c.OK || !strings.Contains(c.Detail, "admits 1 projects") {
		t.Fatalf("onboarding check %+v", c)
	}
	members := 0
	for _, ch := range r.Changes {
		if ch.Member != "" {
			members++
			if !ch.OK || ch.Proof != ProofOnboarding {
				t.Fatalf("member change %+v", ch)
			}
		}
	}
	if members != 1 || len(r.Changes) != 1 {
		t.Fatalf("changes %+v", r.Changes)
	}
	if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, ";"), "onboarding batch") {
		t.Fatalf("auto merge %+v", r.AutoMerge)
	}
	if !strings.Contains(strings.Join(r.Alarms, ";"), "onboarding batch (admitted)") {
		t.Fatalf("alarms %v", r.Alarms)
	}
	if r.onboarding.restRequests[obSlug] == 0 || r.onboarding.restRequests[obSlug] > OnboardingRESTBudget {
		t.Fatalf("rest requests %v", r.onboarding.restRequests)
	}
}

// Without a batch the same data-only change fails as it does on main: the
// base's code admits the pack only against its own table, and refuses the
// moved pack members.
func TestOnboardingChangeWithoutBatchFails(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	r := f.gate(t)
	requireFail(t, r, "admit/cncf")
	requireFail(t, r, "attestation/cncf")
	for _, ch := range r.Changes {
		if ch.Member != "" && ch.OK {
			t.Fatalf("member change admitted without a batch: %+v", ch)
		}
	}
}
