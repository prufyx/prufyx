// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// The native check route labels no pre-release, so a report decided on one
// never exits 0, while a release pair with the same manifest still passes and
// a blocker still blocks.
func TestClaimExitNeverPassesAPreRelease(t *testing.T) {
	t.Parallel()
	served := []byte(`{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"c"}}`)
	removed := []byte(`{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"c"}}`)
	now := supersedeids.Clock()
	for _, c := range []struct {
		name, from, to string
		raw            []byte
		want           int
	}{
		{"release pair passes", "1.24.17", "1.25.0", served, 0},
		{"pre-release target", "1.24.17", "1.25.0-rc.1", served, 11},
		{"pre-release origin", "1.24.0-alpha.1", "1.25.0", served, 11},
		{"pre-release target with a blocker", "1.24.17", "1.25.0-rc.1", removed, 10},
	} {
		prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(c.raw, c.from, c.to, "official_upstream", true, true)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		facts := cncfprepare.KubernetesRemovedAPIAllFacts()
		report, err := CheckFacts("kubernetes", facts, prepared.CanonicalInputJSON, now)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := ClaimExit(report); got != c.want {
			t.Errorf("%s: exit %d, want %d (claims %d)", c.name, got, c.want, len(report.Check.Claims))
		}
	}
}
