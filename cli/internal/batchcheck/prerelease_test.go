// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// Batch labels no pre-release, so an item decided on one is never a PASS,
// while a release pair with the same manifest passes and a blocker blocks.
func TestItemNeverPassesAPreRelease(t *testing.T) {
	t.Parallel()
	served := []byte(`{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"c"}}`)
	removed := []byte(`{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"c"}}`)
	now := supersedeids.Clock()
	for _, c := range []struct {
		name, from, to, outcome string
		raw                     []byte
	}{
		{"release pair passes", "1.24.17", "1.25.0", "PASS", served},
		{"pre-release target", "1.24.17", "1.25.0-rc.1", "UNKNOWN", served},
		{"pre-release origin", "1.24.0-alpha.1", "1.25.0", "UNKNOWN", served},
		{"pre-release target with a blocker", "1.24.17", "1.25.0-rc.1", "BLOCKED", removed},
	} {
		prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(c.raw, c.from, c.to, "official_upstream", true, true)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		result := evaluateItem(Item{Kind: "cncf", Project: "kubernetes", From: c.from, To: c.to}, prepared.CanonicalInputJSON, now, knowledge.VerifiedRevision{})
		if result.Outcome != c.outcome {
			t.Errorf("%s: outcome %s (%s), want %s", c.name, result.Outcome, result.ReasonCode, c.outcome)
		}
	}
}
