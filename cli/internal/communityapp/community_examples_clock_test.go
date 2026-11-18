// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"testing"
	"time"
)

// A bundled example is evaluated at or after the newest review of its
// project's rules, whatever the fixed time of the example is, and the clock is
// the same every time.
func TestExampleClockIsNeverBeforeTheProjectReview(t *testing.T) {
	for _, project := range []string{"ceph", "nats", "etcd", "kyverno", "opa", "rook", "opentelemetry", "coredns", "envoy"} {
		newest, ok := newestProjectReview(project)
		if !ok {
			t.Fatalf("%s: no embedded rule", project)
		}
		got := exampleClock(project, "2001-01-01T00:00:00Z")
		at, err := time.Parse(time.RFC3339, got)
		if err != nil || at.Before(newest) {
			t.Fatalf("%s: clock %q is before the newest review %s (err %v)", project, got, newest.Format(time.RFC3339), err)
		}
		if again := exampleClock(project, "2001-01-01T00:00:00Z"); again != got {
			t.Fatalf("%s: clock not reproducible: %q then %q", project, got, again)
		}
		// A fixed time after the review is kept as it is.
		later := newest.Add(48 * time.Hour).Format(time.RFC3339)
		if kept := exampleClock(project, later); kept != later {
			t.Fatalf("%s: later fixed time moved to %q", project, kept)
		}
	}
	if got := exampleClock("no-such-project", "2026-09-12T09:20:00Z"); got != "2026-09-12T09:20:00Z" {
		t.Fatalf("unknown project changed the clock: %q", got)
	}
}
