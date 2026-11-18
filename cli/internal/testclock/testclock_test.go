// SPDX-License-Identifier: AGPL-3.0-only

package testclock

import (
	"testing"
	"time"
)

func TestFloorOnlyMovesEarlierClocksForward(t *testing.T) {
	n := Newest()
	if got := Floor(n.Add(-24 * time.Hour)); !got.Equal(n) {
		t.Fatalf("earlier clock = %s want %s", got, n)
	}
	later := n.Add(48 * time.Hour)
	if got := Floor(later); !got.Equal(later) {
		t.Fatalf("later clock moved: %s", got)
	}
	if got := FloorText("not a time"); got != "not a time" {
		t.Fatalf("unparsable text changed: %q", got)
	}
	if got := FloorText("2001-01-01T00:00:00Z"); got != n.Format(time.RFC3339) {
		t.Fatalf("text floor = %q", got)
	}
}
