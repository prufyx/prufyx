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

func TestProjectNewestIsPerProjectAndNeverAfterThePackNewest(t *testing.T) {
	cilium := ProjectNewest("cilium")
	if cilium.IsZero() || cilium.After(Newest()) {
		t.Fatalf("cilium newest %s, pack newest %s", cilium, Newest())
	}
	if !ProjectNewest("no-such-project").IsZero() {
		t.Fatal("unknown project has a clock")
	}
	early := "2001-01-01T00:00:00Z"
	if got := FloorTextFor("cilium", early); got != cilium.Format(time.RFC3339) {
		t.Fatalf("floor = %q", got)
	}
	if got := FloorTextFor("no-such-project", early); got != early {
		t.Fatalf("unknown project floor = %q", got)
	}
	later := cilium.Add(48 * time.Hour).Format(time.RFC3339)
	if got := FloorTextFor("cilium", later); got != later {
		t.Fatalf("later clock moved: %q", got)
	}
}
