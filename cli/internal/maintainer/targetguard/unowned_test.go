// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// A record that covers fewer kinds than before is a removal; one that covers
// the same or more is not.
func TestUnownedCovers(t *testing.T) {
	rec := func(kinds ...string) customresources.UnownedGroup {
		return customresources.UnownedGroup{Name: "g.example.io", Kinds: kinds}
	}
	whole := customresources.UnownedGroup{Name: "g.example.io"}
	for _, tc := range []struct {
		name       string
		head, base customresources.UnownedGroup
		want       bool
	}{
		{"same kinds", rec("A", "B"), rec("A", "B"), true},
		{"more kinds", rec("A", "B", "C"), rec("A", "B"), true},
		{"fewer kinds", rec("A"), rec("A", "B"), false},
		{"other kinds", rec("C"), rec("A", "B"), false},
		{"whole group over kinds", whole, rec("A", "B"), true},
		{"kinds over whole group", rec("A", "B"), whole, false},
		{"whole over whole", whole, whole, true},
	} {
		if got := unownedCovers(tc.head, tc.base); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
