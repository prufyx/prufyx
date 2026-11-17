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

// Dropping an unowned record, or narrowing one, is a removal that needs a
// matching guard entry; keeping or widening one is not.
func TestDiffUnownedRemovals(t *testing.T) {
	rec := func(name string, kinds ...string) customresources.UnownedGroup {
		return customresources.UnownedGroup{Name: name, Kinds: kinds}
	}
	base := Inputs{Unowned: []customresources.UnownedGroup{rec("a.example.io"), rec("b.example.io", "A", "B")}}
	ids := func(head []customresources.UnownedGroup) map[string]bool {
		out := map[string]bool{}
		for _, r := range Diff(base, Inputs{Unowned: head}) {
			if r.Kind == KindUnowned {
				out[r.Project+"|"+r.Detail] = true
			}
		}
		return out
	}
	if got := ids(base.Unowned); len(got) != 0 {
		t.Fatalf("unchanged: %v", got)
	}
	if got := ids([]customresources.UnownedGroup{rec("a.example.io"), rec("b.example.io", "A", "B", "C")}); len(got) != 0 {
		t.Fatalf("widened: %v", got)
	}
	got := ids([]customresources.UnownedGroup{rec("b.example.io", "A", "B")})
	if len(got) != 1 || !got["a.example.io|a.example.io"] {
		t.Fatalf("dropped: %v", got)
	}
	got = ids([]customresources.UnownedGroup{rec("a.example.io"), rec("b.example.io", "A")})
	if len(got) != 1 || !got["b.example.io|b.example.io:narrowed"] {
		t.Fatalf("narrowed: %v", got)
	}
}
