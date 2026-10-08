// SPDX-License-Identifier: AGPL-3.0-only

package supersedefixture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

func shipped(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The fixture's 25 entries are the reviewed rules, one for each reviewed id.
func TestFixtureHoldsTheReviewedRules(t *testing.T) {
	want := map[string]bool{}
	for _, id := range supersedeids.ReviewedIDs() {
		want[id] = true
	}
	entries := ReviewedEntries()
	if len(entries) != 25 {
		t.Fatalf("%d entries", len(entries))
	}
	for _, raw := range entries {
		id, err := ruleID(raw)
		if err != nil || !want[id] {
			t.Fatalf("entry %q: %v", id, err)
		}
		delete(want, id)
	}
}

// Reviewed restores the reviewed generation from either generation and is a
// fixed point; on the reviewed pack it changes nothing.
func TestReviewedRestoresTheReviewedGeneration(t *testing.T) {
	out, err := Reviewed(shipped(t))
	if err != nil {
		t.Fatal(err)
	}
	if superseded, err := supersedeids.Generation(out); err != nil || superseded {
		t.Fatalf("generation %v err %v", superseded, err)
	}
	again, err := Reviewed(out)
	if err != nil || string(again) != string(out) {
		t.Fatalf("not a fixed point: %v", err)
	}
	if !supersedeids.Superseded() && string(out) != string(shipped(t)) {
		t.Fatal("the reviewed shipped pack was changed")
	}
}
