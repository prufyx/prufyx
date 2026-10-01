// SPDX-License-Identifier: AGPL-3.0-only

package reviewrecord

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestRangeBoundVectorsRequiredAtEveryBound: a ranged rule's review vectors
// need one deciding vector just inside and one UNKNOWN vector just outside at
// each of the four bounds. Dropping any one of the eight is refused.
func TestRangeBoundVectorsRequiredAtEveryBound(t *testing.T) {
	rng := constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
	complete := []vectorObservation{
		{"1.24.0", "1.25.3", "BLOCKED"},   // from.gte inside
		{"1.23.99", "1.25.3", "UNKNOWN"},  // from.gte outside
		{"1.24.17", "1.25.3", "PASS"},     // from.lt inside
		{"1.25.0", "1.25.3", "UNKNOWN"},   // from.lt outside (crossing semantics)
		{"1.24.17", "1.25.0", "BLOCKED"},  // to.gte inside
		{"1.24.17", "1.24.99", "UNKNOWN"}, // to.gte outside
		{"1.24.17", "1.25.99", "PASS"},    // to.lt inside
		{"1.24.17", "1.26.0", "UNKNOWN"},  // to.lt outside
	}
	if !rangeBoundsCovered(rng, complete) {
		t.Fatal("complete bound vectors refused")
	}
	// Each outside vector is the only witness of its bound.
	for _, index := range []int{1, 3, 5, 7} {
		partial := append(append([]vectorObservation(nil), complete[:index]...), complete[index+1:]...)
		if rangeBoundsCovered(rng, partial) {
			t.Fatalf("missing outside vector %d accepted", index)
		}
	}
	// Deciding vectors only at the anchor leave both lt bounds unwitnessed.
	anchorOnly := []vectorObservation{{"1.24.0", "1.25.0", "BLOCKED"}, {"1.24.0", "1.25.0", "PASS"}, complete[1], complete[3], complete[5], complete[7]}
	if rangeBoundsCovered(rng, anchorOnly) {
		t.Fatal("anchor-only deciding vectors accepted as inside bound vectors")
	}
	// An outside vector that decided is not evidence of the bound.
	wrong := append([]vectorObservation(nil), complete...)
	wrong[7].status = "PASS"
	if rangeBoundsCovered(rng, wrong) {
		t.Fatal("deciding vector accepted as an outside bound vector")
	}
}
