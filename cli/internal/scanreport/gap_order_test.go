// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"reflect"
	"testing"
)

// TestGapOrderIsTotal: gaps that differ only in their hop reference's from,
// to, index or whole-upgrade flag (with the same sort order) still sort the
// same whatever the input order, and an exact duplicate among them is
// removed even when another gap was between the two copies.
func TestGapOrderIsTotal(t *testing.T) {
	gap := func(hop *HopRef) Gap {
		return Gap{Component: "kubernetes", Hop: hop, Reason: "RULE_COVERAGE_MISSING", Detail: "d", Action: "a"}
	}
	x := &HopRef{Index: 1, From: "1.24.0", To: "1.25"}
	y := &HopRef{Index: 1, From: "1.24.0", To: "1.26"}
	z := &HopRef{Index: 1, From: "1.23.0", To: "1.26"}
	want := []Gap{gap(z), gap(x), gap(y)}
	for _, order := range [][]Gap{
		{gap(x), gap(y), gap(z)},
		{gap(y), gap(z), gap(x)},
		{gap(z), gap(y), gap(x), gap(&HopRef{Index: 1, From: "1.24.0", To: "1.25"})},
		{gap(x), gap(y), gap(&HopRef{Index: 1, From: "1.24.0", To: "1.25"}), gap(z)},
	} {
		report := Report{Gaps: order}
		Finalize(&report)
		if !reflect.DeepEqual(report.Gaps, want) {
			t.Fatalf("input %+v gave %+v", order, report.Gaps)
		}
	}
	if !hopRefLess(nil, x) || hopRefLess(x, nil) || hopRefLess(nil, nil) || hopRefLess(x, x) {
		t.Fatal("nil and equal hop references")
	}
	if !hopRefLess(&HopRef{Index: 2, From: "1", To: "2"}, &HopRef{Index: 2, From: "1", To: "2", WholeUpgrade: true}) {
		t.Fatal("whole-upgrade flag tie-break")
	}
}
