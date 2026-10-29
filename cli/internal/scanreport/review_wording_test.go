// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"strings"
	"testing"
)

// "partially evaluated" is said only when something was evaluated.
func TestCheckedLineSaysNothingEvaluatedWhenNothingRan(t *testing.T) {
	report := Report{Verdict: VerdictUnknown}
	report.Summary = Summary{ComponentsDetected: 1, ComponentsWithRules: 0, Hops: 0}
	line := checkedLine(report)
	if !strings.Contains(line, "(nothing evaluated)") || strings.Contains(line, "partially") {
		t.Fatalf("line=%q", line)
	}
	report.Summary = Summary{ComponentsDetected: 1, ComponentsWithRules: 1, Hops: 2}
	if line := checkedLine(report); !strings.Contains(line, "(partially evaluated)") {
		t.Fatalf("line=%q", line)
	}
}

// A gap's fingerprint does not depend on the counts in its detail, and two
// gaps with the same rule, component and hop still differ.
func TestGapFingerprintIgnoresDetailAndStaysUnique(t *testing.T) {
	first, second := map[string]int{}, map[string]int{}
	a := gapFingerprint("prufyx/gap/X", "kubernetes", "1.24->1.25", first)
	b := gapFingerprint("prufyx/gap/X", "kubernetes", "1.24->1.25", first)
	if a == b {
		t.Fatal("two gaps with the same key share a fingerprint")
	}
	if a != gapFingerprint("prufyx/gap/X", "kubernetes", "1.24->1.25", second) {
		t.Fatal("the fingerprint changed between runs")
	}
}

// A family PASS on a component without rules is something evaluated: the
// headline and the checked line must not say that nothing ran, and the
// verdict stays UNKNOWN.
func TestFamilyPassOnUncoveredComponentCountsAsEvaluated(t *testing.T) {
	gap := NewGap("kubeswift", nil, GapDeclarationScope, "kubernetes")
	build := func(families []FamilyResult) Report {
		report := Report{
			Inventory: []Component{{Name: "kubeswift"}},
			Paths:     []Path{{Component: "kubeswift", Hops: []Hop{{Index: 1, Status: "PARTIAL", Families: families}}}},
			Gaps:      []Gap{gap},
		}
		Finalize(&report)
		return report
	}
	report := build([]FamilyResult{{Family: "crd.custom_resource_versions", Line: "0.20", Status: FamilyPass, Basis: "mechanical"}})
	if report.Verdict != VerdictUnknown || report.Summary.ComponentsWithRules != 0 {
		t.Fatalf("verdict=%s withRules=%d", report.Verdict, report.Summary.ComponentsWithRules)
	}
	if want := "UNKNOWN: no blocker in the checks that ran; 1 area was not checked (see NOT CHECKED)"; report.Headline != want {
		t.Fatalf("headline=%q", report.Headline)
	}
	if line := checkedLine(report); strings.Contains(line, "nothing evaluated") || !strings.Contains(line, "(partially evaluated)") {
		t.Fatalf("line=%q", line)
	}
	// No family result: nothing ran, old wording stays.
	report = build(nil)
	if !strings.Contains(report.Headline, "nothing could be evaluated") || !strings.Contains(checkedLine(report), "(nothing evaluated)") {
		t.Fatalf("headline=%q line=%q", report.Headline, checkedLine(report))
	}
}
