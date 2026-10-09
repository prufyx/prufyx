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
