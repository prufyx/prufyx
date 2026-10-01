// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestProjectFilterUsesTheSharedMatcher: version filters select by anchor or
// reviewed range, never by a separate string comparison.
func TestProjectFilterUsesTheSharedMatcher(t *testing.T) {
	exact := constraintengine.RuleTransition{Component: "pkg:github/kubernetes/kubernetes", From: "1.24.0", To: "1.25.0"}
	ranged := exact
	ranged.Range = &constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
	cases := []struct {
		name, project, from, to string
		subject                 constraintengine.RuleTransition
		excluded                bool
	}{
		{"no filter", "", "", "", exact, false},
		{"other project", "etcd", "", "", exact, true},
		{"exact anchor", "kubernetes", "1.24.0", "1.25.0", exact, false},
		{"exact patch pair", "kubernetes", "1.24.17", "1.25.3", exact, true},
		{"ranged patch pair", "kubernetes", "1.24.17", "1.25.3", ranged, false},
		{"ranged crossing violation", "kubernetes", "1.25.1", "1.25.4", ranged, true},
		{"ranged from only", "kubernetes", "1.24.17", "", ranged, false},
		{"exact from only", "kubernetes", "1.24.17", "", exact, true},
		{"ranged to only outside", "kubernetes", "", "1.26.0", ranged, true},
	}
	for _, tc := range cases {
		if got := projectFilter(tc.project, tc.from, tc.to, "kubernetes", tc.subject); got != tc.excluded {
			t.Errorf("%s: excluded=%v want %v", tc.name, got, tc.excluded)
		}
	}
}

// TestDiscoverPatchPairOnRangedPack: with the published Kubernetes removal
// ranges, an off-anchor patch pair on a reviewed line, such as
// 1.24.17 -> 1.25.3, now matches the same rules as the anchor pair itself (at
// least the seven API removals), each disclosing its range match; the anchor
// pair's own checks are unaffected. The exact-only 1.32 flow-control rule
// still never matches off its anchor.
func TestDiscoverPatchPairOnRangedPack(t *testing.T) {
	patch, err := Discover("kubernetes", "1.24.17", "1.25.3")
	if err != nil {
		t.Fatal(err)
	}
	if patch.RuleCoverageState != "MATCHED" || len(patch.Checks) < 7 {
		t.Fatalf("patch pair=%+v", patch)
	}
	for _, check := range patch.Checks {
		if check.Range == nil || check.MatchMode != "range" {
			t.Fatalf("ranged check missing range fields: %+v", check)
		}
	}
	anchor, err := Discover("kubernetes", "1.24.0", "1.25.0")
	if err != nil {
		t.Fatal(err)
	}
	if anchor.RuleCoverageState != "MATCHED" || len(anchor.Checks) != len(patch.Checks) {
		t.Fatalf("anchor checks=%d, patch checks=%d", len(anchor.Checks), len(patch.Checks))
	}
	for _, check := range anchor.Checks {
		if check.Range == nil {
			t.Fatalf("anchor check missing its published range: %+v", check)
		}
	}
	noRule, err := Discover("kubernetes", "1.31.17", "1.32.3")
	if err != nil {
		t.Fatal(err)
	}
	// The exact-only flow-control rule never matches off its anchor; other
	// ranged rules on the 1.32 line may.
	for _, check := range noRule.Checks {
		if check.RuleID == "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0" || check.Range == nil {
			t.Fatalf("flow-control off-anchor pair=%+v", noRule)
		}
	}
	if len(noRule.Checks) == 0 && noRule.RuleCoverageState != "NO_MATCHING_EMBEDDED_RULE" {
		t.Fatalf("flow-control off-anchor pair=%+v", noRule)
	}
}
