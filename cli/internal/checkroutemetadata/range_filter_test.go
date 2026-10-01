// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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

// publishedMatches counts the embedded Kubernetes rules whose subject matches a
// pair through the shared matcher, so the expectations follow the pack as
// reviewed rules are added to a line.
func publishedMatches(t *testing.T, from, to string) int {
	t.Helper()
	identities, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range identities {
		if item.Project == "kubernetes" && item.Transition().Match(from, to) != constraintengine.MatchNone {
			count++
		}
	}
	return count
}

// TestDiscoverPatchPairOnRangedPack: with the published Kubernetes removal
// ranges, an off-anchor patch pair on a reviewed line, such as
// 1.24.17 -> 1.25.3, matches exactly the rules the anchor pair itself matches,
// each disclosing its range match; the anchor pair's own checks are
// unaffected. The exact-only 1.32 flow-control rule never matches off its
// anchor, and a pair on a line with no reviewed rule finds none.
func TestDiscoverPatchPairOnRangedPack(t *testing.T) {
	want := publishedMatches(t, "1.24.17", "1.25.3")
	if want < 7 {
		t.Fatalf("published matches=%d, want at least the seven API removals", want)
	}
	patch, err := Discover("kubernetes", "1.24.17", "1.25.3")
	if err != nil {
		t.Fatal(err)
	}
	if patch.RuleCoverageState != "MATCHED" || len(patch.Checks) != want {
		t.Fatalf("patch pair checks=%d, want %d: %+v", len(patch.Checks), want, patch)
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
	if anchorWant := publishedMatches(t, "1.24.0", "1.25.0"); anchor.RuleCoverageState != "MATCHED" || len(anchor.Checks) != anchorWant || anchorWant != want {
		t.Fatalf("anchor checks=%d, want %d (patch pair %d)", len(anchor.Checks), anchorWant, want)
	}
	for _, check := range anchor.Checks {
		if check.Range == nil {
			t.Fatalf("anchor check missing its published range: %+v", check)
		}
	}
	// The exact-only flow-control rule never matches off its anchor.
	offAnchor, err := Discover("kubernetes", "1.31.17", "1.32.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(offAnchor.Checks) != publishedMatches(t, "1.31.17", "1.32.3") {
		t.Fatalf("1.32 off-anchor pair=%+v", offAnchor)
	}
	for _, check := range offAnchor.Checks {
		if check.RuleID == "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0" || check.Range == nil {
			t.Fatalf("flow-control off-anchor pair=%+v", offAnchor)
		}
	}
	// A pair that matches no published rule reports no matching rule, always.
	for _, pair := range [][2]string{{"1.31.17", "1.32.3"}, {"1.5.2", "1.6.1"}, {"1.40.1", "1.41.0"}} {
		result, err := Discover("kubernetes", pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if publishedMatches(t, pair[0], pair[1]) == 0 && (result.RuleCoverageState != "NO_MATCHING_EMBEDDED_RULE" || len(result.Checks) != 0) {
			t.Fatalf("pair %v with no rule=%+v", pair, result)
		}
	}
	none, err := Discover("kubernetes", "1.5.2", "1.6.1")
	if err != nil {
		t.Fatal(err)
	}
	if publishedMatches(t, "1.5.2", "1.6.1") != 0 || none.RuleCoverageState != "NO_MATCHING_EMBEDDED_RULE" {
		t.Fatalf("expected a pair with no published rule: %+v", none)
	}
}
