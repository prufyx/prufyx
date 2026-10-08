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

// TestCrossingIsCarriedThroughTheCatalogue: a crossing rule keeps its crossing
// on the catalogue check and on the identity's subject, so route discovery
// lists it for a multi-minor --from/--to pair and reports matchMode crossing.
// Before the crossing was carried the subject lost it and the filter dropped
// the rule.
func TestCrossingIsCarriedThroughTheCatalogue(t *testing.T) {
	spec := &constraintengine.CrossingSpec{
		Change:  constraintengine.CrossingChange{Version: "1.25.0", Basis: constraintengine.BasisRemovedInRelease, SourceID: "src"},
		Horizon: constraintengine.CrossingHorizon{Lt: "1.36.0", Basis: constraintengine.BasisReviewedThroughMinorLine, SourceID: "src"},
	}
	check := Check{Component: "pkg:github/kubernetes/kubernetes", From: "1.24.0", To: "1.25.0", Crossing: spec}
	subject := check.Transition()
	if subject.Crossing != spec {
		t.Fatal("Check.Transition dropped the crossing")
	}
	identity := cncfcheck.RuleIdentity{Component: check.Component, From: check.From, To: check.To, Crossing: spec}
	if identity.Transition().Crossing != spec {
		t.Fatal("RuleIdentity.Transition dropped the crossing")
	}
	cases := []struct {
		name, from, to, mode string
		excluded             bool
	}{
		{"multi-minor pair across C", "1.21.0", "1.30.0", "crossing", false},
		{"patch pair across C", "1.24.17", "1.25.3", "crossing", false},
		{"pair below C", "1.21.0", "1.24.9", "", true},
		// Beyond the horizon the hop still crosses C: listed as unreviewed.
		{"pair at the cap", "1.21.0", "1.36.0", constraintengine.MatchModeBoundaryUnreviewed, false},
		{"pair past C", "1.26.0", "1.30.0", "", true},
		{"anchor", "1.24.0", "1.25.0", "", false},
	}
	for _, tc := range cases {
		if got := projectFilter("kubernetes", tc.from, tc.to, "kubernetes", subject); got != tc.excluded {
			t.Errorf("%s: excluded=%v want %v", tc.name, got, tc.excluded)
		}
		if got := queryMatchMode(subject, tc.from, tc.to); got != tc.mode {
			t.Errorf("%s: matchMode=%q want %q", tc.name, got, tc.mode)
		}
	}
	// Without the crossing the same multi-minor pair is not listed.
	plain := Check{Component: check.Component, From: check.From, To: check.To}.Transition()
	if !projectFilter("kubernetes", "1.21.0", "1.30.0", "kubernetes", plain) {
		t.Error("a rule without a crossing listed a multi-minor pair")
	}
}

// releaseBoundaryRange is a release-boundary range (C = 1.25.0): both
// boundary bounds cite a release, so the engine knows the boundary.
func releaseBoundaryRange() *constraintengine.VersionRange {
	return &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"},
		To:   constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"},
		Bounds: []constraintengine.RangeBound{
			{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: "s"},
			{Bound: "from.lt", Basis: constraintengine.BasisRemovedInRelease, SourceID: "s"},
			{Bound: "to.gte", Basis: constraintengine.BasisRemovedInRelease, SourceID: "s"},
			{Bound: "to.lt", Basis: constraintengine.BasisReviewedThroughMinorLine, SourceID: "s"},
		},
	}
}

// TestBoundaryUnreviewedIsListedNotHidden: a ranged rule whose range pins a
// release boundary is listed, with matchMode boundary-unreviewed, for a pair
// that crosses the boundary outside the range, and stays hidden for a pair
// that does not cross it.
func TestBoundaryUnreviewedIsListedNotHidden(t *testing.T) {
	ranged := Check{Component: "pkg:github/kubernetes/kubernetes", From: "1.24.0", To: "1.25.0", Range: releaseBoundaryRange()}.Transition()
	// A range with no release basis pins no boundary the engine knows.
	series := releaseBoundaryRange()
	series.Bounds[1].Basis, series.Bounds[2].Basis = constraintengine.BasisUpgradeFromSeries, constraintengine.BasisTargetSeries
	plain := Check{Component: "pkg:github/kubernetes/kubernetes", From: "1.24.0", To: "1.25.0", Range: series}.Transition()
	cases := []struct {
		name, from, to, mode string
		subject              constraintengine.RuleTransition
		excluded             bool
	}{
		{"wide hop across C", "1.21.5", "1.30.0", constraintengine.MatchModeBoundaryUnreviewed, ranged, false},
		{"origin below the range", "1.23.9", "1.25.1", constraintengine.MatchModeBoundaryUnreviewed, ranged, false},
		{"target above the range", "1.24.5", "1.26.0", constraintengine.MatchModeBoundaryUnreviewed, ranged, false},
		{"range match is not boundary-unreviewed", "1.24.17", "1.25.3", "range", ranged, false},
		{"anchor", "1.24.0", "1.25.0", "", ranged, false},
		{"target below C", "1.21.5", "1.24.9", "", ranged, true},
		{"origin at C", "1.25.0", "1.30.0", "", ranged, true},
		{"downgrade", "1.30.0", "1.21.5", "", ranged, true},
		{"no release basis", "1.21.5", "1.30.0", "", plain, true},
	}
	for _, tc := range cases {
		if got := projectFilter("kubernetes", tc.from, tc.to, "kubernetes", tc.subject); got != tc.excluded {
			t.Errorf("%s: excluded=%v want %v", tc.name, got, tc.excluded)
		}
		if got := queryMatchMode(tc.subject, tc.from, tc.to); got != tc.mode {
			t.Errorf("%s: matchMode=%q want %q", tc.name, got, tc.mode)
		}
	}
}

// TestDiscoverListsShippedBoundaryRules: the shipped pack's Kubernetes
// removals are release-boundary ranges. A hop that crosses a removal release
// outside the reviewed range is listed with matchMode boundary-unreviewed
// instead of NO_MATCHING_EMBEDDED_RULE, and the expectation is computed from
// the pack's own range bounds, not from the matcher under test.
func TestDiscoverListsShippedBoundaryRules(t *testing.T) {
	identities, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	// crossesBoundary recomputes "from < C <= to" from the range's own bounds.
	crossesBoundary := func(r *constraintengine.VersionRange, from, to string) bool {
		if r == nil || len(r.Bounds) != 4 || r.From.Lt != r.To.Gte {
			return false
		}
		release := func(b constraintengine.RangeBound) bool {
			return b.Basis == constraintengine.BasisRemovedInRelease || b.Basis == constraintengine.BasisChangedInRelease
		}
		return release(r.Bounds[1]) && release(r.Bounds[2]) && constraintengine.VersionLess(from, r.To.Gte) && !constraintengine.VersionLess(to, r.To.Gte)
	}
	for _, pair := range [][2]string{{"1.21.5", "1.23.1"}, {"1.20.15", "1.22.3"}, {"1.20.0", "1.22.0"}} {
		want := 0
		for _, item := range identities {
			if item.Project == "kubernetes" && item.Transition().Match(pair[0], pair[1]) == constraintengine.MatchNone && crossesBoundary(item.Range, pair[0], pair[1]) {
				want++
			}
		}
		if want < 13 {
			t.Fatalf("%v: the pack should hold the 13 removals of 1.22, found %d", pair, want)
		}
		result, err := Discover("kubernetes", pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		for _, check := range result.Checks {
			if check.MatchMode == constraintengine.MatchModeBoundaryUnreviewed {
				got++
			}
		}
		if result.RuleCoverageState != "MATCHED" || got != want || len(result.Checks) < got {
			t.Fatalf("%v: state=%s boundary-unreviewed=%d want %d (checks=%d)", pair, result.RuleCoverageState, got, want, len(result.Checks))
		}
	}
	// A hop that crosses nothing is still reported as having no rule.
	none, err := Discover("kubernetes", "1.5.2", "1.6.1")
	if err != nil {
		t.Fatal(err)
	}
	if none.RuleCoverageState != "NO_MATCHING_EMBEDDED_RULE" || len(none.Checks) != 0 {
		t.Fatalf("1.5.2 -> 1.6.1: %+v", none)
	}
}
