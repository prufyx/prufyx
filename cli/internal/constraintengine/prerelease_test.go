// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import "testing"

func TestCompareVersionsPreReleaseOrder(t *testing.T) {
	// Ascending SemVer 2.0 order; every pair must agree.
	order := []string{
		"1.37.9", "1.38.0-alpha.1", "1.38.0-alpha.2", "1.38.0-alpha.10",
		"1.38.0-beta.0", "1.38.0-beta.1", "1.38.0-rc.0", "1.38.0-rc.1",
		"1.38.0", "1.38.1", "1.39.0-alpha.1", "1.39.0",
	}
	for i, a := range order {
		for j, b := range order {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got, ok := compareVersions(a, b); !ok || got != want {
				t.Errorf("compareVersions(%s, %s) = %d, %v; want %d", a, b, got, ok, want)
			}
		}
	}
	if c, ok := CompareVersions("1.38.0-alpha.2", "1.38.0"); !ok || c != -1 {
		t.Fatal("CompareVersions disagrees with the order")
	}
	// SameVersion and VersionLess keep the release grammar: callers use
	// SameVersion(v, v) as the test for a release version.
	for _, v := range []string{"1.38.0-alpha.2", "1.38.0-rc.1"} {
		if SameVersion(v, v) || VersionLess(v, "1.38.0") || VersionLess("1.37.0", v) {
			t.Errorf("%s is not a release version", v)
		}
	}
	if !SameVersion("1.38.0", "1.38.0") || !VersionLess("1.37.9", "1.38.0") {
		t.Fatal("release comparison changed")
	}
}

func TestPreReleaseGrammar(t *testing.T) {
	for _, v := range []string{"1.38.0-alpha.1", "1.38.0-beta.0", "1.38.0-rc.12"} {
		if !PreRelease(v) {
			t.Errorf("%s refused", v)
		}
		// Rule data stays strict: a pre-release is never a rule version.
		if validVersion(v) {
			t.Errorf("%s accepted as a rule version", v)
		}
	}
	for _, v := range []string{"1.38.0", "1.38.0-alpha", "1.38.0-alpha.01", "1.38.1-alpha.1", "1.38-alpha.1", "1.38.0-alpha.1+x", "v1.38.0-alpha.1", "1.38.0-nightly.1", ""} {
		if PreRelease(v) {
			t.Errorf("%s accepted", v)
		}
		if _, ok := compareVersions(v, "1.38.0"); ok && !validVersion(v) {
			t.Errorf("%s compares", v)
		}
	}
	if !validSideVersion(kubernetesComponent, "1.38.0-rc.1") || validSideVersion("pkg:github/example/project", "1.38.0-rc.1") || !validSideVersion("pkg:github/example/project", "1.38.0") {
		t.Fatal("only Kubernetes takes a pre-release on an input side")
	}
}

func TestLineFloor(t *testing.T) {
	for in, want := range map[string]string{
		"1.38.0-alpha.2": "1.38.0", "1.38.0-rc.1": "1.38.0", "1.38.0": "1.38.0", "1.38.5": "1.38.5", "bad": "bad", "1.38.0-alpha": "1.38.0-alpha",
	} {
		if got := LineFloor(in); got != want {
			t.Errorf("LineFloor(%s) = %s, want %s", in, got, want)
		}
	}
}

// A pre-release is inside its own line for ranges and crossings, while its
// ordering stays below the release. Components other than Kubernetes never
// match one.
func TestPreReleaseMatchesItsOwnLine(t *testing.T) {
	ranged := func(component string) RuleTransition {
		return RuleTransition{Component: component, From: "1.24.0", To: "1.25.0", Range: &VersionRange{
			From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}}
	}
	crossing := func(component string) RuleTransition {
		return RuleTransition{Component: component, From: "1.24.0", To: "1.25.0", Crossing: &CrossingSpec{
			Change: CrossingChange{Version: "1.25.0"}, Horizon: CrossingHorizon{Lt: "1.36.0"}}}
	}
	cases := []struct {
		name, from, to string
		ranged, cross  MatchMode
	}{
		{"pre-release target of the entered line", "1.24.17", "1.25.0-alpha.1", MatchRange, MatchCrossing},
		{"pre-release origin in its own line", "1.24.0-alpha.2", "1.25.3", MatchRange, MatchCrossing},
		{"both ends pre-release", "1.24.0-beta.1", "1.25.0-rc.1", MatchRange, MatchCrossing},
		{"pre-release of the line above the range", "1.24.17", "1.26.0-alpha.1", MatchNone, MatchCrossing},
		{"pre-release is not in the line below", "1.23.9", "1.24.0-alpha.1", MatchNone, MatchNone},
		{"same-line pre-release to release", "1.25.0-alpha.2", "1.25.0", MatchNone, MatchNone},
		{"release to pre-release of the same line", "1.25.0", "1.25.0-rc.1", MatchNone, MatchNone},
		{"anchor stays an exact string", "1.24.0", "1.25.0", MatchAnchor, MatchAnchor},
		{"malformed pre-release", "1.24.17", "1.25.0-alpha", MatchNone, MatchNone},
		{"patch pre-release", "1.24.17", "1.25.1-alpha.1", MatchNone, MatchNone},
	}
	for _, c := range cases {
		if got := ranged(kubernetesComponent).Match(c.from, c.to); got != c.ranged {
			t.Errorf("%s: ranged %s -> %s = %q, want %q", c.name, c.from, c.to, got, c.ranged)
		}
		if got := crossing(kubernetesComponent).Match(c.from, c.to); got != c.cross {
			t.Errorf("%s: crossing %s -> %s = %q, want %q", c.name, c.from, c.to, got, c.cross)
		}
		// A component that takes no pre-release matches none.
		if PreRelease(c.from) || PreRelease(c.to) {
			other := "pkg:github/example/project"
			if got := ranged(other).Match(c.from, c.to); got != MatchNone {
				t.Errorf("%s: other component ranged = %q", c.name, got)
			}
			if got := crossing(other).Match(c.from, c.to); got != MatchNone {
				t.Errorf("%s: other component crossing = %q", c.name, got)
			}
		}
	}
	if !ranged(kubernetesComponent).CrossesUnreviewed("1.24.1", "1.25.0-alpha.1") && ranged(kubernetesComponent).Match("1.24.1", "1.25.0-alpha.1") == MatchNone {
		t.Error("the entered pre-release line crosses nothing")
	}
}

// Plain X.Y.Z pairs match exactly as before the pre-release grammar.
func TestPlainVersionsUnchangedByPreRelease(t *testing.T) {
	ranged := RuleTransition{Component: kubernetesComponent, From: "1.24.0", To: "1.25.0", Range: &VersionRange{
		From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}}
	for _, c := range []struct {
		from, to string
		want     MatchMode
	}{
		{"1.24.17", "1.25.3", MatchRange}, {"1.24.0", "1.25.0", MatchAnchor}, {"1.23.9", "1.25.0", MatchNone},
		{"1.24.17", "1.26.0", MatchNone}, {"1.25.1", "1.25.4", MatchNone}, {"1.25.3", "1.24.17", MatchNone},
	} {
		if got := ranged.Match(c.from, c.to); got != c.want {
			t.Errorf("%s -> %s = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}
