// SPDX-License-Identifier: AGPL-3.0-only

package latestrelease

import (
	"strings"
	"testing"
)

func found(t *testing.T, rs []Release) Release {
	t.Helper()
	res := Select(rs)
	if res.Outcome != Found {
		t.Fatalf("outcome %v (%s)", res.Outcome, res.Reason)
	}
	return res.Release
}

func TestSelectIgnoresDraftsPrereleasesAndOrder(t *testing.T) {
	rs := []Release{
		{ID: 9, Tag: "v3.0.0", Draft: true},
		{ID: 8, Tag: "v2.5.0-rc.1", Prerelease: true},
		{ID: 7, Tag: "v1.9.9"}, // a backport published last
		{ID: 5, Tag: "v2.4.1"},
		{ID: 4, Tag: "v2.4.0"},
	}
	for name, in := range map[string][]Release{"listed": rs, "reversed": {rs[4], rs[3], rs[2], rs[1], rs[0]}} {
		if got := found(t, in); got.Tag != "v2.4.1" {
			t.Fatalf("%s: got %+v", name, got)
		}
	}
}

func TestSelectComparesNumbersNotText(t *testing.T) {
	if got := found(t, []Release{{ID: 1, Tag: "v1.9.0"}, {ID: 2, Tag: "v1.10.0"}, {ID: 3, Tag: "v1.2.30"}}); got.Tag != "v1.10.0" {
		t.Fatalf("got %s", got.Tag)
	}
	if got := found(t, []Release{{ID: 1, Tag: "v1.2.9"}, {ID: 2, Tag: "v1.2.10"}, {ID: 3, Tag: "v1.1.99"}}); got.Tag != "v1.2.10" {
		t.Fatalf("got %s", got.Tag)
	}
}

func TestSelectFallsBackToHighestIDWithoutStrictVersions(t *testing.T) {
	if got := found(t, []Release{{ID: 2, Tag: "nightly"}, {ID: 7, Tag: "2024-05"}, {ID: 3, Tag: "weekly"}}); got.ID != 7 {
		t.Fatalf("got %+v", got)
	}
	if res := Select([]Release{{ID: 1, Tag: "v1.0.0", Draft: true}, {ID: 2, Tag: "v1.1.0", Prerelease: true}}); res.Outcome != None {
		t.Fatal("only drafts and prereleases: no latest")
	}
	if Select(nil).Outcome != None {
		t.Fatal("empty: no latest")
	}
}

// Releases under other prefixes, or under several, are never silently
// ranked: a chart or SDK with a bigger number must not become "latest".
func TestSelectIsAmbiguousForOtherOrMixedPrefixes(t *testing.T) {
	for name, rs := range map[string][]Release{
		"component prefix": {{ID: 2, Tag: "v1.30.0"}, {ID: 3, Tag: "helm-chart-5.0.0"}},
		"path prefix":      {{ID: 2, Tag: "v1.30.0"}, {ID: 3, Tag: "sdk/go/v2.0.0"}},
		"only other":       {{ID: 2, Tag: "release-1.2.3"}},
		"none and v":       {{ID: 2, Tag: "1.2.3"}, {ID: 3, Tag: "v1.2.4"}},
		"v and go":         {{ID: 2, Tag: "v1.2.3"}, {ID: 3, Tag: "go1.2.4"}},
	} {
		res := Select(rs)
		if res.Outcome != Ambiguous || res.Reason == "" {
			t.Fatalf("%s: %+v", name, res)
		}
	}
	// An absurd number is not special-cased: no heuristic, only the rule.
	if got := found(t, []Release{{ID: 2, Tag: "v1.30.0"}, {ID: 3, Tag: "v999.0.0"}}); got.Tag != "v999.0.0" {
		t.Fatalf("got %s", got.Tag)
	}
}

// A repository whose newest release is not a strict version is not left on
// an older strict release.
func TestSelectIsAmbiguousWhenTheNewestReleaseIsNotStrict(t *testing.T) {
	for name, rs := range map[string][]Release{
		"calendar":  {{ID: 1, Tag: "v3.2.1"}, {ID: 2, Tag: "2024.5.0"}, {ID: 3, Tag: "2025.1.0"}},
		"two parts": {{ID: 1, Tag: "v0.9.0"}, {ID: 2, Tag: "v1.5"}, {ID: 3, Tag: "v1.6"}},
	} {
		res := Select(rs)
		if res.Outcome != Ambiguous || !strings.Contains(res.Reason, "not a strict version") {
			t.Fatalf("%s: %+v", name, res)
		}
	}
	// A non-strict release that is older than the strict winner is ignored.
	if got := found(t, []Release{{ID: 1, Tag: "v1.5"}, {ID: 2, Tag: "v2.0.0"}}); got.Tag != "v2.0.0" {
		t.Fatalf("got %s", got.Tag)
	}
}

func TestSelectTagUsesStrictGrammarOnly(t *testing.T) {
	tags := []string{"weekly.2012-03-27", "release.r60.3", "go1.9", "go1.22.5", "go1.22rc1", "go1.24.2", "go1.24beta1", "go1.10.8", "r100.1.1.1"}
	got, out, _ := SelectTag(tags)
	if out != Found || got != "go1.24.2" {
		t.Fatalf("got %q %v", got, out)
	}
	if _, out, _ := SelectTag([]string{"weekly.2012-03-27", "release.r60.3"}); out != None {
		t.Fatal("no strict version: no latest tag")
	}
	if _, out, _ := SelectTag(nil); out != None {
		t.Fatal("no tags: no latest tag")
	}
	if _, out, reason := SelectTag([]string{"v1.0.0", "kubernetes-1.2.3"}); out != Ambiguous || reason == "" {
		t.Fatalf("other prefix must be ambiguous: %v %q", out, reason)
	}
}

func TestAmbiguousPrefixes(t *testing.T) {
	for _, ok := range [][]string{nil, {"v"}, {"v", "v"}, {""}, {"go"}} {
		if r := AmbiguousPrefixes(ok); r != "" {
			t.Errorf("%q: %s", ok, r)
		}
	}
	for _, bad := range [][]string{{"", "v"}, {"v", "go"}, {"release-"}, {"v", "api/v"}} {
		if r := AmbiguousPrefixes(bad); r == "" {
			t.Errorf("%q must be ambiguous", bad)
		}
	}
	if a, b := AmbiguousPrefixes([]string{"x-", "v"}), AmbiguousPrefixes([]string{"v", "x-"}); a != b {
		t.Fatal("reason must not depend on order")
	}
}

func TestParseStrict(t *testing.T) {
	for tag, want := range map[string]bool{
		"v1.2.3": true, "1.2.3": true, "release-1.2.3": true, "api/v1.2.3": true, "go1.22.5": true,
		"v1.2": false, "v1.2.3-rc1": false, "v1.2.3.4": false, "v01.2.3": false, "v1000.0.0": false, "foo1.2.3": false, "": false,
	} {
		if _, ok := ParseStrict(tag); ok != want {
			t.Errorf("ParseStrict(%q) = %v, want %v", tag, ok, want)
		}
	}
}
