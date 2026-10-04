// SPDX-License-Identifier: AGPL-3.0-only

package latestrelease

import "testing"

func TestSelectIgnoresDraftsPrereleasesAndOrder(t *testing.T) {
	rs := []Release{
		{ID: 9, Tag: "v3.0.0", Draft: true},
		{ID: 8, Tag: "v2.5.0-rc.1", Prerelease: true},
		{ID: 7, Tag: "v1.9.9"}, // a backport published last
		{ID: 5, Tag: "v2.4.1"},
		{ID: 4, Tag: "v2.4.0"},
	}
	for name, in := range map[string][]Release{"listed": rs, "reversed": {rs[4], rs[3], rs[2], rs[1], rs[0]}} {
		got, ok := Select(in)
		if !ok || got.Tag != "v2.4.1" {
			t.Fatalf("%s: got %+v ok=%v", name, got, ok)
		}
	}
}

func TestSelectComparesNumbersNotText(t *testing.T) {
	got, _ := Select([]Release{{ID: 1, Tag: "v1.9.0"}, {ID: 2, Tag: "v1.10.0"}, {ID: 3, Tag: "v1.2.30"}})
	if got.Tag != "v1.10.0" {
		t.Fatalf("got %s", got.Tag)
	}
}

func TestSelectFallsBackToHighestIDWithoutStrictVersions(t *testing.T) {
	got, ok := Select([]Release{{ID: 2, Tag: "nightly"}, {ID: 7, Tag: "2024-05"}, {ID: 3, Tag: "weekly"}})
	if !ok || got.ID != 7 {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := Select([]Release{{ID: 1, Tag: "v1.0.0", Draft: true}, {ID: 2, Tag: "v1.1.0", Prerelease: true}}); ok {
		t.Fatal("only drafts and prereleases: no latest")
	}
	if _, ok := Select(nil); ok {
		t.Fatal("empty: no latest")
	}
}

func TestSelectTieIsDeterministic(t *testing.T) {
	a := []Release{{ID: 1, Tag: "release-1.2.3"}, {ID: 2, Tag: "v1.2.3"}, {ID: 3, Tag: "1.2.3"}}
	b := []Release{a[2], a[0], a[1]}
	ga, _ := Select(a)
	gb, _ := Select(b)
	if ga.Tag != "1.2.3" || gb.Tag != "1.2.3" {
		t.Fatalf("%s %s", ga.Tag, gb.Tag)
	}
}

func TestSelectTagUsesStrictGrammarOnly(t *testing.T) {
	tags := []string{"weekly.2012-03-27", "release.r60.3", "go1.9", "go1.22.5", "go1.22rc1", "go1.24.2", "go1.24beta1", "go1.10.8", "v99.0.0-rc1", "r100.1.1.1"}
	got, ok := SelectTag(tags)
	if !ok || got != "go1.24.2" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	if _, ok := SelectTag([]string{"weekly.2012-03-27", "release.r60.3"}); ok {
		t.Fatal("no strict version: no latest tag")
	}
	if _, ok := SelectTag(nil); ok {
		t.Fatal("no tags: no latest tag")
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
