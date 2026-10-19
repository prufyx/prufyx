// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"reflect"
	"strings"
	"testing"
)

func kindsSource(slug string) string {
	return "https://github.com/x/" + slug + "/blob/0123456789abcdef0123456789abcdef01234567/crds/" + slug + ".yaml"
}

func kindsProject(slug string, groups ...Group) Project {
	for i := range groups {
		groups[i].Source = kindsSource(slug)
	}
	return Project{Slug: slug, Catalog: CatalogCNCF, FactProject: slug, Component: "pkg:github/x/" + slug, Groups: groups}
}

func TestOwnerOf(t *testing.T) {
	const shared = "shared.example.io"
	x := NewIndex([]Project{
		kindsProject("a", Group{Name: shared, Kinds: []string{"Alpha", "Beta"}}, Group{Name: "whole.example.io"}),
		kindsProject("b", Group{Name: shared, Kinds: []string{"Gamma"}}),
		kindsProject("c", Group{Name: "mixed.example.io", Kinds: []string{"One"}}),
	})
	for _, tc := range []struct {
		group, kind, owner string
		attribution        Attribution
	}{
		{shared, "Alpha", "a", Owned},
		{shared, "Beta", "a", Owned},
		{shared, "Gamma", "b", Owned},
		{shared, "Delta", "", Unknown},
		{shared, "alpha", "", Unknown}, // exact, case-sensitive
		{shared, "", "", Unknown},
		{shared, "Alpha ", "", Unknown},
		{"whole.example.io", "Anything", "a", Owned},
		{"whole.example.io", "", "a", Owned},
		{"mixed.example.io", "One", "c", Owned},
		{"mixed.example.io", "Two", "", Unknown},
		{"unlisted.example.io", "Alpha", "", Unknown},
	} {
		if owner, attribution := x.OwnerOf(tc.group, tc.kind); owner != tc.owner || attribution != tc.attribution {
			t.Errorf("OwnerOf(%q, %q) = %q %v, want %q %v", tc.group, tc.kind, owner, attribution, tc.owner, tc.attribution)
		}
	}
	// Owner keeps its meaning: a shared group is ambiguous for it.
	if owner, attribution := x.Owner(shared); owner != "" || attribution != Ambiguous {
		t.Errorf("Owner(shared) = %q %v", owner, attribution)
	}
}

func TestOwnerOfIsOrderIndependent(t *testing.T) {
	a := kindsProject("a", Group{Name: "shared.example.io", Kinds: []string{"Alpha"}})
	b := kindsProject("b", Group{Name: "shared.example.io", Kinds: []string{"Beta"}})
	for _, projects := range [][]Project{{a, b}, {b, a}} {
		x := NewIndex(projects)
		if o, at := x.OwnerOf("shared.example.io", "Alpha"); o != "a" || at != Owned {
			t.Errorf("Alpha: %q %v", o, at)
		}
		if o, at := x.OwnerOf("shared.example.io", "Beta"); o != "b" || at != Owned {
			t.Errorf("Beta: %q %v", o, at)
		}
	}
}

// An index over a table Validate refuses still fails closed.
func TestOwnerOfFailsClosedOnUnvalidatedTables(t *testing.T) {
	const g = "shared.example.io"
	for name, projects := range map[string][]Project{
		"overlapping kinds": {kindsProject("a", Group{Name: g, Kinds: []string{"Alpha"}}), kindsProject("b", Group{Name: g, Kinds: []string{"Alpha", "Beta"}})},
		"two whole":         {kindsProject("a", Group{Name: g}), kindsProject("b", Group{Name: g})},
	} {
		if o, at := NewIndex(projects).OwnerOf(g, "Alpha"); o != "" || at != Ambiguous {
			t.Errorf("%s: Alpha %q %v, want ambiguous", name, o, at)
		}
	}
	// A kind only the narrower listing names is still contested by the whole one.
	x := NewIndex([]Project{kindsProject("a", Group{Name: g}), kindsProject("b", Group{Name: g, Kinds: []string{"Beta"}})})
	if o, at := x.OwnerOf(g, "Beta"); o != "" || at != Ambiguous {
		t.Errorf("Beta: %q %v", o, at)
	}
	if o, at := x.OwnerOf(g, "Other"); o != "a" || at != Owned {
		t.Errorf("Other: %q %v", o, at)
	}
	// An empty, non-nil kinds list matches nothing.
	y := NewIndex([]Project{kindsProject("a", Group{Name: g, Kinds: []string{}})})
	if o, at := y.OwnerOf(g, "Alpha"); o != "" || at != Unknown {
		t.Errorf("empty kinds: %q %v", o, at)
	}
}

// Without kinds in the table, OwnerOf is Owner for every kind.
func TestOwnerOfEqualsOwnerOverTheReviewedTable(t *testing.T) {
	x := DefaultIndex()
	groups := map[string]bool{"unlisted.example.io": true, "": true, "apps": true}
	for _, p := range Projects() {
		for _, g := range p.Groups {
			if g.Kinds != nil {
				t.Skip("the reviewed table carries kinds; equality only holds for whole listings")
			}
			groups[g.Name] = true
		}
	}
	for group := range groups {
		wantOwner, wantAttribution := x.Owner(group)
		for _, kind := range []string{"", "Application", "Rollout", "X", "kind with space"} {
			if owner, attribution := x.OwnerOf(group, kind); owner != wantOwner || attribution != wantAttribution {
				t.Errorf("OwnerOf(%q, %q) = %q %v, Owner = %q %v", group, kind, owner, attribution, wantOwner, wantAttribution)
			}
		}
	}
}

func TestValidateKinds(t *testing.T) {
	const g = "shared.example.io"
	build := func(a, b []string) []Project {
		return []Project{kindsProject("a", Group{Name: g, Kinds: a}), kindsProject("b", Group{Name: g, Kinds: b})}
	}
	many := make([]string, 0, maxKindsPerGroup+1)
	for i := 0; i <= maxKindsPerGroup; i++ {
		many = append(many, "K"+strings.Repeat("a", i/26)+string(rune('a'+i%26)))
	}
	for name, tc := range map[string]struct {
		projects []Project
		ok       bool
	}{
		"disjoint kinds":                  {build([]string{"Alpha"}, []string{"Beta"}), true},
		"overlapping kinds":               {build([]string{"Alpha", "Beta"}, []string{"Beta"}), false},
		"whole next to kinds":             {build(nil, []string{"Beta"}), false},
		"kinds next to whole":             {build([]string{"Beta"}, nil), false},
		"two whole":                       {build(nil, nil), false},
		"empty kinds":                     {build([]string{}, []string{"Beta"}), false},
		"unsorted":                        {build([]string{"Beta", "Alpha"}, []string{"Gamma"}), false},
		"duplicate":                       {build([]string{"Alpha", "Alpha"}, []string{"Gamma"}), false},
		"case differs is disjoint":        {build([]string{"Alpha"}, []string{"alpha"}), true},
		"bad kind: space":                 {build([]string{"A b"}, []string{"Gamma"}), false},
		"bad kind: digit first":           {build([]string{"1a"}, []string{"Gamma"}), false},
		"bad kind: empty string":          {build([]string{""}, []string{"Gamma"}), false},
		"bad kind: too long":              {build([]string{"A" + strings.Repeat("a", 63)}, []string{"Gamma"}), false},
		"too many kinds":                  {build(many, []string{"Zzz"}), false},
		"single listing with kinds":       {[]Project{kindsProject("a", Group{Name: g, Kinds: []string{"Alpha"}})}, true},
		"single listing whole":            {[]Project{kindsProject("a", Group{Name: g})}, true},
		"single listing with empty kinds": {[]Project{kindsProject("a", Group{Name: g, Kinds: []string{}})}, false},
	} {
		if got := validate(tc.projects, nil); got != tc.ok {
			t.Errorf("%s: validate = %v, want %v", name, got, tc.ok)
		}
	}
}

func TestValidateRefusesKindsOnReservedGroups(t *testing.T) {
	p := community("kueue", "kubernetes-sigs/kueue", "kueue.x-k8s.io")
	records := []ReservedGroup{{Name: "kueue.x-k8s.io", Owner: "kueue", Repository: "https://github.com/kubernetes-sigs/kueue", Reason: "defined by this repository alone"}}
	if !validate([]Project{p}, records) {
		t.Fatal("whole reserved listing refused")
	}
	p.Groups[0].Kinds = []string{"Workload"}
	if validate([]Project{p}, records) {
		t.Fatal("a reserved group with kinds accepted")
	}
}

func TestProjectsCopiesKinds(t *testing.T) {
	src := []Project{kindsProject("a", Group{Name: "k.example.io", Kinds: []string{"Alpha"}}, Group{Name: "w.example.io"}, Group{Name: "z.example.io", Kinds: []string{}})}
	out := copyProjects(src)
	if !reflect.DeepEqual(src, out) {
		t.Fatalf("copy differs: %+v", out)
	}
	if out[0].Groups[1].Kinds != nil || out[0].Groups[2].Kinds == nil {
		t.Fatal("copy lost the difference between nil and empty kinds")
	}
	out[0].Groups[0].Kinds[0] = "Changed"
	if src[0].Groups[0].Kinds[0] != "Alpha" {
		t.Fatal("copy shares the kinds slice")
	}
}
