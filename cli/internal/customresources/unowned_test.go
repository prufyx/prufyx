// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"bytes"
	"strings"
	"testing"
)

const (
	unownedSrc = "https://github.com/example-org/example-repo/blob/0123456789abcdef0123456789abcdef01234567/crds/a.yaml"
	unownedWhy = "fixture group, no project defines or installs it"
)

func unownedProjects() []Project {
	return []Project{{
		Slug: "pa", Catalog: CatalogCNCF, FactProject: "pa", Component: "pkg:github/o/pa",
		Groups: []Group{
			{Name: "listed.io", Source: "https://github.com/o/pa/blob/0123456789abcdef0123456789abcdef01234567/crds/a.yaml"},
			{Name: "shared.io", Source: "https://github.com/o/pa/blob/0123456789abcdef0123456789abcdef01234567/crds/a.yaml", Kinds: []string{"Alpha", "Beta"}},
		},
	}}
}

func TestValidateUnownedRecords(t *testing.T) {
	rec := func(name string, kinds ...string) UnownedGroup {
		u := UnownedGroup{Name: name, Reason: unownedWhy, Source: unownedSrc}
		if kinds != nil {
			u.Kinds = kinds
		}
		return u
	}
	for _, tc := range []struct {
		name    string
		records []UnownedGroup
		ok      bool
	}{
		{"none", nil, true},
		{"whole fixture group", []UnownedGroup{rec("fixture.io")}, true},
		{"kinds of a shared group", []UnownedGroup{rec("shared.io", "Gamma")}, true},
		{"two sorted groups", []UnownedGroup{rec("a.io"), rec("b.io")}, true},
		{"unsorted", []UnownedGroup{rec("b.io"), rec("a.io")}, false},
		{"duplicate group", []UnownedGroup{rec("a.io"), rec("a.io")}, false},
		{"group listed whole by a project", []UnownedGroup{rec("listed.io")}, false},
		{"kinds of a group listed whole", []UnownedGroup{rec("listed.io", "Gamma")}, false},
		{"whole record over a group listed by kinds", []UnownedGroup{rec("shared.io")}, false},
		{"kind a project lists", []UnownedGroup{rec("shared.io", "Beta", "Gamma")}, false},
		{"empty kinds", []UnownedGroup{{Name: "a.io", Kinds: []string{}, Reason: unownedWhy, Source: unownedSrc}}, false},
		{"unsorted kinds", []UnownedGroup{rec("a.io", "B", "A")}, false},
		{"bad kind", []UnownedGroup{rec("a.io", "not a kind")}, false},
		{"group without a dot", []UnownedGroup{rec("apps")}, false},
		{"kubernetes group", []UnownedGroup{rec("things.k8s.io")}, false},
		{"reserved namespace", []UnownedGroup{rec("things.x-k8s.io")}, false},
		{"bad group", []UnownedGroup{rec("Bad_Group.io")}, false},
		{"short reason", []UnownedGroup{{Name: "a.io", Reason: "no", Source: unownedSrc}}, false},
		{"padded reason", []UnownedGroup{{Name: "a.io", Reason: " " + unownedWhy, Source: unownedSrc}}, false},
		{"long reason", []UnownedGroup{{Name: "a.io", Reason: strings.Repeat("x", 301), Source: unownedSrc}}, false},
		{"source not pinned by commit", []UnownedGroup{{Name: "a.io", Reason: unownedWhy, Source: "https://github.com/o/r/blob/main/a.yaml"}}, false},
		{"source not a manifest", []UnownedGroup{{Name: "a.io", Reason: unownedWhy, Source: "https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.go"}}, false},
		{"source elsewhere", []UnownedGroup{{Name: "a.io", Reason: unownedWhy, Source: "https://example.org/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yaml"}}, false},
	} {
		if got := validateAll(unownedProjects(), nil, tc.records); got != tc.ok {
			t.Errorf("%s: validate = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

// Records change nothing for the readers that attribute by owner: the group
// and kind stay unattributed, and the index fails closed on a clash.
func TestUnownedIsNeverAnOwner(t *testing.T) {
	x := NewIndex(unownedProjects()).WithUnowned([]UnownedGroup{{Name: "fixture.io"}, {Name: "shared.io", Kinds: []string{"Gamma"}}})
	for _, tc := range []struct {
		group, kind string
		unowned     bool
		attr        Attribution
	}{
		{"fixture.io", "Anything", true, Unknown},
		{"shared.io", "Gamma", true, Unknown},
		{"shared.io", "Alpha", false, Owned},
		{"shared.io", "gamma", false, Unknown},
		{"listed.io", "Anything", false, Owned},
		{"nobody.io", "Anything", false, Unknown},
		{"Fixture.io", "Anything", false, Unknown},
		{"sub.fixture.io", "Anything", false, Unknown},
	} {
		if _, attr := x.OwnerOf(tc.group, tc.kind); attr != tc.attr {
			t.Errorf("OwnerOf(%s, %s) = %v, want %v", tc.group, tc.kind, attr, tc.attr)
		}
		if got := x.Unowned(tc.group, tc.kind); got != tc.unowned {
			t.Errorf("Unowned(%s, %s) = %v, want %v", tc.group, tc.kind, got, tc.unowned)
		}
	}
	if NewIndex(unownedProjects()).Unowned("fixture.io", "Anything") {
		t.Error("an index without records reports one")
	}
	// A record over what a project lists is not honoured.
	clash := NewIndex(unownedProjects()).WithUnowned([]UnownedGroup{{Name: "listed.io"}, {Name: "shared.io", Kinds: []string{"Alpha"}}})
	if clash.Unowned("listed.io", "Anything") || clash.Unowned("shared.io", "Alpha") {
		t.Error("a record overrides a project listing")
	}
}

func TestUnownedGroupsIsACopy(t *testing.T) {
	a := UnownedGroups()
	if len(a) == 0 {
		t.Fatal("no records")
	}
	for i := range a {
		a[i].Name = "changed.io"
		for j := range a[i].Kinds {
			a[i].Kinds[j] = "Changed"
		}
	}
	b := UnownedGroups()
	for _, u := range b {
		if u.Name == "changed.io" || (u.Kinds != nil && u.Kinds[0] == "Changed") {
			t.Fatal("UnownedGroups returns the table's own slices")
		}
	}
	x := NewIndex(nil).WithUnowned(b)
	b[0].Name = "changed.io"
	if x.Unowned("changed.io", "Anything") {
		t.Fatal("the index shares the caller's records")
	}
}

// The embedded table holds the two reviewed records, no project lists them,
// and the table round-trips through its loader and canonical encoding.
func TestEmbeddedUnownedRecords(t *testing.T) {
	var names []string
	for _, u := range unowned {
		names = append(names, u.Name)
	}
	if got := strings.Join(names, ","); got != "argoproj.io,example.io" {
		t.Fatalf("records %s", got)
	}
	x := DefaultIndex()
	for _, tc := range []struct {
		group, kind string
		unowned     bool
	}{
		{"example.io", "Example", true},
		{"argoproj.io", "Workflow", true},
		{"argoproj.io", "CronWorkflow", true},
		{"argoproj.io", "Application", false},
		{"argoproj.io", "ApplicationSet", false},
		{"argoproj.io", "Dummy", false},
		{"argoproj.io", "Rollout", false},
		{"example.com", "Example", false},
	} {
		if got := x.Unowned(tc.group, tc.kind); got != tc.unowned {
			t.Errorf("Unowned(%s, %s) = %v", tc.group, tc.kind, got)
		}
	}
	p, r, u, err := LoadTable(tableJSON)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalTable(p, r, u)
	if err != nil || !bytes.Equal(again, tableJSON) {
		t.Fatalf("round trip: %v", err)
	}
}

// The listing moves when any field of a record changes: name, kinds, reason
// or source.
func TestUnownedListingMovesOnEveryField(t *testing.T) {
	base := UnownedGroup{Name: "a.io", Kinds: []string{"A"}, Reason: unownedWhy, Source: unownedSrc}
	listing := func(u UnownedGroup) string {
		return strings.Join(NewIndex(unownedProjects()).WithUnowned([]UnownedGroup{u}).UnownedListing(), "\n")
	}
	want := listing(base)
	if got := listing(base); got != want {
		t.Fatal("the listing is not stable")
	}
	for name, mut := range map[string]func(*UnownedGroup){
		"name":   func(u *UnownedGroup) { u.Name = "b.io" },
		"kinds":  func(u *UnownedGroup) { u.Kinds = []string{"B"} },
		"whole":  func(u *UnownedGroup) { u.Kinds = nil },
		"reason": func(u *UnownedGroup) { u.Reason = unownedWhy + " (edited)" },
		"source": func(u *UnownedGroup) { u.Source = strings.Replace(unownedSrc, "a.yaml", "b.yaml", 1) },
	} {
		u := base
		u.Kinds = append([]string(nil), base.Kinds...)
		mut(&u)
		if listing(u) == want {
			t.Errorf("%s: the listing did not move", name)
		}
	}
}
