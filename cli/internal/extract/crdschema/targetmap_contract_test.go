// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The contract the wiring change must honour: a mapped target carries its
// exact tag prefixes, and FilterIndex with them runs before any line
// derivation.
func TestMappingCarriesTagPrefixes(t *testing.T) {
	for _, c := range [][]string{{"v"}, {""}, {"v", ""}, {"", "v"}} {
		in := okTarget()
		in.TagPrefixes = c
		m, rs := TargetFromCRDVersions(in)
		if len(rs) != 0 || !reflect.DeepEqual(m.TagPrefixes, c) {
			t.Fatalf("%v: got %v %v", c, m.TagPrefixes, rs)
		}
	}
}

func TestFilterTags(t *testing.T) {
	all := []string{"v1.2.0", "1.2.0", "v1.3.0", "2.0.0", "helm-chart-1.2.0", "mariadb-operator-0.1.0", "api/v1.2.0", "v1.3.0-rc.1", "v26.02.0", "v1.02.0"}
	cases := []struct {
		name     string
		prefixes []string
		want     []string
	}{
		{"v only", []string{"v"}, []string{"v1.2.0", "v1.3.0", "v26.02.0"}},
		{"bare only", []string{""}, []string{"1.2.0", "2.0.0"}},
		{"dual keeps both spellings", []string{"v", ""}, []string{"v1.2.0", "1.2.0", "v1.3.0", "2.0.0", "v26.02.0"}},
		{"none", nil, []string{}},
	}
	for _, c := range cases {
		got := FilterTags(all, c.prefixes)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
		}
	}
}

// A bare sibling tag of a v-only target must not become a line.
func TestFilterIndexDropsSiblingSpelling(t *testing.T) {
	c1, c2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	idx := extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{{Name: "v1.2.0", Commit: c1}, {Name: "2.0.0", Commit: c2}, {Name: "helm-chart-1.3.0", Commit: c2}}}
	if n := len(releaseLines(idx)); n != 2 {
		t.Fatalf("unfiltered lines %d", n)
	}
	lines := releaseLines(FilterIndex(idx, []string{"v"}))
	if len(lines) != 1 || lines[0].Versions[0] != "1.2.0" {
		t.Fatalf("filtered lines %+v", lines)
	}
	// dual prefix, same version at different commits: kept, and the line is withheld
	dual := extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{{Name: "v1.2.0", Commit: c1}, {Name: "1.2.0", Commit: c2}}}
	l := releaseLines(FilterIndex(dual, []string{"v", ""}))
	if len(l) != 1 || l[0].Problem == "" {
		t.Fatalf("dual duplicate not withheld: %+v", l)
	}
}
