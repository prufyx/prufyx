// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestReadFinalTagPaddedMinor(t *testing.T) {
	for _, c := range []struct {
		prefix, tag, version string
		padded               bool
	}{
		{"v", "v26.06.2", "26.6.2", true},
		{"v", "v26.02.0", "26.2.0", true},
		{"v", "v25.10.0", "25.10.0", false},
		{"v", "v20.10.1", "20.10.1", false},
		{"v", "v20.01.0", "20.1.0", true},
		{"v", "v20.09.9", "20.9.9", true},
		{"", "26.02.0", "26.2.0", true},
		{"v", "v26.2.0", "26.2.0", false},
		{"v", "v26.0.0", "26.0.0", false},
		{"v", "v1.2.3", "1.2.3", false},
		{"v", "v19.9.0", "19.9.0", false},
		{"v", "v99.02.0", "99.2.0", true},
		{"v", "v100.2.0", "100.2.0", false},
		{"v", "v2024.2.1", "2024.2.1", false},
	} {
		v, p, ok := ReadFinalTag(c.prefix, 4, c.tag)
		if !ok || v != c.version || p != c.padded {
			t.Errorf("%q: %q %v %v", c.tag, v, p, ok)
		}
	}
	for _, tag := range []string{
		"v1.02.3",    // major below 20
		"v19.02.0",   // major below 20
		"v9.01.0",    // major below 20
		"v100.02.0",  // major above 99
		"v2024.02.1", // calendar year major above 99
		"1.02.3",     // major below 20, no prefix
		"v20.00.0",   // zero minor with a leading zero
		"v26.00.1",   // same
		"v20.010.1",  // two leading zeros worth of padding
		"v26.002.0",  // more than one leading zero
		"v26.10.00",  // leading zero of the patch
		"v26.02.00",
		"v26.02.01",
		"v26.2.03",
		"v026.02.0", // leading zero of the major
		"v26.02",    // no patch
		"v26.02.0-rc1",
		"v26.02.0.1",
		"v26.02.0+x",
		"vv26.02.0",
		"xv26.02.0",
		"V26.02.0",
		"26.02.0", // wrong prefix for "v"
		"v26.-2.0",
		"v26.+2.0",
		"v26. 2.0",
	} {
		if v, _, ok := ReadFinalTag("v", 4, tag); ok {
			t.Errorf("%q read as %q", tag, v)
		}
	}
	// The digit bound applies to every component.
	if _, _, ok := ReadFinalTag("v", 4, "v26.02.10000"); ok {
		t.Error("five-digit patch read")
	}
	if _, _, ok := ReadFinalTag("v", 9, "v26.02.10000"); !ok {
		t.Error("five-digit patch not read with the gate bound")
	}
}

func TestPaddedMinorLines(t *testing.T) {
	sha := func(c string) string { return strings.Repeat(c, 40) }
	x := New(Target{TagPrefixes: []string{"v"}})
	tags := func(names ...string) extract.ReleaseIndex {
		var idx extract.ReleaseIndex
		for i, n := range names {
			idx.Tags = append(idx.Tags, extract.Tag{Name: n, Commit: sha(string(rune('a' + i)))})
		}
		return idx
	}
	// Numeric order, not lexical: 26.10 follows 26.2 and 26.6.
	lines := x.releaseLines(tags("v26.10.0", "v26.02.0", "v26.06.2", "v25.10.0", "v26.02.1"))
	var keys []string
	for _, l := range lines {
		keys = append(keys, l.key())
		if l.Problem != "" {
			t.Fatalf("line %s: %s", l.key(), l.Problem)
		}
	}
	if !slices.Equal(keys, []string{"25.10", "26.2", "26.6", "26.10"}) {
		t.Fatalf("lines %v", keys)
	}
	if got := lines[1].Versions; !slices.Equal(got, []string{"26.2.0", "26.2.1"}) || lines[1].Tags[0].Name != "v26.02.0" {
		t.Fatalf("26.2: %v %v", got, lines[1].Tags)
	}
	// Both spellings of one line: ambiguous, whatever the commits and
	// whichever order the tags come in.
	for _, names := range [][]string{
		{"v26.02.0", "v26.2.0"},
		{"v26.2.0", "v26.02.0"},
		{"v26.02.0", "v26.2.1"},
		{"v26.02.5", "v26.2.0", "v26.10.0"},
	} {
		got := x.releaseLines(tags(names...))
		if got[0].key() != "26.2" || !strings.Contains(got[0].Problem, "ambiguous") {
			t.Errorf("%v: %+v", names, got[0])
		}
		for _, l := range got[1:] {
			if l.Problem != "" {
				t.Errorf("%v: unrelated line %s withheld", names, l.key())
			}
		}
	}
	// A padded twin at the same commit is one release, kept under the
	// unpadded spelling whatever the order; at another commit it is a
	// conflict.
	for _, names := range [][]string{{"v26.02.0", "v26.2.0"}, {"v26.2.0", "v26.02.0"}} {
		same := extract.ReleaseIndex{}
		for _, n := range names {
			same.Tags = append(same.Tags, extract.Tag{Name: n, Commit: sha("a")})
		}
		l := x.releaseLines(same)
		if len(l) != 1 || l[0].Problem != "" || !slices.Equal(l[0].Versions, []string{"26.2.0"}) || l[0].Tags[0].Name != "v26.2.0" {
			t.Errorf("%v: same-commit twin: %+v", names, l)
		}
		if l := x.releaseLines(tags(names...)); len(l) != 1 || l[0].Problem == "" {
			t.Errorf("%v: different-commit twin: %+v", names, l)
		}
	}
	// A twin next to other releases of the line, and next to other lines.
	mix := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "v25.08.0", Commit: sha("a")}, {Name: "v25.8.0", Commit: sha("a")},
		{Name: "v25.8.1", Commit: sha("b")}, {Name: "v25.10.0", Commit: sha("c")}, {Name: "v25.0.0", Commit: sha("d")},
	}}
	if l := x.releaseLines(mix); len(l) != 3 || l[1].key() != "25.8" || l[1].Problem != "" ||
		!slices.Equal(l[1].Versions, []string{"25.8.0", "25.8.1"}) || l[0].Problem != "" || l[2].Problem != "" {
		t.Errorf("twin among releases: %+v", l)
	}
	// A twin beside a padded-only release is ambiguous, as in the gate.
	amb := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "v25.08.0", Commit: sha("a")}, {Name: "v25.8.0", Commit: sha("a")},
		{Name: "v25.08.1", Commit: sha("b")},
	}}
	if l := x.releaseLines(amb); len(l) != 1 || !strings.Contains(l[0].Problem, "ambiguous") {
		t.Errorf("twin beside a padded-only release: %+v", l)
	}
	// Dual prefix and zero-padding combinations.
	x3 := New(Target{TagPrefixes: []string{"v", ""}})
	for _, c := range []struct {
		commits []string
		problem bool
	}{
		{[]string{"a", "a", "a", "a"}, false},
		{[]string{"a", "a", "a", "b"}, true},
		{[]string{"a", "b", "a", "a"}, true},
		{[]string{"b", "a", "a", "a"}, true},
	} {
		var idx extract.ReleaseIndex
		for i, n := range []string{"v25.08.0", "25.08.0", "v25.8.0", "25.8.0"} {
			idx.Tags = append(idx.Tags, extract.Tag{Name: n, Commit: sha(c.commits[i])})
		}
		l := x3.releaseLines(idx)
		if len(l) != 1 || (l[0].Problem != "") != c.problem || (!c.problem && (len(l[0].Versions) != 1 || l[0].Tags[0].Name != "v25.8.0")) {
			t.Errorf("%v: %+v", c.commits, l)
		}
	}
	// Ascending ls-remote order: a canonical release, then the padded twin,
	// then its canonical spelling at the same commit: one line, no problem.
	ord := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "25.8.1", Commit: sha("b")}, {Name: "v25.08.0", Commit: sha("a")}, {Name: "v25.8.0", Commit: sha("a")},
	}}
	if l := New(Target{TagPrefixes: []string{"v", ""}}).releaseLines(ord); len(l) != 1 || l[0].Problem != "" || len(l[0].Versions) != 2 {
		t.Errorf("three-tag order: %+v", l)
	}
	// Three spellings, two agree and one differs.
	idx3 := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "v25.08.0", Commit: sha("a")}, {Name: "v25.8.0", Commit: sha("a")}, {Name: "25.8.0", Commit: sha("b")},
	}}
	if l := x3.releaseLines(idx3); len(l) != 1 || l[0].Problem == "" {
		t.Errorf("two agree, one differs: %+v", l)
	}
	// Without twins nothing changes: a line of one spelling has no problem.
	if l := x.releaseLines(tags("v25.8.0", "v25.8.1")); len(l) != 1 || l[0].Problem != "" || l[0].Tags[0].Name != "v25.8.0" {
		t.Errorf("no twin: %+v", l)
	}
	// Padded tags of the same line under two prefixes are one spelling.
	x2 := New(Target{TagPrefixes: []string{"v", ""}})
	two := extract.ReleaseIndex{Tags: []extract.Tag{{Name: "v26.02.0", Commit: sha("a")}, {Name: "26.02.0", Commit: sha("a")}}}
	if l := x2.releaseLines(two); len(l) != 1 || l[0].Problem != "" || len(l[0].Versions) != 1 {
		t.Errorf("%+v", l)
	}
	// Rejected spellings add no release and no line.
	if l := x.releaseLines(tags("v1.02.3", "v20.00.0", "v20.010.1", "v26.02.00")); len(l) != 0 {
		t.Errorf("rejected tags made lines: %+v", l)
	}
	// A rejected tag does not make a canonical line ambiguous.
	if l := x.releaseLines(tags("v26.2.0", "v26.002.0")); len(l) != 1 || l[0].Problem != "" {
		t.Errorf("%+v", l)
	}
}

// The framework's recorded-tag check reads a tag as naming a version only
// when the name ends in it, so a padded tag gets one more entry, named for
// the canonical version; the extractor never reads that entry as a release.
func TestPaddedMinorAlias(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	src := fixedTags{{Name: "v26.02.0", Commit: a}, {Name: "v26.10.0", Commit: b}, {Name: "v1.02.3", Commit: b}}
	for _, prefixes := range [][]string{{"v"}, {"", "v"}, {"v", ""}} {
		x := New(Target{TagPrefixes: prefixes})
		got, err := ReleaseTags(x, src).Tags(extract.RepoRef{})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tg := range got {
			names = append(names, tg.Name)
		}
		if want := []string{"v26.02.0", "v26.10.0", "v1.02.3", "~26.2.0"}; !slices.Equal(names, want) || got[3].Commit != a {
			t.Fatalf("%q: tags %v", prefixes, got)
		}
		if lines := x.releaseLines(extract.ReleaseIndex{Tags: got}); len(lines) != 2 || lines[0].Problem != "" {
			t.Fatalf("%q: alias read as a release: %+v", prefixes, lines)
		}
	}
}

// FinalSet is the one twin rule of the extractor and the knowledge gate.
func TestFinalSetTwinRule(t *testing.T) {
	type tag struct {
		v      string
		padded bool
		commit string
	}
	for _, c := range []struct {
		name string
		tags []tag
		want []string
		err  bool
	}{
		{"twin same commit", []tag{{"25.8.0", true, "a"}, {"25.8.0", false, "a"}}, []string{"25.8.0"}, false},
		{"twin same commit, other order", []tag{{"25.8.0", false, "a"}, {"25.8.0", true, "a"}}, []string{"25.8.0"}, false},
		{"twin different commit", []tag{{"25.8.0", true, "a"}, {"25.8.0", false, "b"}}, nil, true},
		{"three spellings, one differs", []tag{{"25.8.0", true, "a"}, {"25.8.0", false, "a"}, {"25.8.0", false, "b"}}, nil, true},
		{"same spelling two prefixes, two commits", []tag{{"25.8.0", false, "a"}, {"25.8.0", false, "b"}}, nil, true},
		{"twin and canonical release", []tag{{"25.8.0", true, "a"}, {"25.8.0", false, "a"}, {"25.8.1", false, "b"}}, []string{"25.8.0", "25.8.1"}, false},
		{"twin and padded-only release", []tag{{"25.8.0", true, "a"}, {"25.8.0", false, "a"}, {"25.8.1", true, "b"}}, nil, true},
		{"three tags, canonical release before the padded twin", []tag{{"25.8.1", false, "b"}, {"25.8.0", true, "a"}, {"25.8.0", false, "a"}}, []string{"25.8.0", "25.8.1"}, false},
		{"padded-only and canonical-only", []tag{{"25.8.0", true, "a"}, {"25.8.1", false, "b"}}, nil, true},
		{"padded only", []tag{{"25.8.0", true, "a"}, {"25.8.1", true, "b"}}, []string{"25.8.0", "25.8.1"}, false},
		{"canonical only", []tag{{"25.8.0", false, "a"}, {"25.8.1", false, "b"}}, []string{"25.8.0", "25.8.1"}, false},
	} {
		var s FinalSet
		for _, tg := range c.tags {
			s.Add(tg.v, tg.padded, tg.commit)
		}
		if err := s.Err(); (err != nil) != c.err || (!c.err && !slices.Equal(s.Versions(), c.want)) {
			t.Errorf("%s: %v %v", c.name, s.Versions(), err)
		}
	}
}
