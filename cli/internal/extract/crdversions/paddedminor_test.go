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
	} {
		v, p, ok := ReadFinalTag(c.prefix, 4, c.tag)
		if !ok || v != c.version || p != c.padded {
			t.Errorf("%q: %q %v %v", c.tag, v, p, ok)
		}
	}
	for _, tag := range []string{
		"v1.02.3",   // major below 20
		"v19.02.0",  // major below 20
		"v9.01.0",   // major below 20
		"1.02.3",    // major below 20, no prefix
		"v20.00.0",  // zero minor with a leading zero
		"v26.00.1",  // same
		"v20.010.1", // two leading zeros worth of padding
		"v26.002.0", // more than one leading zero
		"v26.10.00", // leading zero of the patch
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
	// The same commit under both spellings is still ambiguous.
	same := extract.ReleaseIndex{Tags: []extract.Tag{{Name: "v26.02.0", Commit: sha("a")}, {Name: "v26.2.0", Commit: sha("a")}}}
	if l := x.releaseLines(same); l[0].Problem == "" {
		t.Error("same-commit padded and canonical tags accepted")
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
