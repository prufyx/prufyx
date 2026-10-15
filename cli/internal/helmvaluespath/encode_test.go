// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func TestBoundIsTheEngines(t *testing.T) {
	if MaxMemberBytes != constraintengine.MaxSetMemberBytes {
		t.Fatalf("MaxMemberBytes %d, engine %d", MaxMemberBytes, constraintengine.MaxSetMemberBytes)
	}
}

func TestMember(t *testing.T) {
	long := strings.Repeat("a", 128)
	for _, tc := range []struct {
		path []string
		want string
		ok   bool
	}{
		// Plain form: unchanged from the plain dotted join.
		{[]string{"a"}, "a", true},
		{[]string{"a", "b"}, "a.b", true},
		{[]string{"A_1", "x-y", "p/q"}, "A_1.x-y.p/q", true},
		{[]string{"a", "_b"}, "a._b", true},
		{[]string{"0", "-"}, "0.-", true},
		{[]string{"k", "a"}, "k.a", true},
		{[]string{long}, long, true},
		// Escaped form.
		{[]string{"_a"}, "k.._5Fa", true},
		{[]string{"/a"}, "k../a", true},
		{[]string{"-"}, "k..-", true},
		{[]string{"a.b"}, "k..a_2Eb", true},
		{[]string{"a", "b.c"}, "k..a..b_2Ec", true},
		{[]string{"a_b", "c.d"}, "k..a_5Fb..c_2Ed", true},
		{[]string{"a b"}, "k..a_20b", true},
		{[]string{"ä"}, "k.._C3_A4", true},
		{[]string{"\x00"}, "", false},
		{[]string{"a", "b\x00c"}, "", false},
		{[]string{"\xff"}, "k.._FF", true},
		{[]string{"annotations", "nginx.ingress.kubernetes.io/proxy-body-size"}, "k..annotations..nginx_2Eingress_2Ekubernetes_2Eio/proxy-body-size", true},
		{[]string{".", "."}, "k.._2E.._2E", true},
		{[]string{strings.Repeat("a", 122) + "."}, "k.." + strings.Repeat("a", 122) + "_2E", true},
		// Not expressible.
		{nil, "", false},
		{[]string{}, "", false},
		{[]string{""}, "", false},
		{[]string{"a", ""}, "", false},
		{[]string{long + "a"}, "", false},
		{[]string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, "", false},
		{[]string{strings.Repeat("a", 123) + "."}, "", false},
		{[]string{strings.Repeat("a", 124) + "."}, "", false},
	} {
		got, ok := Member(tc.path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Member(%q) = %q %v, want %q %v", tc.path, got, ok, tc.want, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if !constraintengine.ValidSetMember(got) {
			t.Errorf("%q: the engine refuses %q", tc.path, got)
		}
		back, ok := Path(got)
		if !ok || !slices.Equal(back, tc.path) {
			t.Errorf("Path(%q) = %q %v, want %q", got, back, ok, tc.path)
		}
		if !Canonical(got) {
			t.Errorf("%q not canonical", got)
		}
	}
}

func TestMemberBoundEdge(t *testing.T) {
	// 127 and 128 bytes are members, 129 is not, in both forms.
	for n, ok := range map[int]bool{127: true, 128: true, 129: false} {
		if _, got := Member([]string{strings.Repeat("a", n)}); got != ok {
			t.Errorf("plain %d bytes: %v", n, got)
		}
		key := "_" + strings.Repeat("a", n-6) // "k.." + "_5F" + n-6 bytes
		m, got := Member([]string{key})
		if got != ok || ok && len(m) != n {
			t.Errorf("escaped %d bytes: %q %v", n, m, got)
		}
	}
}

func TestCanonicalRefuses(t *testing.T) {
	for _, m := range []string{
		"",
		"k..",        // no key
		"k..a..b",    // plainly expressible
		"k..a",       // plainly expressible
		"k..a_2e",    // lower-case hex
		"k..a_2",     // truncated escape
		"k..a_",      // truncated escape
		"k..a_G0",    // not hex
		"k..a....b",  // empty key
		"k..a..",     // empty last key
		"k....a",     // empty first key
		"k..a...b",   // a key starting with "."
		"k.._41",     // escape of a byte written as itself
		"k.._2F_5Fa", // "/" escaped
		"k..a.b",     // "." inside a key
		"k..a b",     // byte outside the alphabet
		"a..b",       // ".." in the plain form
		"a.",         // empty key
		".a",         // empty key
		"_a",         // plain form needs a leading letter or digit
		"/a",         // plain form needs a leading letter or digit
		"a b",        // byte outside the grammar
		"a.b c",      // byte outside the grammar
		"K..a_2Eb",   // the escaped prefix is lower-case k
		"k..a_2Eb_",  // trailing "_"
		strings.Repeat("a", 129),
		"k.." + strings.Repeat("a", 123) + "_2E",
	} {
		if Canonical(m) {
			t.Errorf("%q accepted", m)
		}
		if p, ok := Path(m); ok {
			t.Errorf("Path(%q) = %q", m, p)
		}
	}
	for _, m := range []string{"a", "a.b", "a._b", "k.a", "k..a_2Eb", "k.._5Fa", "k..a..b_2Ec", "k.._C3_A4"} {
		if !Canonical(m) {
			t.Errorf("%q refused", m)
		}
	}
}

// The two forms never collide: a plain member never holds "..", an escaped
// one always does.
func TestFormsAreDisjoint(t *testing.T) {
	for _, p := range [][]string{{"a"}, {"k", "a"}, {"a", "_b"}, {"A_1", "x-y", "p/q"}} {
		m, _ := Member(p)
		if strings.Contains(m, "..") {
			t.Errorf("plain %q holds ..", m)
		}
	}
	for _, p := range [][]string{{"_a"}, {"a.b"}, {"a", "b c"}, {"/"}} {
		m, _ := Member(p)
		if !strings.HasPrefix(m, EscapedPrefix) {
			t.Errorf("escaped %q", m)
		}
	}
}

func TestSourceCoversThePackage(t *testing.T) {
	dir, files := Source()
	if dir != "helmvaluespath" {
		t.Fatalf("dir %q", dir)
	}
	names, err := fs.Glob(files, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"decode.go", "doc.go", "encode.go", "paths.go"} {
		if !slices.Contains(names, want) {
			t.Fatalf("%s not embedded: %v", want, names)
		}
	}
}
