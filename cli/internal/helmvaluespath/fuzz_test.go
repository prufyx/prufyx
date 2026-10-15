// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// splitKeys turns fuzz input into a key path: keys separated by NUL, so a
// key may hold any other byte, "." and "_" included.
func splitKeys(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// Path(Member(p)) == p for every path Member accepts, and the member is
// inside the engine's grammar and bound.
func FuzzMemberRoundTrip(f *testing.F) {
	for _, s := range []string{"a", "a\x00b", "_a", "a.b", "annotations\x00nginx.ingress.kubernetes.io/proxy-body-size", "ä\x00 ", "k\x00a", "-", ".\x00.", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		path := splitKeys(s)
		m, ok := Member(path)
		if !ok {
			// Only the root, an empty key or the bound refuse a path.
			if len(path) > 0 && !slices.Contains(path, "") && len(strings.Join(path, ".")) <= MaxMemberBytes && plainPath(path) {
				t.Fatalf("plain path %q refused", path)
			}
			return
		}
		if !constraintengine.ValidSetMember(m) {
			t.Fatalf("member %q of %q outside the engine grammar", m, path)
		}
		if strings.Contains(m, "..") == plainPath(path) {
			t.Fatalf("member %q of %q in the wrong form", m, path)
		}
		back, ok := Path(m)
		if !ok || !slices.Equal(back, path) {
			t.Fatalf("Path(%q) = %q %v, want %q", m, back, ok, path)
		}
	})
}

// Member(Path(m)) == m for every member Path accepts; any accepted member
// is in the engine grammar, and parse never accepts a member whose path
// renders differently without Path refusing it.
func FuzzPathRoundTrip(f *testing.F) {
	for _, s := range []string{"a", "a.b", "k..a_2Eb", "k..a..b", "k..a_2e", "k..", "k..a....b", "k..a_2", "k.._C3_A4", "a._b", "_a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, m string) {
		path, ok := Path(m)
		if !ok {
			if Canonical(m) {
				t.Fatalf("%q canonical but refused", m)
			}
			return
		}
		if !Canonical(m) || !constraintengine.ValidSetMember(m) {
			t.Fatalf("%q accepted but not canonical or outside the grammar", m)
		}
		again, ok := Member(path)
		if !ok || again != m {
			t.Fatalf("Member(Path(%q)) = %q %v", m, again, ok)
		}
	})
}

// The decoder never panics, and a decoded document's paths read back and
// render as members inside the grammar.
func FuzzDecodeYAML(f *testing.F) {
	for _, s := range []string{"a: {b: 1}\n", "\"a.b\": {c: 1}\n", "a: &x 1\n", "\"on\": 1\n", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, v, err := DecodeYAML(data)
		if err != nil {
			return
		}
		for _, p := range ValuePaths(v) {
			if got, ok := ValueAt(v, p); !ok || got == nil {
				t.Fatalf("path %q does not read back", p)
			}
			if m, ok := Member(p); ok {
				if back, ok := Path(m); !ok || !slices.Equal(back, p) {
					t.Fatalf("member %q of %q does not read back", m, p)
				}
			}
		}
	})
}
