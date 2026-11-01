// SPDX-License-Identifier: AGPL-3.0-only

package membercode

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func p(names ...string) []Seg {
	var out []Seg
	for _, n := range names {
		switch n {
		case "[]":
			out = append(out, Seg{Kind: Item})
		case "*":
			out = append(out, Seg{Kind: Any})
		default:
			out = append(out, Seg{Kind: Prop, Name: n})
		}
	}
	return out
}

func TestGoldenVectors(t *testing.T) {
	long := strings.Repeat("a", 120)
	tests := []struct {
		name string
		got  func() (string, error)
		want string
		err  error
	}{
		{"field", func() (string, error) { return Field("keda.sh", "ScaledJob", p("spec", "jobTargetRef")) }, "keda.sh/ScaledJob/spec/jobTargetRef", nil},
		{"field item and any", func() (string, error) { return Field("a.io", "K", p("spec", "list", "[]", "m", "*", "x")) }, "a.io/K/spec/list/_item_/m/_any_/x", nil},
		{"enum", func() (string, error) { return Enum("a.io", "K", p("spec", "mode"), "Never") }, "a.io/K/spec/mode/Never", nil},
		{"flag", func() (string, error) { return Flag("feature-gates") }, "feature-gates", nil},
		{"config key", func() (string, error) { return ConfigKey(p("server", "tls", "[]", "cert")) }, "server.tls._item_.cert", nil},
		{"space", func() (string, error) { return Field("a.io", "K", p("spec", "a b")) }, "", ErrCharset},
		{"at sign", func() (string, error) { return Field("a.io", "K", p("spec", "a@b")) }, "", ErrCharset},
		{"non ascii", func() (string, error) { return Field("a.io", "K", p("spec", "é")) }, "", ErrCharset},
		{"empty name", func() (string, error) { return Field("a.io", "K", p("spec", "")) }, "", ErrCharset},
		{"slash in name", func() (string, error) { return Field("a.io", "K", p("spec", "a/b")) }, "", ErrAmbiguous},
		{"reserved item", func() (string, error) { return Field("a.io", "K", p("spec", "_item_")) }, "", ErrAmbiguous},
		{"reserved any", func() (string, error) { return Field("a.io", "K", p("_any_")) }, "", ErrAmbiguous},
		{"too long", func() (string, error) { return Field("a.io", "K", p("spec", long)) }, "", ErrTooLong},
		{"enum value slash", func() (string, error) { return Enum("a.io", "K", p("m"), "a/b") }, "", ErrAmbiguous},
		{"enum value space", func() (string, error) { return Enum("a.io", "K", p("m"), "a b") }, "", ErrCharset},
		{"enum value empty", func() (string, error) { return Enum("a.io", "K", p("m"), "") }, "", ErrCharset},
		{"config dot in name", func() (string, error) { return ConfigKey(p("a.b")) }, "", ErrAmbiguous},
		{"flag with slash", func() (string, error) { return Flag("serve/port") }, "", ErrAmbiguous},
		{"empty path", func() (string, error) { return Field("a.io", "K", nil) }, "", ErrCharset},
		{"leading dot group", func() (string, error) { return Field(".io", "K", p("a")) }, "", ErrCharset},
	}
	for _, tc := range tests {
		got, err := tc.got()
		if !errors.Is(err, tc.err) || got != tc.want {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.name, got, err, tc.want, tc.err)
		}
	}
}

// TestRoundTripAndInjective enumerates random paths over an alphabet that
// includes every hazard and requires: every accepted encoding decodes back to
// its input, and no two distinct inputs share a member.
func TestRoundTripAndInjective(t *testing.T) {
	names := []string{"a", "b", "ab", "a.b", "a-b", "a_b", "_item_", "_any_", "x/y", "a b", "", "A", "0", ".", "-"}
	rng := rand.New(rand.NewSource(1))
	seen := map[string]string{}
	accepted := 0
	for i := 0; i < 20000; i++ {
		n := 1 + rng.Intn(4)
		var path []Seg
		for j := 0; j < n; j++ {
			switch rng.Intn(6) {
			case 0:
				path = append(path, Seg{Kind: Item})
			case 1:
				path = append(path, Seg{Kind: Any})
			default:
				path = append(path, Seg{Kind: Prop, Name: names[rng.Intn(len(names))]})
			}
		}
		m, err := Field("g.io", "K", path)
		if err != nil {
			continue
		}
		accepted++
		g, k, back, ok := DecodeField(m)
		if !ok || g != "g.io" || k != "K" || len(back) != len(path) {
			t.Fatalf("round trip failed for %q", m)
		}
		for x := range path {
			if back[x] != path[x] {
				t.Fatalf("round trip %q: seg %d %v != %v", m, x, back[x], path[x])
			}
		}
		key := ""
		for _, s := range path {
			key += string(rune('0'+s.Kind)) + ":" + s.Name + "|"
		}
		if prev, dup := seen[m]; dup && prev != key {
			t.Fatalf("member %q encodes both %q and %q", m, prev, key)
		}
		seen[m] = key

		if len(path) > 0 {
			em, err := Enum("g.io", "K", path, "v1")
			if err == nil {
				_, _, bp, val, ok := DecodeEnum(em)
				if !ok || val != "v1" || len(bp) != len(path) {
					t.Fatalf("enum round trip failed for %q", em)
				}
			}
		}
	}
	if accepted < 1000 {
		t.Fatalf("only %d accepted encodings, generator is too narrow", accepted)
	}
}

func TestDecodeRejectsForeign(t *testing.T) {
	for _, m := range []string{"", "a", "a/b", "g.io/K//x", "g.io/K/a b/x", "g.io/K/x/"} {
		if _, _, _, ok := DecodeField(m); ok {
			t.Errorf("DecodeField(%q) accepted", m)
		}
	}
}
