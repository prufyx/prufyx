// SPDX-License-Identifier: AGPL-3.0-only

package membercode

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func wantNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// TestNameByteEveryValue pins the charset on all 256 byte values, including
// each range edge and its neighbours.
func TestNameByteEveryValue(t *testing.T) {
	edges := map[byte]bool{
		'0' - 1: false /* '/' */, '0': true, '9': true, '9' + 1: false,
		'A' - 1: false, 'A': true, 'Z': true, 'Z' + 1: false,
		'a' - 1: false, 'a': true, 'z': true, 'z' + 1: false,
		'.': true, '_': true, '-': true,
	}
	for c, want := range edges {
		if got := isNameByte(c); got != want {
			t.Errorf("isNameByte(%q) = %v, want %v", c, got, want)
		}
	}
	for i := 0; i < 256; i++ {
		c := byte(i)
		if got := isNameByte(c); got != wantNameByte(c) {
			t.Errorf("isNameByte(%#x) = %v, want %v", c, got, wantNameByte(c))
		}
	}
}

// TestNameByteThroughEncoders checks the same table end to end: a byte in the
// charset is accepted, '/' is ambiguous, every other byte is a charset error.
func TestNameByteThroughEncoders(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := byte(i)
		name := "a" + string([]byte{c}) + "b"
		var want error
		switch {
		case c == '/':
			want = ErrAmbiguous
		case !wantNameByte(c):
			want = ErrCharset
		}
		encoders := map[string]func() (string, error){
			"flag":   func() (string, error) { return Flag(name) },
			"field":  func() (string, error) { return Field("g.io", "K", p(name)) },
			"enum":   func() (string, error) { return Enum("g.io", "K", p("m"), name) },
			"group":  func() (string, error) { return Field(name, "K", p("m")) },
			"kind":   func() (string, error) { return Field("g.io", name, p("m")) },
			"config": func() (string, error) { return ConfigKey(p(name)) },
		}
		for label, f := range encoders {
			c := c
			got, err := f()
			if c == '.' && label == "config" {
				if !errors.Is(err, ErrAmbiguous) {
					t.Errorf("config %q: err %v, want ambiguous", name, err)
				}
				continue
			}
			if !errors.Is(err, want) || (want == nil) != (got != "") {
				t.Errorf("%s %q: got (%q, %v), want err %v", label, name, got, err, want)
			}
		}
	}
}

// TestSeparatorInNameIsAmbiguous covers a separator inside an otherwise valid
// name, and that a bad byte wins over the separator.
func TestSeparatorInNameIsAmbiguous(t *testing.T) {
	if _, err := ConfigKey(p(".")); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("lone dot: %v", err)
	}
	if _, err := ConfigKey(p("a.b@c")); !errors.Is(err, ErrCharset) {
		t.Errorf("dot then bad byte: %v", err)
	}
	if _, err := ConfigKey(p("a@b.c")); !errors.Is(err, ErrCharset) {
		t.Errorf("bad byte then dot: %v", err)
	}
	if _, err := ConfigKey(p("a/b")); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("slash in config name: %v", err)
	}
	// A separator or slash at index 0 is ambiguous, not a charset error.
	for _, name := range []string{".a", "/a", "/"} {
		if _, err := ConfigKey(p(name)); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("config %q: %v", name, err)
		}
		if _, err := Flag(name); name[0] == '/' && !errors.Is(err, ErrAmbiguous) {
			t.Errorf("flag %q: %v", name, err)
		}
		if _, err := Field("g.io", "K", p(name)); name[0] == '/' && !errors.Is(err, ErrAmbiguous) {
			t.Errorf("field %q: %v", name, err)
		}
	}
	if _, err := Field("g.io", "K", p("a.b")); err != nil {
		t.Errorf("dot allowed in field name: %v", err)
	}
	if _, err := Flag("a.b"); err != nil {
		t.Errorf("dot allowed in flag: %v", err)
	}
}

// TestExactLengthLimit: a member of exactly MaxSetMemberBytes is accepted, one
// more byte is ErrTooLong, for every encoder.
func TestExactLengthLimit(t *testing.T) {
	max := constraintengine.MaxSetMemberBytes
	// pad returns a name so that prefix+name has the wanted total length.
	pad := func(total, prefix int) string { return strings.Repeat("a", total-prefix) }
	cases := []struct {
		name string
		enc  func(total int) (string, error)
	}{
		{"flag", func(n int) (string, error) { return Flag(pad(n, 0)) }},
		{"config", func(n int) (string, error) { return ConfigKey(p("s", pad(n, 2))) }},
		{"field", func(n int) (string, error) { return Field("g.io", "K", p(pad(n, len("g.io/K/")))) }},
		{"enum", func(n int) (string, error) { return Enum("g.io", "K", p("m"), pad(n, len("g.io/K/m/"))) }},
		{"item path", func(n int) (string, error) {
			return Field("g.io", "K", append(p(pad(n, len("g.io/K/")+len("/_item_"))), Seg{Kind: Item}))
		}},
	}
	for _, tc := range cases {
		got, err := tc.enc(max)
		if err != nil || len(got) != max {
			t.Errorf("%s at %d: got (len %d, %v)", tc.name, max, len(got), err)
		}
		got, err = tc.enc(max - 1)
		if err != nil || len(got) != max-1 {
			t.Errorf("%s at %d: got (len %d, %v)", tc.name, max-1, len(got), err)
		}
		if got, err = tc.enc(max + 1); !errors.Is(err, ErrTooLong) || got != "" {
			t.Errorf("%s at %d: got (%q, %v), want ErrTooLong", tc.name, max+1, got, err)
		}
	}
}

func TestDecodeAtLimit(t *testing.T) {
	max := constraintengine.MaxSetMemberBytes
	m, err := Field("g.io", "K", p(strings.Repeat("a", max-len("g.io/K/"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := DecodeField(m); !ok {
		t.Error("DecodeField rejects a member of exactly the limit")
	}
	if _, _, _, ok := DecodeField(m + "a"); ok {
		t.Error("DecodeField accepts a member over the limit")
	}
}
