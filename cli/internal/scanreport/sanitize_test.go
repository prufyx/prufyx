// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"printable", "deploy/app 1.yaml:3 CronJob prod/job-1 \\ \"q\" é日本", "deploy/app 1.yaml:3 CronJob prod/job-1 \\ \"q\" é日本"},
		{"csi", "a\x1b[2Jb", `a\x1b[2Jb`},
		{"osc-bel", "\x1b]0;t\x07", `\x1b]0;t\x07`},
		{"cr-lf-tab", "a\r\n\tb", `a\x0d\x0a\x09b`},
		{"del", "\x7f", `\x7f`},
		{"c1", "\u009b", `\x9b`},
		{"nul", "\x00", `\x00`},
		{"bidi", "\u202e\u2066\u061c", `\u202e\u2066\u061c`},
		{"separators", "\u2028\u2029", `\u2028\u2029`},
		{"zero-width-bom", "\u200b\u200d\U0000feff", `\u200b\u200d\ufeff`},
		{"tag-char", "\U000e0041", `\U000e0041`},
		{"invalid-utf8", "a\xffb\xc3", `a\xffb\xc3`},
		{"encoded-surrogate", "\xed\xa0\x80", `\xed\xa0\x80`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Sanitize(c.in)
			if got != c.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := Sanitize(got); again != got {
				t.Fatalf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestSanitizeArgsLeavesNonStrings(t *testing.T) {
	got := sanitizeArgs([]any{"a\x1b", 7, errors.New("e\r"), true})
	want := []any{`a\x1b`, 7, `e\x0d`, true}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestTextSanitizesArguments(t *testing.T) {
	if got := Text("bad %s", "x\x1b[2J\nPASS"); got != `bad x\x1b[2J\x0aPASS` {
		t.Fatalf("Text = %q", got)
	}
}

// TestEscapeJSONKeepsValues: the escaped JSON decodes to the same strings.
func TestEscapeJSONKeepsValues(t *testing.T) {
	for _, hostile := range hostileStrings {
		t.Run(hostile.name, func(t *testing.T) {
			in := []string{hostile.value, "\U000e0041\u009b"}
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			var back []string
			if err := json.Unmarshal(escapeJSON(raw), &back); err != nil {
				t.Fatal(err)
			}
			var plain []string
			if err := json.Unmarshal(raw, &plain); err != nil {
				t.Fatal(err)
			}
			for i := range plain {
				if back[i] != plain[i] {
					t.Fatalf("value %d changed: %q vs %q", i, back[i], plain[i])
				}
			}
		})
	}
}
