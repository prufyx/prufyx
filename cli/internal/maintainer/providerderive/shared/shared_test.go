// SPDX-License-Identifier: AGPL-3.0-only

package shared

import (
	"errors"
	"testing"
)

func TestParseCell(t *testing.T) {
	good := []struct {
		raw, val, prec, foot string
		fn                   bool
	}{
		{"December 1, 2027", "2027-12-01", "day", "", false},
		{"2027-12-01", "2027-12-01", "day", "", false},
		{"December 2027", "2027-12", "month", "", false},
		{"2027-12", "2027-12", "month", "", false},
		{"2027-Q3", "2027-Q3", "quarter", "", false},
		{"TBD", "", "tbd", "", false},
		{"2026-12 4", "2026-12", "month", "4", true},
		{"2027-Q3*", "2027-Q3", "quarter", "*", true},
		{"December 1, 2027 †", "2027-12-01", "day", "†", true},
		{"December 2027", "2027-12", "month", "", true},
	}
	for _, c := range good {
		got, err := ParseCell(c.raw, c.fn)
		if err != nil || got.Value != c.val || got.Precision != c.prec || got.Footnote != c.foot {
			t.Errorf("%q: %+v %v", c.raw, got, err)
		}
	}
	bad := []struct {
		raw string
		fn  bool
	}{
		{"", false}, {"Dec 1, 2027", false}, {"December 01, 2027", false}, {"December 1 2027", false},
		{"2026-13-01", false}, {"2026-02-30", false}, {"2027-Q5", false}, {"2027-13", false}, {"tbd", false},
		{"December 1, 2027*", false}, {"2026-12 4", false}, {"2027-Q3 99x", true}, {"1.37", true}, {"soon", true},
		{"December 32, 2027", false}, {"1999-01-01", false},
	}
	for _, c := range bad {
		if _, err := ParseCell(c.raw, c.fn); err == nil || !errors.Is(err, ErrDrift) || KindOf(err) != KindUnparsable {
			t.Errorf("%q accepted or wrong error: %v", c.raw, err)
		}
	}
}

func TestCheckResponse(t *testing.T) {
	if err := CheckResponse(200, "text/plain; charset=utf-8", []byte("x"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		st   int
		ct   string
		body []byte
		kind string
	}{
		"404":      {404, "text/plain", []byte("x"), KindStatus},
		"empty":    {200, "text/plain", nil, KindEmpty},
		"html":     {200, "text/html", []byte("<html>"), KindFormat},
		"non-utf8": {200, "text/plain", []byte{0xff, 0xfe}, KindFormat},
		"nul":      {200, "text/plain", []byte("a\x00b"), KindFormat},
		"oversize": {200, "text/plain", make([]byte, MaxPage+1), KindFormat},
	} {
		if err := CheckResponse(c.st, c.ct, c.body, "text/plain"); KindOf(err) != c.kind {
			t.Errorf("%s: %v", name, err)
		}
	}
}
