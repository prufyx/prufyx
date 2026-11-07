// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/distribution"
)

func TestUnifyCoarsensToTheCoarsestPrecision(t *testing.T) {
	d := func(s string, est bool) Date {
		x, ok := ParseISO(s)
		if !ok {
			t.Fatal(s)
		}
		x.Estimate = est
		return x
	}
	tbd := Date{Precision: distribution.PrecisionTBD}
	for _, c := range []struct {
		in   []Date
		p    string
		want []string
	}{
		{[]Date{d("2031-05-17", false), d("2031-06-30", false)}, "day", []string{"2031-05-17", "2031-06-30"}},
		{[]Date{d("2031-05-17", false), d("2031-06", false)}, "month", []string{"2031-05", "2031-06"}},
		{[]Date{d("2031-05-17", false), d("2031-Q3", false)}, "quarter", []string{"2031-Q2", "2031-Q3"}},
		{[]Date{d("2031-12", false), d("2032-Q1", false)}, "quarter", []string{"2031-Q4", "2032-Q1"}},
		{[]Date{d("2031-05-17", true), d("2031-06-30", false)}, "month", []string{"2031-05", "2031-06"}}, // estimate day claims the month only
		{[]Date{tbd, d("2031-06-30", false)}, "day", []string{"", "2031-06-30"}},
		{[]Date{tbd, tbd}, "tbd", []string{"", ""}},
	} {
		p, v := Unify(c.in...)
		if p != c.p || v[0] != c.want[0] || v[1] != c.want[1] {
			t.Fatalf("%v: got %s %v want %s %v", c.in, p, v, c.p, c.want)
		}
	}
	for _, bad := range []string{"2031-13", "2031-Q5", "2031-02-30", "2031-2-03", "1999-01", "31-01-2031", "2031-01-01 "} {
		if _, ok := ParseISO(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, ok := Coarsen(d("2031-Q3", false), "day"); ok {
		t.Fatal("refined a quarter to a day")
	}
}

func TestDriftErrorIsTyped(t *testing.T) {
	err := Drift("x", KindRow, "bad %d", 1)
	var de *DriftError
	if !errors.As(err, &de) || !errors.Is(err, ErrDrift) || de.Kind != KindRow {
		t.Fatal("not typed")
	}
}

func TestLineNumGrammar(t *testing.T) {
	for s, want := range map[string]int{"1.0": 0, "1.34": 34, "1.123": 123} {
		if n, ok := LineNum(s); !ok || n != want || !ParseLine(s) {
			t.Fatalf("%q: %d %v", s, n, ok)
		}
	}
	for _, s := range []string{"", "1.", "1.1234", "2.3", "1.+3", "1.3a", "1.٣", " 1.3", "1.-1"} {
		if _, ok := LineNum(s); ok || ParseLine(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestExcerptFailuresAreDrift(t *testing.T) {
	_, err := Body("src-x", Excerpt{})
	var d *DriftError
	if !errors.As(err, &d) || !errors.Is(err, ErrDrift) || d.Kind != KindExcerpt || d.Source != "src-x" {
		t.Fatalf("Body: %v", err)
	}
	_, _, err = Compose("src-y", Spec{ID: "x"}, "b")
	if !errors.As(err, &d) || !errors.Is(err, ErrDrift) || d.Kind != KindExcerpt || d.Source != "src-y" {
		t.Fatalf("Compose: %v", err)
	}
}

func TestChunkLinesCapsLines(t *testing.T) {
	var rows []string
	for i := 0; i < 130; i++ {
		rows = append(rows, "r")
	}
	out, err := ChunkLines("s", "h", rows, 1<<20)
	if err != nil || len(out) < 3 {
		t.Fatalf("%d %v", len(out), err)
	}
	for _, c := range out {
		if n := strings.Count(c, "\n"); n > 64 {
			t.Fatalf("chunk of %d lines", n)
		}
	}
}
