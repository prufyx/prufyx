// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"errors"
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
