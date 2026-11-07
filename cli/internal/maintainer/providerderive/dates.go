// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"strconv"

	"github.com/prufyx/prufyx/cli/internal/distribution"
)

// Date is one parsed provider date at its own precision. TBD holds no value.
type Date struct {
	Value     string // YYYY-MM-DD, YYYY-MM, YYYY-Qn, or "" for TBD
	Precision string // distribution.Precision*
	Estimate  bool   // the source marks it as a prediction (italics or footnote)
}

// TBD reports a date announced without a value.
func (d Date) TBD() bool { return d.Precision == distribution.PrecisionTBD }

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func daysIn(y, m int) int {
	switch m {
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// ParseISO parses the exact ISO-style grammar: YYYY-MM-DD, YYYY-MM, YYYY-Qn.
func ParseISO(s string) (Date, bool) {
	switch {
	case len(s) == 10 && s[4] == '-' && s[7] == '-' && allDigits(s[:4]) && allDigits(s[5:7]) && allDigits(s[8:]):
		y, m, d := atoi(s[:4]), atoi(s[5:7]), atoi(s[8:])
		if y < 2000 || m < 1 || m > 12 || d < 1 || d > daysIn(y, m) {
			return Date{}, false
		}
		return Date{Value: s, Precision: distribution.PrecisionDay}, true
	case len(s) == 7 && s[4] == '-' && allDigits(s[:4]) && allDigits(s[5:]):
		y, m := atoi(s[:4]), atoi(s[5:])
		if y < 2000 || m < 1 || m > 12 {
			return Date{}, false
		}
		return Date{Value: s, Precision: distribution.PrecisionMonth}, true
	case len(s) == 7 && s[4] == '-' && s[5] == 'Q' && allDigits(s[:4]) && s[6] >= '1' && s[6] <= '4':
		if atoi(s[:4]) < 2000 {
			return Date{}, false
		}
		return Date{Value: s, Precision: distribution.PrecisionQuarter}, true
	}
	return Date{}, false
}

var rank = map[string]int{distribution.PrecisionDay: 0, distribution.PrecisionMonth: 1, distribution.PrecisionQuarter: 2}

// Coarsen returns d at precision p (day -> month -> quarter). It never
// invents detail: asking for a finer precision than d has is refused.
func Coarsen(d Date, p string) (string, bool) {
	if d.TBD() {
		return "", false
	}
	rd, ok1 := rank[d.Precision]
	rp, ok2 := rank[p]
	if !ok1 || !ok2 || rp < rd {
		return "", false
	}
	v := d.Value
	if rd == 0 && rp >= 1 {
		v = v[:7]
	}
	if rd <= 1 && rp == 2 {
		m := atoi(v[5:7])
		v = v[:4] + "-Q" + strconv.Itoa((m-1)/3+1)
	}
	return v, true
}

// Effective is the precision a date may claim: a prediction written as a day
// is only claimed to the month (the row never says "to the day" for an
// estimate).
func Effective(d Date) string {
	if d.Estimate && d.Precision == distribution.PrecisionDay {
		return distribution.PrecisionMonth
	}
	return d.Precision
}

// Unify returns the coarsest effective precision of the non-TBD dates and
// each date at that precision. All TBD (or none) gives precision tbd and no
// values.
func Unify(dates ...Date) (string, []string) {
	p := ""
	for _, d := range dates {
		if d.TBD() {
			continue
		}
		e := Effective(d)
		if p == "" || rank[e] > rank[p] {
			p = e
		}
	}
	out := make([]string, len(dates))
	if p == "" {
		return distribution.PrecisionTBD, out
	}
	for i, d := range dates {
		if d.TBD() {
			continue
		}
		v, _ := Coarsen(d, p)
		out[i] = v
	}
	return p, out
}

// Coarser returns the coarser of two non-TBD precisions.
func Coarser(a, b string) string {
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// LineNum parses a minor line of the 1.N grammar (N one to three ASCII
// digits) and returns N; ok is false for anything else.
func LineNum(line string) (n int, ok bool) {
	if len(line) < 3 || len(line) > 5 || line[0] != '1' || line[1] != '.' || !allDigits(line[2:]) {
		return 0, false
	}
	return atoi(line[2:]), true
}

// ParseLine reports whether s is a minor line of the 1.N grammar.
func ParseLine(s string) bool {
	_, ok := LineNum(s)
	return ok
}
