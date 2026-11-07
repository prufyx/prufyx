// SPDX-License-Identifier: AGPL-3.0-only

// Package shared holds the pieces every provider extractor uses: the typed
// drift error, response and excerpt guards, and the strict date-cell grammar.
// Everything is offline and deterministic; nothing here fetches.
package shared

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// ErrDrift is wrapped by every extractor rejection: the source no longer has
// the shape the extractor was written for (or never had). No partial output
// accompanies it.
var ErrDrift = errors.New("provider source drift")

// Kinds of drift.
const (
	KindStatus     = "status"     // non-200 answer
	KindEmpty      = "empty"      // empty body
	KindFormat     = "format"     // wrong content type, encoding, size or structure
	KindHeader     = "header"     // header column set or anchor changed
	KindMissing    = "missing"    // required field, column or section absent
	KindUnparsable = "unparsable" // a cell or row outside the grammar
	KindPrerelease = "prerelease" // a prerelease where a release is required
	KindConflict   = "conflict"   // two views of one fact disagree
	KindExcerpt    = "excerpt"    // excerpt or manifest metadata unusable
)

// Error is the typed drift error.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%s): %s", ErrDrift.Error(), e.Kind, e.Msg) }
func (e *Error) Unwrap() error { return ErrDrift }

// Drift builds a typed drift error.
func Drift(kind, format string, args ...any) error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// KindOf returns the drift kind of err, or "" when err is not a drift error.
func KindOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// MaxPage caps any page or file an extractor accepts.
const MaxPage = 1 << 20

// CheckResponse is the guard for a fetched answer, applied by the caller
// before parsing: only a 200 with a body of an expected type is accepted.
// contentType matches when it starts with one of want (parameters ignored).
func CheckResponse(status int, contentType string, body []byte, want ...string) error {
	if status != 200 {
		return Drift(KindStatus, "HTTP status %d", status)
	}
	if err := CheckBody(body); err != nil {
		return err
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	for _, w := range want {
		if ct == w {
			return nil
		}
	}
	return Drift(KindFormat, "content type %q", contentType)
}

// CheckBody rejects an empty, oversized, non-UTF-8 or NUL-bearing body.
func CheckBody(body []byte) error {
	if len(body) == 0 {
		return Drift(KindEmpty, "empty body")
	}
	if len(body) > MaxPage {
		return Drift(KindFormat, "body of %d bytes exceeds the %d byte cap", len(body), MaxPage)
	}
	if !utf8.Valid(body) {
		return Drift(KindFormat, "body is not UTF-8")
	}
	if strings.IndexByte(string(body), 0) >= 0 {
		return Drift(KindFormat, "body holds a NUL byte")
	}
	return nil
}

// Body validates an excerpt against its manifest entry (the providerexcerpt
// rules: digest, header agreement, licence form) and returns the body text.
func Body(e providerexcerpt.Entry, data []byte) (string, error) {
	start, end, err := providerexcerpt.ParseExcerpt(e, data)
	if err != nil {
		return "", Drift(KindExcerpt, "%v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	return strings.Join(lines[start-1:end], "\n") + "\n", nil
}

// FetchedDate returns the YYYY-MM-DD day of an entry's fetchedAt.
func FetchedDate(e providerexcerpt.Entry) (string, error) {
	t, err := time.Parse(time.RFC3339, e.FetchedAt)
	if err != nil {
		return "", Drift(KindExcerpt, "fetchedAt %q", e.FetchedAt)
	}
	return t.UTC().Format("2006-01-02"), nil
}

// Cell is one parsed date cell.
type Cell struct {
	Value     string // YYYY-MM-DD, YYYY-MM, YYYY-Qn, or "" for TBD
	Precision string // distribution.Precision*
	Footnote  string // marker text when AllowFootnote was set
}

var months = map[string]int{"January": 1, "February": 2, "March": 3, "April": 4, "May": 5, "June": 6,
	"July": 7, "August": 8, "September": 9, "October": 10, "November": 11, "December": 12}

// ParseCell parses one date cell with the strict grammar: day (`January 2,
// 2006` or `2006-01-02`), month (`January 2006` or `2006-01`), quarter
// (`2006-Q1`) and `TBD`. A trailing footnote marker (`*`, a dagger, or a
// space and 1-2 digits) is accepted only when allowFootnote is set. Anything
// else is an unparsable cell.
func ParseCell(raw string, allowFootnote bool) (Cell, error) {
	s := strings.TrimSpace(raw)
	c := Cell{}
	if allowFootnote {
		s, c.Footnote = splitFootnote(s)
	}
	fail := func() (Cell, error) { return Cell{}, Drift(KindUnparsable, "date cell %q", raw) }
	if s == "" {
		return fail()
	}
	if s == "TBD" {
		c.Precision = distribution.PrecisionTBD
		return c, nil
	}
	if len(s) == 10 && s[4] == '-' && s[7] == '-' {
		t, err := time.Parse("2006-01-02", s)
		if err != nil || t.Format("2006-01-02") != s || t.Year() < 2000 {
			return fail()
		}
		c.Value, c.Precision = s, distribution.PrecisionDay
		return c, nil
	}
	if len(s) == 7 && s[4] == '-' {
		if s[5] == 'Q' {
			if s[6] < '1' || s[6] > '4' || !allDigits(s[:4]) || s[:4] < "2000" {
				return fail()
			}
			c.Value, c.Precision = s, distribution.PrecisionQuarter
			return c, nil
		}
		m, err := strconv.Atoi(s[5:])
		if err != nil || !allDigits(s[:4]) || !allDigits(s[5:]) || s[:4] < "2000" || m < 1 || m > 12 {
			return fail()
		}
		c.Value, c.Precision = s, distribution.PrecisionMonth
		return c, nil
	}
	f := strings.Split(s, " ")
	switch len(f) {
	case 3: // Month D, YYYY
		mo, ok := months[f[0]]
		d := strings.TrimSuffix(f[1], ",")
		if !ok || d == f[1] || !allDigits(d) || len(d) > 2 || d[0] == '0' || !allDigits(f[2]) || len(f[2]) != 4 {
			return fail()
		}
		day, _ := strconv.Atoi(d)
		v := fmt.Sprintf("%s-%02d-%02d", f[2], mo, day)
		t, err := time.Parse("2006-01-02", v)
		if err != nil || t.Format("2006-01-02") != v || t.Year() < 2000 {
			return fail()
		}
		c.Value, c.Precision = v, distribution.PrecisionDay
		return c, nil
	case 2: // Month YYYY
		mo, ok := months[f[0]]
		if !ok || !allDigits(f[1]) || len(f[1]) != 4 || f[1] < "2000" {
			return fail()
		}
		c.Value, c.Precision = fmt.Sprintf("%s-%02d", f[1], mo), distribution.PrecisionMonth
		return c, nil
	}
	return fail()
}

func splitFootnote(s string) (string, string) {
	for _, m := range []string{"*", "†", "‡"} {
		if strings.HasSuffix(s, m) {
			return strings.TrimSpace(strings.TrimSuffix(s, m)), m
		}
	}
	if i := strings.LastIndexByte(s, ' '); i > 0 {
		tail := s[i+1:]
		if len(tail) <= 2 && allDigits(tail) && !strings.HasSuffix(strings.TrimSpace(s[:i]), ",") && len(strings.Fields(s[:i])) >= 1 {
			head := strings.TrimSpace(s[:i])
			// "January 2006" must not lose its year: only strip when the head
			// still ends in a date-shaped token.
			if hasDateTail(head) {
				return head, tail
			}
		}
	}
	return s, ""
}

func hasDateTail(h string) bool {
	if h == "TBD" {
		return true
	}
	f := strings.Fields(h)
	last := f[len(f)-1]
	return (len(last) == 4 && allDigits(last)) || (len(last) == 7 && last[4] == '-') || (len(last) == 10 && last[4] == '-')
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
