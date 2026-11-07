// SPDX-License-Identifier: AGPL-3.0-only

// Package gke turns the GKE release schedule page and the GKE release-notes
// feed into provider lifecycle rows. Page parsing is strict: the exact header
// set, every row, every cell; one bad row is a typed drift error and there is
// no partial output. Derivation reads only committed paraphrase excerpts.
package gke

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/htmltable"
)

const (
	srcSchedule = "gke-schedule"
	// ScheduleFormat is the first body line of a schedule excerpt.
	ScheduleFormat = "format gke-schedule/v1"
	// MaxBody is the excerpt body cap (providerexcerpt.MaxParaphrase).
	MaxBody = 1024
	// Distribution is the record id of the facts.
	Distribution = "gke"
)

// Channels is the closed channel set in record order (ascending by name).
var Channels = []string{"extended", "rapid", "regular", "stable"}

// SourceHosts are the hosts a GKE excerpt may cite (the old host redirects to
// the canonical one; both are the vendor's).
var SourceHosts = map[string]bool{"cloud.google.com": true, "docs.cloud.google.com": true}

// Cell is one schedule date cell as the page states it.
type Cell = pd.Date

// Row is one schedule row: the minor line and its ten date cells in header
// order: rapid, regular, stable, extended (available, auto upgrade each),
// end of standard support, end of extended support.
type Row struct {
	Line  string
	Dates [10]Cell
}

// Schedule is the parsed table.
type Schedule struct{ Rows []Row }

var (
	lineRE    = regexp.MustCompile(`^1\.[0-9]{1,3}$`)
	markersOK = map[string]bool{"4": true, "5": true}
)

// Exact header sets (column labels with footnote markers removed).
var (
	headTop = []string{"Minor version ( release date )", "Rapid", "Regular", "Stable", "Extended", "End of standard support (formerly end of life )", "End of extended support"}
	topSpan = [][2]int{{2, 1}, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {2, 1}, {2, 1}} // rowspan, colspan
)

const (
	pairAvail = "Available"
	pairAuto  = "Auto Upgrade"
)

// ParseSchedule reads the release schedule page bytes. Exactly one table must
// carry the anchored header; every row must parse.
func ParseSchedule(page []byte) (Schedule, error) {
	if len(page) == 0 {
		return Schedule{}, pd.Drift(srcSchedule, pd.KindEmpty, "no page bytes")
	}
	tables, err := htmltable.Parse(page)
	if err != nil {
		return Schedule{}, pd.Drift(srcSchedule, pd.KindStructure, "%v", err)
	}
	if len(tables) == 0 {
		return Schedule{}, pd.Drift(srcSchedule, pd.KindEmpty, "page holds no table")
	}
	var found []htmltable.Table
	for _, t := range tables {
		if len(t.Rows) >= 2 && len(t.Rows[0]) > 0 && strings.HasPrefix(t.Rows[0][0].Text, "Minor version") {
			found = append(found, t)
		}
	}
	if len(found) != 1 {
		return Schedule{}, pd.Drift(srcSchedule, pd.KindHeader, "%d tables carry the schedule header, want exactly 1", len(found))
	}
	t := found[0]
	if err := checkHeader(t); err != nil {
		return Schedule{}, err
	}
	var s Schedule
	for i, cells := range t.Rows[2:] {
		r, err := parseRow(cells)
		if err != nil {
			k := pd.KindRow
			var ce *cellErr
			if errors.As(err, &ce) {
				k = ce.kind
			}
			return Schedule{}, pd.Drift(srcSchedule, k, "data row %d: %v", i+1, err)
		}
		s.Rows = append(s.Rows, r)
	}
	if len(s.Rows) == 0 {
		return Schedule{}, pd.Drift(srcSchedule, pd.KindEmpty, "table has no data rows")
	}
	if err := s.check(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

func checkHeader(t htmltable.Table) error {
	top, sub := t.Rows[0], t.Rows[1]
	if len(top) != len(headTop) {
		return pd.Drift(srcSchedule, pd.KindHeader, "top header has %d cells, want %d", len(top), len(headTop))
	}
	for i, c := range top {
		if !c.Header || c.Text != headTop[i] || c.RowSpan != topSpan[i][0] || c.ColSpan != topSpan[i][1] {
			return pd.Drift(srcSchedule, pd.KindHeader, "top header cell %d differs from the anchored set", i+1)
		}
		if len(c.Markers) > 1 {
			return pd.Drift(srcSchedule, pd.KindMarker, "header cell %d carries several markers", i+1)
		}
	}
	if len(sub) != 8 {
		return pd.Drift(srcSchedule, pd.KindHeader, "second header row has %d cells, want 8", len(sub))
	}
	for i, c := range sub {
		want := pairAvail
		if i%2 == 1 {
			want = pairAuto
		}
		if !c.Header || c.Text != want || c.RowSpan != 1 || c.ColSpan != 1 {
			return pd.Drift(srcSchedule, pd.KindHeader, "second header cell %d differs from the anchored set", i+1)
		}
	}
	// The spans must expand to a rectangular 11-slot grid.
	g, err := htmltable.Grid(t.Rows[:2])
	if err != nil || len(g) != 2 || len(g[0]) != 11 {
		return pd.Drift(srcSchedule, pd.KindHeader, "header spans do not expand to 11 columns")
	}
	return nil
}

// cellErr marks an error as a cell-grammar problem (kind cell or marker).
type cellErr struct {
	kind string
	msg  string
}

func (e *cellErr) Error() string { return e.msg }

func parseRow(cells []htmltable.Cell) (Row, error) {
	var r Row
	if len(cells) != 11 {
		return r, fmt.Errorf("%d cells, want 11", len(cells))
	}
	for i, c := range cells {
		if c.RowSpan != 1 || c.ColSpan != 1 {
			return r, fmt.Errorf("cell %d uses a span", i+1)
		}
	}
	if !lineRE.MatchString(cells[0].Text) || len(cells[0].Markers) != 0 {
		return r, fmt.Errorf("first cell is not a minor line")
	}
	r.Line = cells[0].Text
	for i, c := range cells[1:] {
		d, err := parseCell(c)
		if err != nil {
			var ce *cellErr
			if errors.As(err, &ce) {
				return r, &cellErr{ce.kind, fmt.Sprintf("date cell %d: %s", i+1, ce.msg)}
			}
			return r, fmt.Errorf("date cell %d: %v", i+1, err)
		}
		r.Dates[i] = d
	}
	return r, nil
}

func parseCell(c htmltable.Cell) (Cell, error) {
	for _, m := range c.Markers {
		if !markersOK[m] {
			return Cell{}, &cellErr{pd.KindMarker, "unknown footnote marker"}
		}
	}
	est := c.Italic || len(c.Markers) > 0
	if c.Text == "TBD" {
		return Cell{Precision: distribution.PrecisionTBD, Estimate: est}, nil
	}
	d, ok := pd.ParseISO(c.Text)
	if !ok {
		return Cell{}, &cellErr{pd.KindCell, "not a day, month, quarter or TBD value"}
	}
	d.Estimate = est
	return d, nil
}

// Cheap invariants: rows strictly ascending by minor; per channel available
// <= auto upgrade; end of standard <= end of extended (compared at the
// coarser precision of the pair).
func (s Schedule) check() error {
	prev := -1
	for _, r := range s.Rows {
		n := atoi(r.Line[2:])
		if n <= prev {
			return pd.Drift(srcSchedule, pd.KindRow, "lines are not strictly ascending at %s", r.Line)
		}
		prev = n
		for ch := 0; ch < 4; ch++ {
			if !leq(r.Dates[2*ch], r.Dates[2*ch+1]) {
				return pd.Drift(srcSchedule, pd.KindRow, "%s: available is after auto upgrade (%s)", r.Line, Channels2[ch])
			}
		}
		if !leq(r.Dates[8], r.Dates[9]) {
			return pd.Drift(srcSchedule, pd.KindRow, "%s: end of standard support is after end of extended support", r.Line)
		}
	}
	return nil
}

// Channels2 is the header order of the channel pairs.
var Channels2 = []string{"rapid", "regular", "stable", "extended"}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// leq compares two dates at the coarser of their two precisions; a TBD side
// compares as true.
func leq(a, b Cell) bool {
	if a.TBD() || b.TBD() {
		return true
	}
	p := pd.Coarser(a.Precision, b.Precision)
	av, ok1 := pd.Coarsen(a, p)
	bv, ok2 := pd.Coarsen(b, p)
	return ok1 && ok2 && av <= bv
}

// token renders a cell for an excerpt body: the value (or tbd) and "~" when
// the source marks it as a prediction.
func token(c Cell) string {
	v := c.Value
	if c.TBD() {
		v = "tbd"
	}
	if c.Estimate {
		v += "~"
	}
	return v
}

// Bodies renders the schedule as paraphrase excerpt bodies of at most MaxBody
// bytes: one line per minor, ten date tokens in header order.
func (s Schedule) Bodies() ([]string, error) {
	var rows []string
	for _, r := range s.Rows {
		parts := []string{r.Line}
		for _, d := range r.Dates {
			parts = append(parts, token(d))
		}
		rows = append(rows, strings.Join(parts, " "))
	}
	return pd.ChunkLines(srcSchedule, ScheduleFormat, rows, MaxBody)
}
