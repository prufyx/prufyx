// SPDX-License-Identifier: AGPL-3.0-only

// Package aks turns the AKS supported-versions page and the AKS GitHub
// releases list into provider lifecycle rows. The lifecycle tables are found
// by their exact header text, never by position. Any surprise is a typed drift
// error; there is no partial output. Derivation reads only committed
// paraphrase excerpts.
package aks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/htmltable"
)

const (
	srcSupport = "aks-support"
	// SupportFormat is the first body line of a support-table excerpt.
	SupportFormat = "format aks-support/v1"
	MaxBody       = 1024
	Distribution  = "aks"
	// SupportHost and SupportPath are the anchored source of the page.
	SupportHost = "learn.microsoft.com"
	SupportPath = "/en-us/azure/aks/supported-kubernetes-versions"
)

// Value kinds of an AKS cell.
const (
	KindDate  = "date"
	KindTBD   = "tbd"
	KindUntil = "until" // "Until 1.N GA": relative to a later line's GA, not a date
)

// Cell is one date-like cell as the page states it.
type Cell struct {
	Kind      string
	Date      pd.Date // KindDate
	UntilLine string  // KindUntil: the line whose GA ends it, e.g. "1.36"
}

// Row is one table row. Upstream, Preview, GA and EOL exist in both tables;
// Platform (standard table) or LTSEnd (LTS table) is the column that differs;
// PlatformUpgrade is the platform-initiated upgrade column.
type Row struct {
	Line            string
	Upstream        Cell
	Preview         Cell
	GA              Cell
	EOL             Cell
	Platform        Cell // standard table only
	LTSEnd          Cell // LTS table only
	PlatformUpgrade Cell
}

// Support is the two parsed lifecycle tables.
type Support struct {
	Standard []Row
	LTS      []Row
}

var (
	stdHeader = []string{"Kubernetes version", "Upstream release", "AKS preview", "AKS GA", "End of life", "Platform support", "Platform-initiated upgrade"}
	ltsHeader = []string{"Kubernetes version", "Upstream release", "AKS preview", "AKS GA", "End of life", "LTS End of life", "Platform-initiated upgrade"}
	untilRE   = regexp.MustCompile(`^Until (1\.[0-9]{1,3}) GA$`)
	monthD    = regexp.MustCompile(`^([A-Z][a-z]{2}) ([0-9]{4})$`)
	dayD      = regexp.MustCompile(`^([A-Z][a-z]{2}) ([0-9]{1,2}), ([0-9]{4})$`)
	months    = map[string]string{"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
)

func headerIs(row []htmltable.Cell, want []string) bool {
	if len(row) != len(want) {
		return false
	}
	for i, c := range row {
		if !c.Header || c.Text != want[i] || c.RowSpan != 1 || c.ColSpan != 1 || len(c.Markers) != 0 {
			return false
		}
	}
	return true
}

// ParseSupport reads the support page bytes. Exactly one standard and one LTS
// table must be found by header text; every row must parse.
func ParseSupport(page []byte) (Support, error) {
	if len(page) == 0 {
		return Support{}, pd.Drift(srcSupport, pd.KindEmpty, "no page bytes")
	}
	tables, err := htmltable.Parse(page)
	if err != nil {
		return Support{}, pd.Drift(srcSupport, pd.KindStructure, "%v", err)
	}
	if len(tables) == 0 {
		return Support{}, pd.Drift(srcSupport, pd.KindEmpty, "static page holds no table")
	}
	var std, lts []htmltable.Table
	for _, t := range tables {
		switch {
		case headerIs(t.Rows[0], stdHeader):
			std = append(std, t)
		case headerIs(t.Rows[0], ltsHeader):
			lts = append(lts, t)
		}
	}
	if len(std) != 1 || len(lts) != 1 {
		return Support{}, pd.Drift(srcSupport, pd.KindHeader, "found %d standard and %d LTS tables by header text, want 1 and 1", len(std), len(lts))
	}
	var s Support
	if s.Standard, err = parseTable(std[0], false); err != nil {
		return Support{}, err
	}
	if s.LTS, err = parseTable(lts[0], true); err != nil {
		return Support{}, err
	}
	if _, err := s.facts(); err != nil {
		return Support{}, err
	}
	return s, nil
}

func parseTable(t htmltable.Table, lts bool) ([]Row, error) {
	name := "standard"
	if lts {
		name = "LTS"
	}
	if len(t.Rows) < 2 {
		return nil, pd.Drift(srcSupport, pd.KindEmpty, "%s table has no data rows", name)
	}
	var out []Row
	prev := -1
	for i, cells := range t.Rows[1:] {
		if len(cells) != 7 {
			return nil, pd.Drift(srcSupport, pd.KindRow, "%s row %d has %d cells, want 7", name, i+1, len(cells))
		}
		for _, c := range cells {
			if c.Header || c.RowSpan != 1 || c.ColSpan != 1 || len(c.Markers) != 0 {
				return nil, pd.Drift(srcSupport, pd.KindRow, "%s row %d: header cell, span or marker in a data row", name, i+1)
			}
		}
		if !pd.ParseLine(cells[0].Text) {
			return nil, pd.Drift(srcSupport, pd.KindCell, "%s row %d: first cell is not a minor line", name, i+1)
		}
		r := Row{Line: cells[0].Text}
		dst := []*Cell{&r.Upstream, &r.Preview, &r.GA, &r.EOL, &r.Platform, &r.PlatformUpgrade}
		if lts {
			dst[4] = &r.LTSEnd
		}
		for k, d := range dst {
			c, err := parseCell(cells[k+1].Text)
			if err != nil {
				return nil, pd.Drift(srcSupport, pd.KindCell, "%s row %d (%s) column %d: %v", name, i+1, r.Line, k+2, err)
			}
			*d = c
		}
		n := lineN(r.Line)
		if n <= prev {
			return nil, pd.Drift(srcSupport, pd.KindRow, "%s table lines are not strictly ascending at %s", name, r.Line)
		}
		prev = n
		out = append(out, r)
	}
	return out, nil
}

func lineN(line string) int {
	n, _ := pd.LineNum(line)
	return n
}

func parseCell(text string) (Cell, error) {
	if text == "TBD" {
		return Cell{Kind: KindTBD, Date: pd.Date{Precision: distribution.PrecisionTBD}}, nil
	}
	if m := untilRE.FindStringSubmatch(text); m != nil {
		return Cell{Kind: KindUntil, UntilLine: m[1], Date: pd.Date{Precision: distribution.PrecisionTBD}}, nil
	}
	if m := monthD.FindStringSubmatch(text); m != nil {
		if mm, ok := months[m[1]]; ok {
			if d, ok := pd.ParseISO(m[2] + "-" + mm); ok {
				return Cell{Kind: KindDate, Date: d}, nil
			}
		}
	}
	if m := dayD.FindStringSubmatch(text); m != nil {
		if mm, ok := months[m[1]]; ok {
			day := m[2]
			if len(day) == 1 {
				day = "0" + day
			}
			if d, ok := pd.ParseISO(m[3] + "-" + mm + "-" + day); ok {
				return Cell{Kind: KindDate, Date: d}, nil
			}
		}
	}
	return Cell{}, fmt.Errorf("not Mon YYYY, Mon D, YYYY, TBD or Until 1.N GA")
}

// Line is one merged lifecycle line of the page.
type Line struct {
	Line string
	Row  Row
	// InLTS reports the line is in the LTS table (LTSEnd is meaningful).
	InLTS bool
	// Prerelease: no GA date, or no upstream release date yet (preview or
	// unannounced). It carries no lifecycle claim.
	Prerelease bool
}

// Merge joins the tables by line. A line in both tables must agree on every
// shared column, else drift (conflict). A line whose GA is not a date is a
// prerelease.
func (s Support) Merge() ([]Line, error) {
	by := map[string]*Line{}
	var order []string
	for _, r := range s.Standard {
		l := Line{Line: r.Line, Row: r}
		by[r.Line] = &l
		order = append(order, r.Line)
	}
	for _, r := range s.LTS {
		l, ok := by[r.Line]
		if !ok {
			by[r.Line] = &Line{Line: r.Line, Row: r, InLTS: true}
			order = append(order, r.Line)
			continue
		}
		if l.Row.Upstream != r.Upstream || l.Row.Preview != r.Preview || l.Row.GA != r.GA || l.Row.EOL != r.EOL || l.Row.PlatformUpgrade != r.PlatformUpgrade {
			return nil, pd.Drift(srcSupport, pd.KindConflict, "%s: standard and LTS tables disagree", r.Line)
		}
		l.Row.LTSEnd = r.LTSEnd
		l.InLTS = true
	}
	// Ascending numeric order.
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && lineN(order[j]) < lineN(order[j-1]); j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	var out []Line
	for _, k := range order {
		l := *by[k]
		l.Prerelease = l.Row.GA.Kind != KindDate || l.Row.Upstream.Kind != KindDate
		out = append(out, l)
	}
	return out, nil
}

func cellTok(c Cell) string {
	switch c.Kind {
	case KindTBD:
		return "tbd"
	case KindUntil:
		return "until:" + c.UntilLine
	}
	return c.Date.Value
}

// Bodies renders the tables as paraphrase excerpt bodies: one line per table
// row, "std|lts <line> <six tokens>", at most MaxBody bytes per body.
func (s Support) Bodies() ([]string, error) {
	var rows []string
	for _, r := range s.Standard {
		rows = append(rows, strings.Join([]string{"std", r.Line, cellTok(r.Upstream), cellTok(r.Preview), cellTok(r.GA), cellTok(r.EOL), cellTok(r.Platform), cellTok(r.PlatformUpgrade)}, " "))
	}
	for _, r := range s.LTS {
		rows = append(rows, strings.Join([]string{"lts", r.Line, cellTok(r.Upstream), cellTok(r.Preview), cellTok(r.GA), cellTok(r.EOL), cellTok(r.LTSEnd), cellTok(r.PlatformUpgrade)}, " "))
	}
	return pd.ChunkLines(srcSupport, SupportFormat, rows, MaxBody)
}
