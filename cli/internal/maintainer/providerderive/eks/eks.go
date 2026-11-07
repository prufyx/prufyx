// SPDX-License-Identifier: AGPL-3.0-only

// Package eks turns the EKS Kubernetes release calendar (the markdown twin
// or the HTML page) into a strict table, and a committed paraphrase excerpt
// of that table into lifecycle rows of the distribution record shape. It is
// pure: bytes in, rows out, no network, no clock, no join to eks-distro.
// Extended support is automatic on EKS, so extendedRequiresOptIn is false.
//
// The later watcher that fetches the page and commits the excerpt must
// guarantee: excerpts are generated only through ParseMarkdown, ParseHTML,
// Agree and Canonical (a hand-edited excerpt is rejected); each excerpt is
// bound to the fetched digest, status and content type, and any drift fails
// closed; the markdown and HTML checks use the same fetch day.
package eks

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/shared"
)

// Columns is the exact header column set, in order.
var Columns = []string{"Kubernetes version", "Upstream release", "Amazon EKS release", "End of standard support", "End of extended support"}

// Heading is the section heading above the table (markdown twin).
const Heading = "## Amazon EKS Kubernetes release calendar"

// Row is one calendar row. Dates use the shared cell form: YYYY-MM-DD,
// YYYY-MM, YYYY-Qn, or "" with Precision tbd.
type Row struct {
	Line        string
	Upstream    shared.DateCell
	Release     shared.DateCell
	StandardEnd shared.DateCell
	ExtendedEnd shared.DateCell
}

var versionMD = regexp.MustCompile("^`(1\\.(?:0|[1-9][0-9]{0,5}))`$")
var versionHTML = regexp.MustCompile(`^(1\.(?:0|[1-9][0-9]{0,5}))$`)

// ParseMarkdown parses the markdown twin. Exactly one table must exist, under
// Heading, with exactly the Columns header; every row must parse.
func ParseMarkdown(page []byte) ([]Row, error) {
	if err := shared.CheckBody(source, page); err != nil {
		return nil, err
	}
	if strings.Count(string(page), "\r") > 0 {
		return nil, drift(pd.KindStructure, "carriage return in markdown")
	}
	lines := strings.Split(string(page), "\n")
	head := -1
	for i, l := range lines {
		if strings.TrimRight(l, " ") == Heading {
			if head >= 0 {
				return nil, drift(pd.KindHeader, "heading appears twice")
			}
			head = i
		}
	}
	if head < 0 {
		return nil, drift(pd.KindStructure, "release calendar heading")
	}
	// count table blocks over the whole page
	blocks, first := 0, -1
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
			if i == 0 || !strings.HasPrefix(strings.TrimSpace(lines[i-1]), "|") {
				blocks++
				if first < 0 {
					first = i
				}
			}
		}
	}
	if blocks != 1 {
		return nil, drift(pd.KindHeader, "%d tables on the page, exactly 1 expected", blocks)
	}
	// the table must follow the heading with only blank lines or prose before it
	if first < head {
		return nil, drift(pd.KindHeader, "table precedes the calendar heading")
	}
	for _, l := range lines[head+1 : first] {
		if strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "# ") {
			return nil, drift(pd.KindHeader, "another section sits between the heading and the table")
		}
	}
	var tbl []string
	for i := first; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|"); i++ {
		tbl = append(tbl, strings.TrimSpace(lines[i]))
	}
	if len(tbl) < 3 {
		return nil, drift(pd.KindStructure, "table has no data rows")
	}
	hdr, err := mdCells(tbl[0])
	if err != nil {
		return nil, err
	}
	if err := checkHeader(hdr); err != nil {
		return nil, err
	}
	del, err := mdCells(tbl[1])
	if err != nil || len(del) != len(Columns) {
		return nil, drift(pd.KindHeader, "delimiter row")
	}
	for _, c := range del {
		if strings.Trim(c, "-") != "" || len(c) < 3 {
			return nil, drift(pd.KindHeader, "delimiter row")
		}
	}
	var rows [][]string
	for i, l := range tbl[2:] {
		cells, err := mdCells(l)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		rows = append(rows, cells)
	}
	return buildRows(rows, versionMD)
}

func mdCells(line string) ([]string, error) {
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") || len(line) < 2 {
		return nil, drift(pd.KindCell, "table line without outer pipes")
	}
	parts := strings.Split(line[1:len(line)-1], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, nil
}

func checkHeader(h []string) error {
	if len(h) != len(Columns) {
		return drift(pd.KindHeader, "%d header columns, %d expected", len(h), len(Columns))
	}
	for i := range h {
		if h[i] != Columns[i] {
			return drift(pd.KindHeader, "header column %d is %q, expected %q", i+1, h[i], Columns[i])
		}
	}
	return nil
}

var (
	tableOpen = regexp.MustCompile(`(?i)<table[\s>]`)
	theadRE   = regexp.MustCompile(`(?is)<thead[^>]*>(.*?)</thead>`)
	trRE      = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	thRE      = regexp.MustCompile(`(?is)<th(?:\s[^>]*)?>(.*?)</th>`)
	tdRE      = regexp.MustCompile(`(?is)<td(\s[^>]*)?>(.*?)</td>`)
	tagRE     = regexp.MustCompile(`(?s)<[^>]*>`)
	spanRE    = regexp.MustCompile(`(?i)\b(rowspan|colspan)\b`)
)

func htmlText(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRE.ReplaceAllString(s, " "))), " ")
}

// ParseHTML parses the HTML page: exactly one table, a thead with exactly the
// Columns, then rows of five plain cells (no rowspan or colspan).
func ParseHTML(page []byte) ([]Row, error) {
	if err := shared.CheckBody(source, page); err != nil {
		return nil, err
	}
	s := string(page)
	if n := len(tableOpen.FindAllStringIndex(s, -1)); n != 1 {
		return nil, drift(pd.KindHeader, "%d tables on the page, exactly 1 expected", n)
	}
	th := theadRE.FindAllStringSubmatchIndex(s, -1)
	if len(th) != 1 {
		return nil, drift(pd.KindHeader, "%d table heads, exactly 1 expected", len(th))
	}
	headHTML := s[th[0][2]:th[0][3]]
	var hdr []string
	for _, m := range thRE.FindAllStringSubmatch(headHTML, -1) {
		hdr = append(hdr, htmlText(m[1]))
	}
	if err := checkHeader(hdr); err != nil {
		return nil, err
	}
	rest := s[th[0][1]:]
	end := strings.Index(strings.ToLower(rest), "</table>")
	if end < 0 {
		return nil, drift(pd.KindStructure, "table is not closed")
	}
	var rows [][]string
	for _, tr := range trRE.FindAllStringSubmatch(rest[:end], -1) {
		var cells []string
		for _, td := range tdRE.FindAllStringSubmatch(tr[1], -1) {
			if spanRE.MatchString(td[1]) {
				return nil, drift(pd.KindCell, "rowspan or colspan in a data row")
			}
			cells = append(cells, htmlText(td[2]))
		}
		rows = append(rows, cells)
	}
	return buildRows(rows, versionHTML)
}

func buildRows(raw [][]string, ver *regexp.Regexp) ([]Row, error) {
	if len(raw) == 0 {
		return nil, drift(pd.KindStructure, "table has no data rows")
	}
	var out []Row
	prev := -1
	for i, c := range raw {
		if len(c) != len(Columns) {
			return nil, drift(pd.KindRow, "row %d has %d cells, %d expected", i+1, len(c), len(Columns))
		}
		m := ver.FindStringSubmatch(c[0])
		if m == nil || !pd.ParseLine(m[1]) {
			return nil, drift(pd.KindCell, "row %d version cell %q", i+1, c[0])
		}
		r := Row{Line: m[1]}
		var err error
		cells := []*shared.DateCell{&r.Upstream, &r.Release, &r.StandardEnd, &r.ExtendedEnd}
		for j, dst := range cells {
			if *dst, err = shared.GrammarCell(source, c[j+1], false); err != nil {
				return nil, fmt.Errorf("row %d (%s): %w", i+1, r.Line, err)
			}
		}
		if err := checkRow(r); err != nil {
			return nil, fmt.Errorf("row %d (%s): %w", i+1, r.Line, err)
		}
		n := lineNum(r.Line)
		if prev >= 0 && n >= prev {
			return nil, drift(pd.KindRow, "row %d (%s): versions must be strictly descending", i+1, r.Line)
		}
		prev = n
		out = append(out, r)
	}
	return out, nil
}

// lineNum is the minor number of a line already checked with pd.ParseLine.
func lineNum(l string) int {
	n, _ := pd.LineNum(l)
	return n
}

// checkRow enforces the per-row invariants: uniform precision across the
// three lifecycle dates (TBD only for all three), and order where comparable.
func checkRow(r Row) error {
	p := r.Release.Precision
	if r.StandardEnd.Precision != p || r.ExtendedEnd.Precision != p {
		return drift(pd.KindRow, "release and end dates mix precisions (%s, %s, %s)", r.Release.Precision, r.StandardEnd.Precision, r.ExtendedEnd.Precision)
	}
	if p == distribution.PrecisionTBD {
		return nil
	}
	if r.Upstream.Precision == distribution.PrecisionTBD {
		return drift(pd.KindRow, "upstream release is TBD while the EKS release is dated")
	}
	if !(r.Release.Value <= r.StandardEnd.Value && r.StandardEnd.Value <= r.ExtendedEnd.Value) {
		return drift(pd.KindRow, "dates out of order (release <= standard end <= extended end)")
	}
	if r.Upstream.Precision == p && r.Upstream.Value > r.Release.Value {
		return drift(pd.KindRow, "EKS release is before the upstream release")
	}
	return nil
}

// Agree requires the markdown and HTML tables to be identical: a disagreement
// is a conflict and neither is picked.
func Agree(md, htm []Row) error {
	if len(md) != len(htm) {
		return drift(pd.KindConflict, "markdown has %d rows, html %d", len(md), len(htm))
	}
	for i := range md {
		if md[i] != htm[i] {
			return drift(pd.KindConflict, "row %s differs between the markdown and the html page", md[i].Line)
		}
	}
	return nil
}

func cellText(c shared.DateCell) string {
	if c.Precision == distribution.PrecisionTBD {
		return "tbd"
	}
	return c.Value
}

// Canonical renders rows as the paraphrase excerpt body: one line per row,
// no quotation or table markup. It is the only form the excerpt parser reads.
func Canonical(rows []Row) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "eks %s upstream %s release %s standard-end %s extended-end %s\n", r.Line,
			cellText(r.Upstream), cellText(r.Release), cellText(r.StandardEnd), cellText(r.ExtendedEnd))
	}
	return b.String()
}

// source names this extractor in every drift error.
const source = "eks-calendar"

func drift(kind, format string, args ...any) error { return pd.Drift(source, kind, format, args...) }
