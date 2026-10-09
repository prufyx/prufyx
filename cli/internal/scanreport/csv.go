// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/csv"
	"strconv"
)

// csvColumns are the columns of the CSV rendering, in order.
var csvColumns = []string{"verdict", "rule_id", "project", "file", "line", "kind", "namespace", "name", "title", "fix"}

// renderCSV renders the report as CSV: one header row, one summary row (the
// report's verdict in the verdict column and its headline in the title
// column, so the answer is in the file and an undecided report never reads
// like an empty pass), then one row per
// finding location (findings are blocking) in the order the Markdown
// renderer lists findings, one row per
// gap with the message the Markdown renderer shows, and, when the options
// show passes, one row per pass. Every cell is sanitized like the other
// renderers, and a cell that could start a spreadsheet formula is prefixed
// with a single quote.
func renderCSV(report Report, options RenderOptions) ([]byte, error) {
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	if err := writer.Write(csvColumns); err != nil {
		return nil, err
	}
	summary := make([]string, len(csvColumns))
	summary[0] = csvCell(report.Verdict)
	summary[8] = csvCell(report.Headline)
	if err := writer.Write(summary); err != nil {
		return nil, err
	}
	for _, finding := range csvFindings(report) {
		locations := finding.Locations
		if len(locations) == 0 {
			locations = []Location{{}}
		}
		// One row per location so no affected manifest is dropped.
		for _, location := range locations {
			row := make([]string, len(csvColumns))
			row[0] = csvCell("BLOCKED")
			row[1] = csvCell(finding.RuleID)
			row[2] = csvCell(finding.Component)
			row[3] = csvCell(location.File)
			if location.Line > 0 {
				row[4] = csvCell(strconv.Itoa(location.Line))
			}
			row[5] = csvCell(location.Kind)
			row[6] = csvCell(location.Namespace)
			row[7] = csvCell(location.Name)
			row[8] = csvCell(finding.Title)
			row[9] = csvCell(finding.Fix)
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}
	for _, gap := range report.Gaps {
		row := make([]string, len(csvColumns))
		row[0] = csvCell("GAP")
		row[2] = csvCell(gap.Component)
		row[8] = csvCell(csvGapTitle(gap))
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	if options.ShowPasses {
		for _, pass := range report.Passes {
			row := make([]string, len(csvColumns))
			row[0] = csvCell("PASS")
			row[1] = csvCell(pass.RuleID)
			row[2] = csvCell(pass.Component)
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// csvFindings lists the findings in the order the Markdown renderer shows
// them: the findings of each path first, then the findings whose component
// has no path.
func csvFindings(report Report) []Finding {
	var out []Finding
	for _, path := range report.Paths {
		out = append(out, findingsOf(report.Findings, path.Component)...)
	}
	for _, finding := range report.Findings {
		if !hasPath(report.Paths, finding.Component) {
			out = append(out, finding)
		}
	}
	return out
}

// csvGapTitle is the gap message the Markdown renderer shows: the detail
// with the action appended after "; " when there is one.
func csvGapTitle(gap Gap) string {
	switch {
	case gap.Detail == "":
		return gap.Action
	case gap.Action == "":
		return gap.Detail
	}
	return gap.Detail + "; " + gap.Action
}

// csvCell sanitizes a cell of the CSV output, like the other renderers,
// and guards it against spreadsheet formula injection: a cell that starts
// with a character that could open a formula (=, +, -, @, tab, carriage
// return) is prefixed with a single quote.
func csvCell(text string) string {
	text = Sanitize(text)
	if text == "" {
		return ""
	}
	switch text[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + text
	}
	return text
}
