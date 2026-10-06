// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// csvOf renders a report as CSV, requires a trailing newline, parses the
// bytes back with encoding/csv and checks that every record has all the
// columns.
func csvOf(t *testing.T, report Report, options RenderOptions) [][]string {
	t.Helper()
	raw, err := renderCSV(report, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("no trailing newline:\n%q", raw)
	}
	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("%v:\n%s", err, raw)
	}
	for _, record := range records {
		if len(record) != len(csvColumns) {
			t.Fatalf("record %q has %d cells, want %d", record, len(record), len(csvColumns))
		}
	}
	return records
}

// csvOrderReport has a finding for a component with a path and a finding
// for a component without one that sorts before it: the CSV must list the
// path's finding first, like the Markdown renderer, although the sorted
// findings list it second.
func csvOrderReport() Report {
	hop := HopRef{Index: 1, From: "1.0.0", To: "2.0.0"}
	report := Report{
		Inventory: []Component{{Name: "aaa"}, {Name: "zzz", Target: "2.0.0", Covered: true}},
		Paths: []Path{{Component: "zzz", From: "1.0.0", To: "2.0.0", Hops: []Hop{
			{Index: 1, From: Endpoint{Version: "1.0.0"}, To: Endpoint{Version: "2.0.0"}, Status: HopBlocked},
		}}},
		Findings: []Finding{
			{RuleID: "aaa.nopath", Component: "aaa", Hop: hop, Title: "No path", Fix: "None", Match: "anchor", Basis: "reviewed"},
			{RuleID: "zzz.path", Component: "zzz", Hop: hop, Title: "On the path", Fix: "Fix it", Match: "anchor", Basis: "reviewed",
				Locations: []Location{{File: "zzz.yaml", Document: 0, Item: -1, Line: 7, Kind: "Widget", Namespace: "team", Name: "w"}}},
		},
	}
	Finalize(&report)
	return report
}

// TestCSVHeaderOnly: a report with no findings, gaps or passes renders as
// the header row alone.
func TestCSVHeaderOnly(t *testing.T) {
	report := Report{}
	Finalize(&report)
	raw, err := renderCSV(report, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(csvColumns, ",") + "\n"; string(raw) != want {
		t.Fatalf("CSV of an empty report = %q, want %q", raw, want)
	}
}

// TestCSVRows: one row per finding location in the Markdown order, one row per gap, and passes only when the options show them.
func TestCSVRows(t *testing.T) {
	empty := Report{}
	Finalize(&empty)
	ordered := csvOrderReport()
	full := fullReport()
	// Findings are blocking; every location gets its own row.
	var fullRows [][]string
	for _, f := range full.Findings {
		locations := f.Locations
		if len(locations) == 0 {
			locations = []Location{{}}
		}
		for _, l := range locations {
			line := ""
			if l.Line > 0 {
				line = strconv.Itoa(l.Line)
			}
			fullRows = append(fullRows, []string{"BLOCKED", f.RuleID, f.Component, l.File, line, l.Kind, l.Namespace, l.Name, csvCell(f.Title), csvCell(f.Fix)})
		}
	}
	orderedRows := [][]string{
		{"BLOCKED", "zzz.path", "zzz", "zzz.yaml", "7", "Widget", "team", "w", "On the path", "Fix it"},
		{"BLOCKED", "aaa.nopath", "aaa", "", "", "", "", "", "No path", "None"},
	}
	cases := []struct {
		name         string
		report       Report
		options      RenderOptions
		wantFindings [][]string
		wantGaps     int
		wantPasses   int
	}{
		{"empty report", empty, RenderOptions{}, nil, 0, 0},
		{"findings in markdown order", ordered, RenderOptions{}, orderedRows, 0, 0},
		{"full report without passes", full, RenderOptions{}, fullRows, 3, 0},
		{"full report with passes", full, RenderOptions{ShowPasses: true}, fullRows, 3, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := csvOf(t, tc.report, tc.options)
			wantTotal := 1 + len(tc.wantFindings) + tc.wantGaps + tc.wantPasses
			if len(records) != wantTotal {
				t.Fatalf("%d records, want %d:\n%v", len(records), wantTotal, records)
			}
			if !reflect.DeepEqual(records[0], csvColumns) {
				t.Fatalf("header %q, want %q", records[0], csvColumns)
			}
			for i, want := range tc.wantFindings {
				if !reflect.DeepEqual(records[1+i], want) {
					t.Errorf("finding row %d = %q, want %q", i, records[1+i], want)
				}
			}
			index := 1 + len(tc.wantFindings)
			for i, gap := range tc.report.Gaps {
				row := records[index+i]
				if row[0] != "GAP" || row[1] != "" || row[2] != gap.Component || row[8] != csvCell(csvGapTitle(gap)) {
					t.Errorf("gap row %d = %q", i, row)
					continue
				}
				if !strings.Contains(row[8], gap.Detail) {
					t.Errorf("gap row %d title %q does not show the detail %q", i, row[8], gap.Detail)
				}
			}
			index += len(tc.report.Gaps)
			if tc.wantPasses > 0 {
				for i, pass := range tc.report.Passes {
					row := records[index+i]
					if row[0] != "PASS" || row[1] != pass.RuleID || row[2] != pass.Component {
						t.Errorf("pass row %d = %q", i, row)
					}
				}
			}
		})
	}
}

// TestCSVCell: every cell is sanitized, and a cell that could start a
// spreadsheet formula is prefixed with a single quote.
func TestCSVCell(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"=SUM(A1:A2)", "'=SUM(A1:A2)"},
		{"+1", "'+1"},
		{"-2", "'-2"},
		{"@user", "'@user"},
		{"a=b", "a=b"},
		{"a-b", "a-b"},
		{"tab\tx", "tab\\x09x"},
		{"line\nbreak", "line\\x0abreak"},
		{"esc\x1b[0m", "esc\\x1b[0m"},
		{"\u202ebidi", "\\u202ebidi"},
	}
	for _, tc := range cases {
		if got := csvCell(tc.in); got != tc.want {
			t.Errorf("csvCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCSVGapTitle: the gap title is the detail with the action appended.
func TestCSVGapTitle(t *testing.T) {
	cases := []struct{ detail, action, want string }{
		{"unrendered templates", "Re-render the chart", "unrendered templates; Re-render the chart"},
		{"unrendered templates", "", "unrendered templates"},
		{"", "Re-render the chart", "Re-render the chart"},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := csvGapTitle(Gap{Detail: tc.detail, Action: tc.action}); got != tc.want {
			t.Errorf("csvGapTitle(Gap{Detail: %q, Action: %q}) = %q, want %q", tc.detail, tc.action, got, tc.want)
		}
	}
}

// TestCSVHostileCells: a finding whose fields start a formula or carry a
// control or bidi character is quoted and escaped in the output row.
func TestCSVHostileCells(t *testing.T) {
	report := fullReport()
	report.Findings = []Finding{{
		RuleID: "=cmd", Component: "@project", Hop: HopRef{Index: 1, From: "1.24.17", To: "1.25"},
		Title: "=SUM(A1:A2)", Fix: "+delete everything", Match: "anchor", Basis: "reviewed",
		Locations: []Location{{File: "-report.xlsx", Document: 0, Item: -1, Line: 4, Kind: "K\x00ind", Namespace: "@ns", Name: "\u202ename"}},
	}}
	Finalize(&report)
	records := csvOf(t, report, RenderOptions{})
	want := []string{"BLOCKED", "'=cmd", "'@project", "'-report.xlsx", "4", "K\\x00ind", "'@ns", "\\u202ename", "'=SUM(A1:A2)", "'+delete everything"}
	if !reflect.DeepEqual(records[1], want) {
		t.Fatalf("finding row = %q, want %q", records[1], want)
	}
}

// TestCSVRenderFormat: the "csv" format selects the CSV renderer.
func TestCSVRenderFormat(t *testing.T) {
	raw, err := Render(fullReport(), "csv", RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("verdict,rule_id,")) || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("csv format does not render CSV:\n%s", raw)
	}
}
