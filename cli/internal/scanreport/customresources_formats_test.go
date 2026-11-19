// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// crFormatsReport has one blocked (with a finding at its location), one
// blocked without a finding result, one not evaluated and one no-finding
// custom resource, with hostile text in the first.
func crFormatsReport() Report {
	hop := HopRef{Index: 1, From: "1.0.0", To: "2.0.0"}
	report := Report{
		Paths: []Path{{Component: "zzz", From: "1.0.0", To: "2.0.0", Hops: []Hop{
			{Index: 1, From: Endpoint{Version: "1.0.0"}, To: Endpoint{Version: "2.0.0"}, Status: HopBlocked},
		}}},
		Findings: []Finding{{RuleID: "zzz.rule", Component: "zzz", Hop: hop, Title: "T", Fix: "F", Match: "anchor", Basis: "reviewed",
			Locations: []Location{{File: "a.yaml", Document: 0, Item: -1, Line: 3, Kind: "Widget", Namespace: "team", Name: "w"}}}},
		CustomResources: []CustomResource{
			{APIVersion: "x.example.com/v1", Kind: "Widget", Namespace: "team", Name: "w|=cmd", File: "a.yaml", Document: 0, Item: -1, Line: 3,
				Component: "zzz", Status: CRStatusEvaluated, Verdict: CRVerdictBlocked, Next: "see |rule| `x`"},
			{APIVersion: "x.example.com/v1", Kind: "Gadget", Name: "g", File: "b.yaml", Document: 0, Item: -1, Line: 1,
				Component: "zzz", Status: CRStatusEvaluated, Verdict: CRVerdictBlocked, Next: "n"},
			{APIVersion: "y.example.com/v1", Kind: "Other", Name: "=HYPERLINK(\"x\")", File: "c.yaml", Document: 0, Item: -1, Line: 2,
				Status: CRStatusNotEvaluated, Reason: CRKindNotInKnowledge, Next: "@verify, \"quoted\"\nby hand"},
			{APIVersion: "x.example.com/v1", Kind: "Fine", Name: "f", File: "d.yaml", Document: 0, Item: -1, Line: 4,
				Component: "zzz", Status: CRStatusEvaluated, Verdict: CRVerdictNoFinding, Next: "version check only"},
		},
	}
	Finalize(&report)
	return report
}

func TestCustomResourcesMarkdown(t *testing.T) {
	out := string(Markdown(crFormatsReport(), MarkdownOptions{}))
	for _, want := range []string{"## Custom resources (4)", "| apiVersion | Kind | Object |", "BLOCKED", `NO\_FINDING`, `NOT\_EVALUATED`, `CR\_KIND\_NOT\_IN\_KNOWLEDGE`, "Gadget", "Fine"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	for _, row := range strings.Split(out, "\n") {
		if strings.Contains(row, "Widget") && strings.HasPrefix(row, "| x.example") {
			if strings.Contains(row, "see |rule|") || !strings.Contains(row, "`team/w\\|=cmd`") || !strings.Contains(row, "see \\|rule\\| \\`x\\`") {
				t.Fatalf("row not escaped: %s", row)
			}
		}
		if strings.Contains(row, "Other") && strings.Contains(row, "\n") {
			t.Fatalf("row broken: %q", row)
		}
	}
	if strings.Contains(out, "@verify") || !strings.Contains(out, "&#64;verify") {
		t.Fatalf("mention not escaped:\n%s", out)
	}
}

func TestCustomResourcesMarkdownCap(t *testing.T) {
	report := Report{}
	for i := 0; i < maxCustomResourceLines+7; i++ {
		report.CustomResources = append(report.CustomResources, CustomResource{APIVersion: "x/v1", Kind: "K", Name: fmt.Sprint("n", i),
			File: "f.yaml", Document: i, Item: -1, Status: CRStatusNotEvaluated, Reason: CRPairNotCovered, Next: "n"})
	}
	out := string(Markdown(report, MarkdownOptions{}))
	if !strings.Contains(out, "and 7 more") || strings.Count(out, "| x/v1 |") != maxCustomResourceLines {
		t.Fatalf("cap:\n%s", out)
	}
}

func TestCustomResourcesCSV(t *testing.T) {
	records := csvOf(t, crFormatsReport(), RenderOptions{})
	var rows [][]string
	for _, r := range records {
		if r[0] == "CUSTOM_RESOURCE" {
			rows = append(rows, r)
		}
	}
	if len(rows) != 4 {
		t.Fatalf("want 4 custom_resource rows, got %d: %q", len(rows), records)
	}
	states := map[string]bool{}
	for _, r := range rows {
		states[strings.Fields(r[8])[0]] = true
		for _, cell := range r {
			if cell != "" && strings.ContainsAny(cell[:1], "=+-@\t\r") {
				t.Fatalf("formula cell %q", cell)
			}
		}
	}
	for _, s := range []string{"BLOCKED", "NO_FINDING", "NOT_EVALUATED"} {
		if !states[s] {
			t.Fatalf("no %s row: %q", s, rows)
		}
	}
	if rows[2][7] != "'=HYPERLINK(\"x\")" || rows[2][1] != CRKindNotInKnowledge {
		t.Fatalf("not evaluated row: %q", rows[2])
	}
}

func TestCustomResourcesSARIF(t *testing.T) {
	raw, err := SARIF(crFormatsReport())
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
			Properties struct {
				CustomResources []struct {
					Kind  string `json:"kind"`
					State string `json:"state"`
				} `json:"customResources"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	got := map[string]string{}
	for _, r := range run.Results {
		got[r.RuleID] = r.Level
	}
	want := map[string]string{"zzz.rule": "error", crSarifBlocked: "error", crSarifPrefix + CRKindNotInKnowledge: "note"}
	if len(run.Results) != 3 {
		t.Fatalf("results %+v", run.Results)
	}
	for id, level := range want {
		if got[id] != level {
			t.Fatalf("%s: level %q, want %q (%+v)", id, got[id], level, run.Results)
		}
	}
	ids := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ids[r.ID] = true
	}
	for id := range want {
		if !ids[id] {
			t.Fatalf("rule %s not declared", id)
		}
	}
	states := map[string]string{}
	for _, c := range run.Properties.CustomResources {
		states[c.Kind] = c.State
	}
	if len(states) != 4 || states["Fine"] != "NO_FINDING" || states["Other"] != "NOT_EVALUATED" || states["Widget"] != "BLOCKED" {
		t.Fatalf("properties %+v", states)
	}
	if strings.Contains(string(raw), `"pass"`) {
		t.Fatal("a pass in the SARIF")
	}
}

func TestCustomResourcesRedactedInAllFormats(t *testing.T) {
	report := crFormatsReport()
	Redact(&report)
	raw, _ := SARIF(report)
	csvRaw, _ := renderCSV(report, RenderOptions{})
	for name, out := range map[string]string{"markdown": string(Markdown(report, MarkdownOptions{})), "sarif": string(raw), "csv": string(csvRaw)} {
		for _, secret := range []string{"a.yaml", "b.yaml", "c.yaml", "d.yaml", "team", "HYPERLINK", "cmd", `"g"`} {
			if strings.Contains(out, secret) {
				t.Fatalf("%s leaks %q:\n%s", name, secret, out)
			}
		}
		if !strings.Contains(out, "sha256:") && !strings.Contains(out, digestPrefix) {
			t.Fatalf("%s has no digest", name)
		}
	}
}
