// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decodeSARIF(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var log map[string]any
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&log); err != nil {
		t.Fatal(err)
	}
	return log
}

func undecidedReport() Report {
	hop := &HopRef{Index: 1, From: "1.27", To: "1.28"}
	report := Report{
		Inventory: []Component{{Name: "kubernetes", Target: "1.28.0", Covered: true}},
		Paths:     []Path{{Component: "kubernetes", Hops: []Hop{{Index: 1, Status: HopPartial}}}},
		Gaps: []Gap{
			NewGap("kubernetes", hop, GapLineNotAttested, "kubernetes", "1.28"),
			NewGap("kubernetes", nil, GapDeclarationScope, "kubernetes"),
		},
		Anchor: "manifests/app.yaml",
	}
	report.Provenance.Build.Version = "development"
	report.Provenance.EvaluatedAt = "2026-10-04T00:00:00Z"
	Finalize(&report)
	return report
}

// An UNKNOWN scan must not be an empty result list: code scanning shows
// results, not tool notifications, so an empty list reads as "no alerts".
func TestSARIFUnknownScanHasWarningResults(t *testing.T) {
	report := undecidedReport()
	if report.Verdict != VerdictUnknown {
		t.Fatalf("verdict %s", report.Verdict)
	}
	raw, err := SARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	log := decodeSARIF(t, raw)
	results := runOf(log)["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("an UNKNOWN scan with 2 gaps has %d results", len(results))
	}
	rules := rulesOf(log)
	for _, r := range results {
		result := r.(map[string]any)
		id := result["ruleId"].(string)
		if !strings.HasPrefix(id, "prufyx/gap/") || result["level"] != "warning" {
			t.Errorf("gap result %v level %v", id, result["level"])
		}
		if rule := rules[int(result["ruleIndex"].(float64))].(map[string]any); rule["id"] != id {
			t.Errorf("ruleIndex points at %v, want %s", rule["id"], id)
		}
		message := result["message"].(map[string]any)["text"].(string)
		if !strings.Contains(message, " - ") {
			t.Errorf("message lacks detail and action: %q", message)
		}
		uri := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
		if uri != "manifests/app.yaml" {
			t.Errorf("uri %v", uri)
		}
		if result["partialFingerprints"] == nil {
			t.Error("no fingerprint")
		}
	}
	if results[0].(map[string]any)["ruleId"] == results[1].(map[string]any)["ruleId"] {
		t.Error("two different gap reasons share a rule id")
	}
	// The notifications stay, so nothing a reader of the old log had is lost.
	notes := runOf(log)["invocations"].([]any)[0].(map[string]any)["toolExecutionNotifications"].([]any)
	if len(notes) != 2 {
		t.Errorf("%d notifications", len(notes))
	}
	again, _ := SARIF(report)
	if !bytes.Equal(raw, again) {
		t.Error("SARIF is not deterministic")
	}
}

// With only standard input there is no file to point at: the result sits at
// prufyx.yaml. A redacted scan never shows the path.
func TestSARIFGapResultLocation(t *testing.T) {
	report := undecidedReport()
	report.Anchor = ""
	raw, _ := SARIF(report)
	if !strings.Contains(string(raw), `"uri": "prufyx.yaml"`) {
		t.Errorf("no fallback location:\n%s", raw)
	}
	report.Anchor = "manifests/secret-name.yaml"
	Redact(&report)
	raw, _ = SARIF(report)
	if strings.Contains(string(raw), "secret-name") || !strings.Contains(string(raw), `"uri": "redacted/`) {
		t.Errorf("redacted scan leaks the path or has no redacted location:\n%s", raw)
	}
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
}

// A blocked scan keeps its errors first and adds its gaps as warnings.
func TestSARIFBlockedScanListsFindingsBeforeGaps(t *testing.T) {
	report := undecidedReport()
	report.Findings = []Finding{{RuleID: "kubernetes.rule", Component: "kubernetes", Hop: HopRef{Index: 1, From: "1.27", To: "1.28"}, Title: "t", Fix: "f", Match: "anchor",
		Locations: []Location{{File: "manifests/app.yaml", Item: -1, Line: 3, Kind: "CronJob", Name: "n"}}}}
	Finalize(&report)
	raw, err := SARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	results := runOf(decodeSARIF(t, raw))["results"].([]any)
	if len(results) != 3 || results[0].(map[string]any)["level"] != "error" || results[1].(map[string]any)["level"] != "warning" {
		t.Fatalf("results %v", results)
	}
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
}
