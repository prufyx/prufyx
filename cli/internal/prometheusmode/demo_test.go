// SPDX-License-Identifier: AGPL-3.0-only

package prometheusmode

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDemoReportUsesPinnedSyntheticVectors(t *testing.T) {
	report, err := BuildDemoReport()
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "SYNTHETIC_DEMONSTRATION" || report.Aggregate != "UNKNOWN" || !report.Truth.Synthetic {
		t.Fatalf("demo envelope = %#v", report)
	}
	want := []struct{ id, status, code string }{{"proposed-dedicated-preserves-current-agent-mode", "PASS", "PROMETHEUS_AGENT_MODE_PRESERVED"}, {"proposed-legacy-loses-current-agent-mode", "ATTENTION", "PROMETHEUS_AGENT_MODE_NOT_PRESERVED"}, {"proposed-wrapper-remains-unknown", "UNKNOWN", "PROMETHEUS_AGENT_MODE_EVIDENCE_INCOMPLETE"}}
	if len(report.Cases) != len(want) {
		t.Fatalf("case count = %d", len(report.Cases))
	}
	for i, expected := range want {
		got := report.Cases[i]
		if got.ID != expected.id || got.Claim.Status != expected.status || got.Claim.ReasonCode != expected.code {
			t.Fatalf("case %d = %#v", i, got)
		}
	}
}

func TestDemoReportDeterministic(t *testing.T) {
	a, err := BuildDemoReport()
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildDemoReport()
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if !bytes.Equal(ab, bb) {
		t.Fatalf("reports differ")
	}
}
