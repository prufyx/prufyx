// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import "testing"

func TestCheckBaseline(t *testing.T) {
	t.Parallel()
	b := Baseline{DecidedPairs: 46, CRDProjects: 19}
	if err := CheckBaseline(b, 46, 19); err != nil {
		t.Fatalf("equal numbers: %v", err)
	}
	if err := CheckBaseline(b, 50, 20); err != nil {
		t.Fatalf("higher numbers: %v", err)
	}
	// The dapr drop: 46 -> 41 decided pairs and 19 -> 18 projects.
	if err := CheckBaseline(b, 41, 18); err == nil {
		t.Fatal("a drop without a named withdrawal was accepted")
	}
	if err := CheckBaseline(b, 41, 19); err == nil {
		t.Fatal("a decided-pair drop alone was accepted")
	}
	if err := CheckBaseline(b, 46, 18); err == nil {
		t.Fatal("a covered-project drop alone was accepted")
	}
	b.Withdrawals = []Withdrawal{{Project: "dapr", DecidedPairs: 5, CRDProjects: 1, Reason: "attestations withdrawn"}}
	if err := CheckBaseline(b, 41, 18); err != nil {
		t.Fatalf("named withdrawal: %v", err)
	}
	if err := CheckBaseline(b, 40, 18); err == nil {
		t.Fatal("a drop beyond the named withdrawal was accepted")
	}
}

func TestParseBaselineRefuses(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"unknown field": `{"decidedPairs":1,"crdPublishedProjects":1,"withdrawals":[],"x":1}`,
		"no reason":     `{"decidedPairs":1,"crdPublishedProjects":1,"withdrawals":[{"project":"dapr","decidedPairs":1,"crdPublishedProjects":0}]}`,
		"negative":      `{"decidedPairs":-1,"crdPublishedProjects":1,"withdrawals":[]}`,
		"empty":         ``,
	} {
		if _, err := ParseBaseline([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
