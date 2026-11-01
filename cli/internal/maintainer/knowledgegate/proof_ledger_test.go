// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestProofLedgerLen(t *testing.T) {
	t.Parallel()
	type entry struct {
		Code string `json:"code"`
		Item string `json:"item"`
	}
	cases := []struct {
		name    string
		proof   any
		want    int
		wantErr bool
	}{
		{"nil", nil, 0, false},
		{"no ledger member", map[string]any{"removed": []string{"a"}}, 0, false},
		{"empty ledger", map[string]any{"ledger": []entry{}}, 0, false},
		{"null ledger", map[string]any{"ledger": nil}, 0, false},
		{"two entries", map[string]any{"ledger": []entry{{"A_CODE", "a"}, {"A_CODE", "b"}}}, 2, false},
		{"struct proof", struct {
			Ledger []entry `json:"ledger"`
		}{[]entry{{"A_CODE", "a"}}}, 1, false},
		{"not an object", []string{"x"}, 0, false},
		{"ledger not an array", map[string]any{"ledger": "none"}, 0, true},
		{"ledger an object", map[string]any{"ledger": map[string]any{}}, 0, true},
		{"unencodable", map[string]any{"ledger": make(chan int)}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := proofLedgerLen(c.proof)
			if got != c.want || (err != nil) != c.wantErr {
				t.Fatalf("got %d, %v; want %d, err %v", got, err, c.want, c.wantErr)
			}
		})
	}
}

// A re-derived pair that records withheld items in its proof and also says
// "attested" (a corrupt or hand-made record) never backs a line attestation.
func TestCrossCheckAttestationRefusesProofLedger(t *testing.T) {
	t.Parallel()
	out := func(proof any) *extract.Output {
		return &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{{
			From: "1.29.0", To: "1.30.0", Status: extract.PairDerived, Proof: proof,
			Attestation: &extract.PairAttestation{Status: extract.PairAttested, Line: "1.30", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}},
		}}}}
	}
	a := lineattest.LineAttestation{Component: recordComponent, Line: "1.30", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: []string{}}
	err := crossCheckAttestation(out(map[string]any{"ledger": []map[string]string{{"code": "A_CODE", "item": "a"}}}), "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "withheld 1 item(s)") {
		t.Fatalf("proof with a ledger and an attestation: %v", err)
	}
	err = crossCheckAttestation(out(map[string]any{"ledger": 3}), "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "not an array") {
		t.Fatalf("unreadable ledger: %v", err)
	}
	// Control: an empty ledger passes this check and goes on to the
	// extractor's own attestations, which this output does not hold.
	err = crossCheckAttestation(out(map[string]any{"ledger": []any{}}), "", a, nil)
	if err == nil || strings.Contains(err.Error(), "withheld") || !strings.Contains(err.Error(), "does not attest line") {
		t.Fatalf("proof with an empty ledger: %v", err)
	}
}
