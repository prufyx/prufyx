// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
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
		{"null ledger", map[string]any{"ledger": nil}, 0, true},
		{"repeated ledger key", json.RawMessage(`{"ledger":[1],"ledger":[]}`), 0, true},
		{"repeated other key", json.RawMessage(`{"a":1,"a":2}`), 0, true},
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
	if err == nil || !strings.Contains(err.Error(), "pair 1.29.0->1.30.0: the extractor withheld 1 item(s)") {
		t.Fatalf("proof with a ledger and an attestation: %v", err)
	}
	err = crossCheckAttestation(out(map[string]any{"ledger": 3}), "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "pair 1.29.0->1.30.0: line 1.30: pair proof ledger") {
		t.Fatalf("unreadable ledger: %v", err)
	}
	// Control: an empty ledger passes this check and goes on to the
	// extractor's own attestations, which this output does not hold.
	err = crossCheckAttestation(out(map[string]any{"ledger": []any{}}), "", a, nil)
	if err == nil || strings.Contains(err.Error(), "withheld") || !strings.Contains(err.Error(), "does not attest line") {
		t.Fatalf("proof with an empty ledger: %v", err)
	}
}

// Every pair into the line counts, not only the last: a ledger on an earlier
// pair into the same line refuses the attestation.
func TestCrossCheckAttestationChecksEveryPairOfTheLine(t *testing.T) {
	t.Parallel()
	pair := func(to string, proof any) extract.PairRecord {
		return extract.PairRecord{From: "1.29.0", To: to, Status: extract.PairDerived, Proof: proof,
			Attestation: &extract.PairAttestation{Status: extract.PairAttested, Line: "1.30", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}}}
	}
	withLedger := map[string]any{"ledger": []map[string]string{{"code": "A_CODE", "item": "a"}}}
	a := lineattest.LineAttestation{Component: recordComponent, Line: "1.30", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: []string{}}
	out := &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{pair("1.30.0", withLedger), pair("1.30.1", map[string]any{})}}}
	err := crossCheckAttestation(out, "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "pair 1.29.0->1.30.0: the extractor withheld 1 item(s)") {
		t.Fatalf("ledger on the earlier pair of the line: %v", err)
	}
}

// crdschemaResultGolden is the canonical JSON of a crdschema.Result with one
// ledger entry. The same literal is pinned in the crdschema package
// (TestResultGoldenShape): this test and that one together tie the gate's
// reading of a pair proof to the shape the extractor writes. The gate check
// and crdschema live in different branches until both merge; after that a
// test here could import crdschema directly (no import cycle: crdschema
// imports only extract, constraintengine and membercode).
const crdschemaResultGolden = `{"schema":"prufyx.io/crd-schema-removal/v2","from":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","fields":{"members":[],"complete":false},"enums":{"members":[],"complete":false},"omissions":[{"reason":"MEMBER_CHARSET","subject":"example.io/Widget","count":1}],"ledger":[{"code":"MEMBER_CHARSET","item":"example.io/Widget"}],"exclusions":[]}`

func TestProofLedgerReadsTheCrdschemaResultShape(t *testing.T) {
	t.Parallel()
	n, err := proofLedgerLen(json.RawMessage(crdschemaResultGolden))
	if err != nil || n != 1 {
		t.Fatalf("ledger entries = %d, %v; want 1", n, err)
	}
}
