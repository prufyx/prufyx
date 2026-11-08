// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// A pair record that lists withheld items and also says "attested" (a
// hand-edited or corrupt record) never backs a line attestation.
func TestCrossCheckAttestationRefusesPairWithLedger(t *testing.T) {
	t.Parallel()
	pair := func(ledger []extract.LedgerEntry) *extract.Output {
		return &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{{
			From: "1.29.0", To: "1.30.0", Status: extract.PairDerived, Ledger: ledger,
			Attestation: &extract.PairAttestation{Status: extract.PairAttested, Line: "1.30", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}},
		}}}}
	}
	a := lineattest.LineAttestation{Component: recordComponent, Line: "1.30", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: []string{}}
	err := crossCheckAttestation(pair([]extract.LedgerEntry{{Code: "FIELD_UNENCODABLE", Item: "spec.a"}}), "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "withheld 1 item(s)") {
		t.Fatalf("pair with a ledger and an attestation: %v", err)
	}
	// Without a ledger the same pair passes this check and goes on to the
	// extractor's own attestations, which this output does not hold.
	err = crossCheckAttestation(pair(nil), "", a, nil)
	if err == nil || strings.Contains(err.Error(), "withheld") || !strings.Contains(err.Error(), "does not attest line") {
		t.Fatalf("pair without a ledger: %v", err)
	}
}

// Two pairs into one line, only one with a ledger: the line is refused
// whichever pair carries it, not only the last.
func TestCrossCheckAttestationRefusesLedgerOnAnyPairOfTheLine(t *testing.T) {
	t.Parallel()
	pair := func(to string, ledger []extract.LedgerEntry) extract.PairRecord {
		return extract.PairRecord{From: "1.29.0", To: to, Status: extract.PairDerived, Ledger: ledger,
			Attestation: &extract.PairAttestation{Status: extract.PairAttested, Line: "1.30", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}}}
	}
	led := []extract.LedgerEntry{{Code: "FIELD_UNENCODABLE", Item: "spec.a"}}
	a := lineattest.LineAttestation{Component: recordComponent, Line: "1.30", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: []string{}}
	first := &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{pair("1.30.0", led), pair("1.30.1", nil)}}}
	err := crossCheckAttestation(first, "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "pair 1.29.0->1.30.0: the extractor withheld 1 item(s)") {
		t.Fatalf("ledger on the first pair only: %v", err)
	}
	last := &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{pair("1.30.0", nil), pair("1.30.1", led)}}}
	err = crossCheckAttestation(last, "", a, nil)
	if err == nil || !strings.Contains(err.Error(), "pair 1.29.0->1.30.1: the extractor withheld 1 item(s)") {
		t.Fatalf("ledger on the last pair only: %v", err)
	}
}
