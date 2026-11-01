// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func wantFault(what string, got []LedgerEntry, code string) error {
	if len(got) != 1 || got[0].Code != code || got[0].Item != LedgerFaultItem {
		return fmt.Errorf("%s: want one %s entry, got %v", what, code, got)
	}
	return nil
}

func om(reason, subject string) Omission { return Omission{Reason: reason, Subject: subject, Count: 1} }

// Scenarios return nil when the guard they are named for works.

func scenarioCode(g ledgerGuards) error {
	for _, reason := range []string{"bad code", "AB", "1ABC", strings.Repeat("A", 49)} {
		if err := wantFault("reason "+reason, ledgerOf([]Omission{om(reason, "a/B")}, g), LedgerInvalid); err != nil {
			return err
		}
	}
	return nil
}

func scenarioReserved(g ledgerGuards) error {
	return wantFault("reserved code", ledgerOf([]Omission{om(LedgerOverflow, "a/B")}, g), LedgerInvalid)
}

func scenarioItem(g ledgerGuards) error {
	for _, item := range []string{"has space", "", "quote\"d", "line\nbreak", strings.Repeat("a", MaxLedgerItemLen+1), "é"} {
		if err := wantFault(fmt.Sprintf("item %q", item), ledgerOf([]Omission{om("MEMBER_CHARSET", item)}, g), LedgerInvalid); err != nil {
			return err
		}
	}
	return nil
}

func scenarioLimit(g ledgerGuards) error {
	var in []Omission
	for i := 0; i <= MaxLedgerEntries; i++ {
		in = append(in, om("MEMBER_CHARSET", fmt.Sprintf("g/K%d", i)))
	}
	if err := wantFault("cap+1", ledgerOf(in, g), LedgerOverflow); err != nil {
		return err
	}
	if got := ledgerOf(in[:MaxLedgerEntries], g); len(got) != MaxLedgerEntries || got[0].Code == LedgerOverflow {
		return fmt.Errorf("exactly the cap must be kept whole, got %d entries", len(got))
	}
	return nil
}

func scenarioOrder(g ledgerGuards) error {
	got := ledgerOf([]Omission{om("B_CODE", "a/B"), om("A_CODE", "z/Z"), om("A_CODE", "b/B")}, g)
	want := []LedgerEntry{{"A_CODE", "b/B"}, {"A_CODE", "z/Z"}, {"B_CODE", "a/B"}}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("not sorted: %v", got)
	}
	return nil
}

func scenarioDedupe(g ledgerGuards) error {
	if got := ledgerOf([]Omission{om("A_CODE", "b/B"), om("A_CODE", "b/B"), om("a_code", "b/B")}, g); len(got) != 1 {
		return fmt.Errorf("duplicates kept: %v", got)
	}
	return nil
}

func scenarioVeto(g ledgerGuards) error {
	r := &Result{Omissions: []Omission{om("MEMBER_CHARSET", "a/B")}}
	r.seal([]string{"m"}, nil, g)
	if r.Fields.Complete || r.Enums.Complete || r.Attestable() || len(r.Ledger) != 1 {
		return fmt.Errorf("a result with a ledger is complete or attestable: %+v", r)
	}
	return nil
}

var ledgerScenarios = map[string]struct {
	run func(ledgerGuards) error
	off func(*ledgerGuards)
}{
	"TestLedgerCodeVocabulary":      {scenarioCode, func(g *ledgerGuards) { g.code = false }},
	"TestLedgerReservedCodes":       {scenarioReserved, func(g *ledgerGuards) { g.reserved = false }},
	"TestLedgerItemCharsetAndLen":   {scenarioItem, func(g *ledgerGuards) { g.item = false }},
	"TestLedgerEntryCap":            {scenarioLimit, func(g *ledgerGuards) { g.limit = false }},
	"TestLedgerSorted":              {scenarioOrder, func(g *ledgerGuards) { g.order = false }},
	"TestLedgerDeduplicated":        {scenarioDedupe, func(g *ledgerGuards) { g.dedupe = false }},
	"TestLedgerNeverYieldsAttested": {scenarioVeto, func(g *ledgerGuards) { g.veto = false }},
}

func mustPass(t *testing.T, name string) {
	t.Helper()
	if err := ledgerScenarios[name].run(defaultLedgerGuards()); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerCodeVocabulary(t *testing.T)    { mustPass(t, "TestLedgerCodeVocabulary") }
func TestLedgerReservedCodes(t *testing.T)     { mustPass(t, "TestLedgerReservedCodes") }
func TestLedgerItemCharsetAndLen(t *testing.T) { mustPass(t, "TestLedgerItemCharsetAndLen") }
func TestLedgerEntryCap(t *testing.T)          { mustPass(t, "TestLedgerEntryCap") }
func TestLedgerSorted(t *testing.T)            { mustPass(t, "TestLedgerSorted") }
func TestLedgerDeduplicated(t *testing.T)      { mustPass(t, "TestLedgerDeduplicated") }

// TestLedgerNeverYieldsAttested: a non-empty ledger is never complete and
// never attestable, from generated omissions and from every fixture.
func TestLedgerNeverYieldsAttested(t *testing.T) {
	mustPass(t, "TestLedgerNeverYieldsAttested")
	// Control: no omissions is attestable, so the veto is what refuses.
	ok := &Result{}
	ok.seal(nil, nil, defaultLedgerGuards())
	if !ok.Attestable() || !ok.Fields.Complete {
		t.Fatalf("control result is not attestable: %+v", ok)
	}
	// Hand-built results that claim completeness with a ledger.
	for name, r := range map[string]*Result{
		"ledger only":    {Ledger: []LedgerEntry{{"A_CODE", "a/B"}}, Fields: constraintengine.SetValue{Complete: true}, Enums: constraintengine.SetValue{Complete: true}},
		"omissions only": {Omissions: []Omission{om("A_CODE", "a/B")}, Fields: constraintengine.SetValue{Complete: true}, Enums: constraintengine.SetValue{Complete: true}},
	} {
		if r.Attestable() {
			t.Errorf("%s: attestable", name)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	reasons := []string{"MEMBER_CHARSET", "bad reason", "LEDGER_INVALID", "inventory_fault_x", "X", "CRD_PARSE_UNPROVEN"}
	subjects := []string{"a/B", "crd/x.yaml", "has space", "", strings.Repeat("a", 201), "\x00"}
	for i := 0; i < 300; i++ {
		var in []Omission
		for n := rng.IntN(5); n > 0; n-- {
			in = append(in, om(reasons[rng.IntN(len(reasons))], subjects[rng.IntN(len(subjects))]))
		}
		if rng.IntN(10) == 0 {
			for j := 0; j <= MaxLedgerEntries; j++ {
				in = append(in, om("MEMBER_CHARSET", fmt.Sprintf("g/K%d", j)))
			}
		}
		r := &Result{Omissions: in}
		r.seal([]string{"m"}, []string{"e"}, defaultLedgerGuards())
		if len(in) == 0 {
			continue
		}
		if len(r.Ledger) == 0 || len(r.Ledger) > MaxLedgerEntries || r.Fields.Complete || r.Enums.Complete || r.Attestable() {
			t.Fatalf("omissions %v gave %+v", in, r)
		}
	}
	for _, c := range allCases(t) {
		res, err := derive(context.Background(), c.reader(), testTarget, commitA, commitB, guardsFor(c, defaultGuards()))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (len(res.Ledger) > 0) != (len(c.exp.Omissions) > 0) || res.Attestable() != c.exp.Complete {
			t.Errorf("%s: ledger %v, attestable %v, expected complete=%v", c.name, res.Ledger, res.Attestable(), c.exp.Complete)
		}
	}
}

// TestLedgerMutations disables each guard in turn and requires the test
// named for it to fail.
func TestLedgerMutations(t *testing.T) {
	for name, s := range ledgerScenarios {
		t.Run(name, func(t *testing.T) {
			if err := s.run(defaultLedgerGuards()); err != nil {
				t.Fatalf("scenario fails with all guards on: %v", err)
			}
			g := defaultLedgerGuards()
			s.off(&g)
			if s.run(g) == nil {
				t.Fatalf("%s still passes with its guard off", name)
			}
		})
	}
}

// With the veto off, a real fixture with a withheld item comes out complete.
func TestLedgerVetoMutationOnFixture(t *testing.T) {
	for _, c := range allCases(t) {
		if c.name != "member_charset" {
			continue
		}
		g := defaultGuards()
		g.ledger.veto = false
		if check(c, g) == nil {
			t.Fatal("member_charset passes with the ledger veto off")
		}
		return
	}
	t.Fatal("member_charset fixture missing")
}

func TestLedgerDeterministicUnderShuffle(t *testing.T) {
	base := []Omission{om("MEMBER_CHARSET", "a/B"), om("MEMBER_CHARSET", "a/A"), om("CRD_TOO_LARGE", "crd/x.yaml"), om("MEMBER_CHARSET", "a/B")}
	want, _ := (&Result{Ledger: ledgerOf(base, defaultLedgerGuards())}).Canonical()
	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 20; i++ {
		in := append([]Omission(nil), base...)
		rng.Shuffle(len(in), func(a, b int) { in[a], in[b] = in[b], in[a] })
		got, _ := (&Result{Ledger: ledgerOf(in, defaultLedgerGuards())}).Canonical()
		if !bytes.Equal(got, want) {
			t.Fatalf("shuffle %d changed the canonical bytes", i)
		}
	}
}

// Every shipped withhold reason is a valid ledger code once upper-cased, so
// no real withhold collapses into LEDGER_INVALID.
func TestLedgerCodesCoverEveryReason(t *testing.T) {
	for _, r := range []string{ReasonParseUnproven, ReasonTooLarge, ReasonConversion, ReasonVersionSpecific, ReasonPresence, ReasonPreserveUnknown, ReasonRename, ReasonSecret, ReasonNonCRD, ReasonPathMissing, ReasonSourceKind, ReasonUnlistedSubtree, ReasonMemberCharset, ReasonMemberTooLong, ReasonMemberAmbiguous, ReasonSetTooLarge} {
		if got := ledgerOf([]Omission{om(r, "a/B")}, defaultLedgerGuards()); len(got) != 1 || got[0].Code != strings.ToUpper(r) {
			t.Errorf("reason %s: ledger %v", r, got)
		}
	}
}
