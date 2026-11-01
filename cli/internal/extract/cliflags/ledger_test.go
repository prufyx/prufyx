// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
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
		if err := wantFault("reason "+reason, ledgerOf([]Omission{om(reason, "cmd/a")}, g), LedgerInvalid); err != nil {
			return err
		}
	}
	return nil
}

func scenarioReserved(g ledgerGuards) error {
	return wantFault("reserved code", ledgerOf([]Omission{om(LedgerOverflow, "cmd/a")}, g), LedgerInvalid)
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
		in = append(in, om("FLAG_X_CODE", fmt.Sprintf("cmd/b%d", i)))
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
	got := ledgerOf([]Omission{om("B_CODE", "cmd/a"), om("A_CODE", "cmd/z"), om("A_CODE", "cmd/b")}, g)
	want := []LedgerEntry{{"A_CODE", "cmd/b"}, {"A_CODE", "cmd/z"}, {"B_CODE", "cmd/a"}}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("not sorted: %v", got)
	}
	return nil
}

func scenarioDedupe(g ledgerGuards) error {
	if got := ledgerOf([]Omission{om("A_CODE", "cmd/b"), om("A_CODE", "cmd/b"), om("a_code", "cmd/b")}, g); len(got) != 1 {
		return fmt.Errorf("duplicates kept: %v", got)
	}
	return nil
}

// scenarioVeto: a binary with a ledger entry is never complete and the
// result is never attestable, whatever the other fields say.
func scenarioVeto(g ledgerGuards) error {
	r := &Result{
		Binaries:  []Binary{{Dir: "cmd/a", Set: constraintengine.SetValue{Members: []string{"m"}}}},
		Omissions: []Omission{om("FLAG_X_CODE", "cmd/a")},
	}
	r.seal(g)
	if r.Binaries[0].Set.Complete || len(r.Ledger) != 1 {
		return fmt.Errorf("a binary with a ledger entry is complete: %+v", r)
	}
	r.Binaries[0].Set.Complete = true
	if r.Attestable() {
		return fmt.Errorf("a result with a ledger is attestable")
	}
	return nil
}

// scenarioInventory: a fault about something that is not a scanned binary
// leaves no binary complete, even a binary the ledger does not name.
func scenarioInventory(g ledgerGuards) error {
	for name, o := range map[string]Omission{
		"global flag":     {Reason: "INVENTORY_FAULT_TOO_LARGE", Subject: "docs", Count: 1, Global: true},
		"unknown subject": {Reason: "INVENTORY_FAULT_TOO_LARGE", Subject: "docs", Count: 1},
	} {
		r := &Result{
			Binaries:  []Binary{{Dir: "cmd/a"}, {Dir: "cmd/b"}},
			Omissions: []Omission{o},
		}
		r.seal(g)
		for _, b := range r.Binaries {
			if b.Set.Complete {
				return fmt.Errorf("%s: %s is complete next to an unscanned fault", name, b.Dir)
			}
		}
	}
	// Control: a fault about one binary leaves the other complete.
	r := &Result{Binaries: []Binary{{Dir: "cmd/a"}, {Dir: "cmd/b"}}, Omissions: []Omission{om("FLAG_X_CODE", "cmd/a")}}
	r.seal(g)
	if r.Binaries[0].Set.Complete || !r.Binaries[1].Set.Complete {
		return fmt.Errorf("a binary fault must withhold exactly that binary: %+v", r.Binaries)
	}
	return nil
}

var ledgerScenarios = map[string]struct {
	run func(ledgerGuards) error
	off func(*ledgerGuards)
}{
	"TestLedgerCodeVocabulary":        {scenarioCode, func(g *ledgerGuards) { g.code = false }},
	"TestLedgerReservedCodes":         {scenarioReserved, func(g *ledgerGuards) { g.reserved = false }},
	"TestLedgerItemCharsetAndLen":     {scenarioItem, func(g *ledgerGuards) { g.item = false }},
	"TestLedgerEntryCap":              {scenarioLimit, func(g *ledgerGuards) { g.limit = false }},
	"TestLedgerSorted":                {scenarioOrder, func(g *ledgerGuards) { g.order = false }},
	"TestLedgerDeduplicated":          {scenarioDedupe, func(g *ledgerGuards) { g.dedupe = false }},
	"TestLedgerInventoryWithholdsAll": {scenarioInventory, func(g *ledgerGuards) { g.inventory = false }},
	"TestLedgerNeverYieldsAttested":   {scenarioVeto, func(g *ledgerGuards) { g.veto = false }},
}

func mustPass(t *testing.T, name string) {
	t.Helper()
	if err := ledgerScenarios[name].run(defaultLedgerGuards()); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerCodeVocabulary(t *testing.T)        { mustPass(t, "TestLedgerCodeVocabulary") }
func TestLedgerReservedCodes(t *testing.T)         { mustPass(t, "TestLedgerReservedCodes") }
func TestLedgerItemCharsetAndLen(t *testing.T)     { mustPass(t, "TestLedgerItemCharsetAndLen") }
func TestLedgerEntryCap(t *testing.T)              { mustPass(t, "TestLedgerEntryCap") }
func TestLedgerSorted(t *testing.T)                { mustPass(t, "TestLedgerSorted") }
func TestLedgerDeduplicated(t *testing.T)          { mustPass(t, "TestLedgerDeduplicated") }
func TestLedgerInventoryWithholdsAll(t *testing.T) { mustPass(t, "TestLedgerInventoryWithholdsAll") }

// TestLedgerNeverYieldsAttested: a non-empty ledger is never complete and
// never attestable, from generated omissions and hand-built results.
func TestLedgerNeverYieldsAttested(t *testing.T) {
	mustPass(t, "TestLedgerNeverYieldsAttested")
	// Control: no omissions and a scanned binary is attestable, so the ledger
	// is what refuses.
	ok := &Result{Binaries: []Binary{{Dir: "cmd/a"}}}
	ok.seal(defaultLedgerGuards())
	if !ok.Attestable() || !ok.Binaries[0].Set.Complete {
		t.Fatalf("control result is not attestable: %+v", ok)
	}
	// Hand-built results that claim completeness with a ledger.
	complete := []Binary{{Dir: "cmd/a", Set: constraintengine.SetValue{Complete: true}}}
	for name, r := range map[string]*Result{
		"nil":            nil,
		"empty":          {},
		"ledger only":    {Binaries: complete, Ledger: []LedgerEntry{{"A_CODE", "cmd/a"}}},
		"omissions only": {Binaries: complete, Omissions: []Omission{om("A_CODE", "cmd/a")}},
		"fault":          {Binaries: complete, Ledger: faultLedger(LedgerInvalid)},
		"incomplete":     {Binaries: []Binary{{Dir: "cmd/a"}}},
	} {
		if r.Attestable() {
			t.Errorf("%s: attestable", name)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	reasons := []string{"FLAG_DYNAMIC_REGISTRATION", "bad reason", "LEDGER_INVALID", "inventory_fault_x", "X", "FLAG_IDIOM_UNSUPPORTED"}
	subjects := []string{"cmd/a", "cmd/b", "has space", "", strings.Repeat("a", 201), "\x00", "."}
	for i := 0; i < 300; i++ {
		var in []Omission
		for n := rng.IntN(5); n > 0; n-- {
			in = append(in, om(reasons[rng.IntN(len(reasons))], subjects[rng.IntN(len(subjects))]))
		}
		if rng.IntN(10) == 0 {
			for j := 0; j <= MaxLedgerEntries; j++ {
				in = append(in, om("FLAG_X_CODE", fmt.Sprintf("cmd/b%d", j)))
			}
		}
		r := &Result{Binaries: []Binary{{Dir: "cmd/a"}, {Dir: "cmd/b"}}, Omissions: in}
		r.seal(defaultLedgerGuards())
		if len(in) == 0 {
			if !r.Attestable() {
				t.Fatalf("clean result is not attestable: %+v", r)
			}
			continue
		}
		if r.Attestable() {
			t.Fatalf("ledger %v is attestable", r.Ledger)
		}
		if len(r.Ledger) == 0 {
			t.Fatalf("omissions %v gave an empty ledger", in)
		}
		// Even a caller that sets the flags back to true gets no attestation.
		for i := range r.Binaries {
			r.Binaries[i].Set.Complete = true
		}
		if r.Attestable() {
			t.Fatalf("ledger %v is attestable after forcing complete", r.Ledger)
		}
	}
}
