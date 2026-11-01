// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"fmt"
	"regexp"
	"sort"
)

// LedgerEntry names one item an extractor withheld from a derived pair and
// why. It carries identifiers only, never document content: Code is a member
// of a closed vocabulary the extractor documents, Item a member name or path
// the extractor read.
type LedgerEntry struct {
	Code string `json:"code"`
	Item string `json:"item"`
}

// Ledger bounds. Exceeding any of them is a fault that the framework records
// and answers with a NotAttested pair; it never truncates.
const (
	// MaxLedgerEntries is the most distinct entries one pair may carry.
	MaxLedgerEntries = 256
	// MaxLedgerItemLen is the longest Item, in bytes.
	MaxLedgerItemLen = 200
)

// Framework ledger codes. An extractor may not use them: a ledger holding
// one of them was written by the framework.
const (
	// LedgerInvalid marks a ledger the extractor returned that broke a rule
	// (bad code, bad item, reserved code). The entries are not recorded.
	LedgerInvalid = "LEDGER_INVALID"
	// LedgerOverflow marks a ledger with more than MaxLedgerEntries
	// distinct entries. The entries are not recorded.
	LedgerOverflow = "LEDGER_OVERFLOW"
	// LedgerFrameworkItem is the item of a framework entry.
	LedgerFrameworkItem = "ledger"

	ledgerReservedPrefix = "LEDGER_"
)

var (
	ledgerCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)
	ledgerItemRE = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=*\[\]-]{1,200}$`)
)

// ledgerGuards is a test seam: each field switches one guard off so a test
// can show that the test named for the guard fails without it. All false in
// production; only tests set it.
var ledgerGuards ledgerGuardSet

type ledgerGuardSet struct {
	noCodeCheck    bool
	noItemCheck    bool
	noReserved     bool
	noCap          bool
	noSort         bool
	noDedupe       bool
	noAttestVeto   bool
	noRecordedScan bool
}

// normalizeLedger validates in and returns it sorted by (code, item) and
// deduplicated. On any fault it returns the one-entry framework ledger that
// records the fault instead, never a truncated list. The result is empty only
// when in is empty.
func normalizeLedger(in []LedgerEntry) []LedgerEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]LedgerEntry, len(in))
	copy(out, in)
	for _, e := range out {
		if !ledgerGuards.noCodeCheck && !ledgerCodeRE.MatchString(e.Code) {
			return faultLedger(LedgerInvalid)
		}
		if !ledgerGuards.noReserved && len(e.Code) >= len(ledgerReservedPrefix) && e.Code[:len(ledgerReservedPrefix)] == ledgerReservedPrefix {
			return faultLedger(LedgerInvalid)
		}
		if !ledgerGuards.noItemCheck && !ledgerItemRE.MatchString(e.Item) {
			return faultLedger(LedgerInvalid)
		}
	}
	if !ledgerGuards.noSort {
		sort.Slice(out, func(i, j int) bool {
			if out[i].Code != out[j].Code {
				return out[i].Code < out[j].Code
			}
			return out[i].Item < out[j].Item
		})
	}
	if !ledgerGuards.noDedupe {
		w := 0
		for i, e := range out {
			if i > 0 && e == out[w-1] {
				continue
			}
			out[w] = e
			w++
		}
		out = out[:w]
	}
	if !ledgerGuards.noCap && len(out) > MaxLedgerEntries {
		return faultLedger(LedgerOverflow)
	}
	return out
}

func faultLedger(code string) []LedgerEntry {
	return []LedgerEntry{{Code: code, Item: LedgerFrameworkItem}}
}

// ledgerReason is the fixed NotAttested reason of a pair with a ledger. It
// names counts and the framework fault, never an item.
func ledgerReason(l []LedgerEntry) string {
	if len(l) == 1 && l[0].Item == LedgerFrameworkItem {
		switch l[0].Code {
		case LedgerInvalid:
			return "the item ledger is invalid"
		case LedgerOverflow:
			return fmt.Sprintf("the item ledger has more than %d entries", MaxLedgerEntries)
		}
	}
	return fmt.Sprintf("the pair withheld %d item(s), see ledger", len(l))
}

// CheckPairLedger reports whether a recorded pair keeps the ledger rules: a
// well-formed ledger in canonical order, and no attestation on a pair with a
// non-empty ledger. Run produces only such pairs; a hand-edited record that
// breaks them is refused here.
func CheckPairLedger(p PairRecord) error {
	if len(p.Ledger) == 0 {
		return nil
	}
	if len(p.Ledger) == 1 && p.Ledger[0].Item == LedgerFrameworkItem && (p.Ledger[0].Code == LedgerInvalid || p.Ledger[0].Code == LedgerOverflow) {
		// a recorded framework fault
	} else if !ledgerEqual(normalizeLedger(p.Ledger), p.Ledger) {
		return fmt.Errorf("pair %s->%s: ledger is invalid or not in canonical order", p.From, p.To)
	}
	if !ledgerGuards.noRecordedScan && p.Attestation != nil && (p.Attestation.Status != PairNotAttested || len(p.Attestation.Families) > 0) {
		return fmt.Errorf("pair %s->%s: attested although its ledger is not empty", p.From, p.To)
	}
	return nil
}

func ledgerEqual(a, b []LedgerEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
