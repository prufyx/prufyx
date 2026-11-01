// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"regexp"
	"sort"
	"strings"
)

// LedgerEntry names one item the extractor withheld and why. It carries
// identifiers only, never document content: Code is the upper-cased withhold
// reason, Item the group/Kind (or configured repository path) it concerns.
// Result.Ledger is canonical: sorted by (Code, Item), without duplicates, at
// most MaxLedgerEntries entries.
type LedgerEntry struct {
	Code string `json:"code"`
	Item string `json:"item"`
}

// Ledger bounds. Exceeding any of them is recorded as one framework entry,
// never truncated.
const (
	MaxLedgerEntries = 256
	MaxLedgerItemLen = 200
)

// Fault entries. They stand alone in a ledger that broke a rule, and the
// LEDGER_ prefix is reserved for them.
const (
	LedgerInvalid  = "LEDGER_INVALID"
	LedgerOverflow = "LEDGER_OVERFLOW"
	// LedgerFaultItem is the item of a fault entry.
	LedgerFaultItem = "ledger"

	ledgerReservedPrefix = "LEDGER_"
)

var (
	ledgerCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)
	ledgerItemRE = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=*\[\]-]{1,200}$`)
)

// ledgerGuards are switched off only by tests (see guards).
type ledgerGuards struct {
	code, item, reserved, limit, order, dedupe, veto bool
}

func defaultLedgerGuards() ledgerGuards {
	return ledgerGuards{code: true, item: true, reserved: true, limit: true, order: true, dedupe: true, veto: true}
}

// ledgerOf turns the omissions into the canonical ledger. Any entry that
// breaks a rule, or too many entries, give the single fault entry instead.
func ledgerOf(om []Omission, g ledgerGuards) []LedgerEntry {
	if len(om) == 0 {
		return []LedgerEntry{}
	}
	out := make([]LedgerEntry, 0, len(om))
	for _, o := range om {
		e := LedgerEntry{Code: strings.ToUpper(o.Reason), Item: o.Subject}
		if g.code && !ledgerCodeRE.MatchString(e.Code) {
			return faultLedger(LedgerInvalid)
		}
		if g.reserved && strings.HasPrefix(e.Code, ledgerReservedPrefix) {
			return faultLedger(LedgerInvalid)
		}
		if g.item && !ledgerItemRE.MatchString(e.Item) {
			return faultLedger(LedgerInvalid)
		}
		out = append(out, e)
	}
	if g.order {
		sort.Slice(out, func(i, j int) bool {
			if out[i].Code != out[j].Code {
				return out[i].Code < out[j].Code
			}
			return out[i].Item < out[j].Item
		})
	}
	if g.dedupe {
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
	if g.limit && len(out) > MaxLedgerEntries {
		return faultLedger(LedgerOverflow)
	}
	return out
}

func faultLedger(code string) []LedgerEntry {
	return []LedgerEntry{{Code: code, Item: LedgerFaultItem}}
}

// seal sets the ledger and the complete flags of a result whose omissions
// and member lists are final. The flags are decided by the ledger alone: a
// non-empty ledger, valid or not, is never complete.
func (r *Result) seal(fm, em []string, g ledgerGuards) {
	r.Ledger = ledgerOf(r.Omissions, g)
	complete := len(r.Ledger) == 0
	if !g.veto {
		complete = true
	}
	r.Fields.Members, r.Fields.Complete = fm, complete
	r.Enums.Members, r.Enums.Complete = em, complete
}

// Attestable reports whether the result may back a line attestation: only
// when nothing was withheld. A non-empty ledger can never yield one,
// whatever the other fields say.
func (r *Result) Attestable() bool {
	return len(r.Ledger) == 0 && len(r.Omissions) == 0 && r.Fields.Complete && r.Enums.Complete
}
