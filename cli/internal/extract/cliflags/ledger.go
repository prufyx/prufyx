// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LedgerEntry names one item the scanner withheld and why. It carries
// identifiers only, never source content: Code is the withhold reason, Item
// the binary directory (or the repository path) it concerns. Result.Ledger is
// canonical: sorted by (Code, Item), without duplicates, at most
// MaxLedgerEntries entries.
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
	ledgerItemRE = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=*\[\]-]{1,` + strconv.Itoa(MaxLedgerItemLen) + `}$`)
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

func isFault(l []LedgerEntry) bool {
	for _, e := range l {
		if strings.HasPrefix(e.Code, ledgerReservedPrefix) {
			return true
		}
	}
	return false
}

// seal sets the ledger and the complete flags of a result whose omissions
// and binaries are final. The flags are decided by the ledger alone: a
// binary with a ledger entry, or any binary when the ledger is a fault, is
// never complete.
func (r *Result) seal(g ledgerGuards) {
	r.Ledger = ledgerOf(r.Omissions, g)
	fault := isFault(r.Ledger)
	bad := map[string]bool{}
	for _, e := range r.Ledger {
		bad[e.Item] = true
	}
	for i := range r.Binaries {
		b := &r.Binaries[i]
		b.Set.Complete = !fault && !bad[b.Dir]
		if !g.veto {
			b.Set.Complete = true
		}
	}
}

// Attestable reports whether the result may back a line attestation: only
// when nothing was withheld and at least one binary was scanned. A non-empty
// ledger can never yield one, whatever the other fields say.
func (r *Result) Attestable() bool {
	if r == nil || len(r.Ledger) != 0 || len(r.Omissions) != 0 || len(r.Binaries) == 0 {
		return false
	}
	for i := range r.Binaries {
		if !r.Binaries[i].Set.Complete {
			return false
		}
	}
	return true
}
