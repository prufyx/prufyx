// SPDX-License-Identifier: AGPL-3.0-only

package configkeys

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LedgerEntry names one thing the walker withheld and why. It carries
// identifiers only (a reason code and a Go field path), never source text or
// tag values. Result.Ledger is canonical: sorted by (Code, Item), without
// duplicates, at most MaxLedgerEntries entries.
type LedgerEntry struct {
	Code string `json:"code"`
	Item string `json:"item"`
}

// Ledger bounds. Exceeding one is recorded as a fault entry, never truncated.
const (
	MaxLedgerEntries = 256
	MaxLedgerItemLen = 200
)

// Fault entries. They stand alone in a ledger that broke a rule; the LEDGER_
// prefix is reserved for them.
const (
	LedgerInvalid   = "LEDGER_INVALID"
	LedgerOverflow  = "LEDGER_OVERFLOW"
	LedgerFaultItem = "ledger"

	ledgerReservedPrefix = "LEDGER_"
)

var (
	ledgerCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)
	ledgerItemRE = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=*\[\]-]{1,` + strconv.Itoa(MaxLedgerItemLen) + `}$`)
)

// ledgerGuards are switched off only by tests.
type ledgerGuards struct {
	code, item, reserved, limit, order, dedupe, veto bool
}

func defaultLedgerGuards() ledgerGuards {
	return ledgerGuards{code: true, item: true, reserved: true, limit: true, order: true, dedupe: true, veto: true}
}

// ledgerOf canonicalises entries. An entry that breaks a rule, or too many
// entries, give the single fault entry instead.
func ledgerOf(in []LedgerEntry, g ledgerGuards) []LedgerEntry {
	if len(in) == 0 {
		return []LedgerEntry{}
	}
	out := make([]LedgerEntry, 0, len(in))
	for _, e := range in {
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

// Ledger reason codes.
const (
	ReasonCharset       = "CONFIG_MEMBER_CHARSET"
	ReasonAmbiguous     = "CONFIG_MEMBER_AMBIGUOUS"
	ReasonTooLong       = "CONFIG_MEMBER_TOO_LONG"
	ReasonInvalidMember = "CONFIG_MEMBER_INVALID"
	ReasonDynamicMap    = "CONFIG_DYNAMIC_MAP"
	ReasonDynamicAny    = "CONFIG_DYNAMIC_ANY"
	ReasonCustomUnmarsh = "CONFIG_CUSTOM_UNMARSHAL"
	ReasonUnresolvable  = "CONFIG_UNRESOLVABLE_TYPE"
	ReasonImportDenied  = "CONFIG_IMPORT_DENIED"
	ReasonImplicitName  = "CONFIG_IMPLICIT_NAME"
	ReasonKeyCollision  = "CONFIG_KEY_COLLISION"
	ReasonAmbiguousType = "CONFIG_AMBIGUOUS_TYPE"
	ReasonBadTag        = "CONFIG_BAD_TAG"
	ReasonParse         = "CONFIG_PARSE_FAILED"
	ReasonBuildConstr   = "CONFIG_BUILD_CONSTRAINT"
	ReasonPackages      = "CONFIG_MULTIPLE_PACKAGES"
	ReasonDepth         = "CONFIG_DEPTH_LIMIT"
	ReasonKeyLimit      = "CONFIG_KEY_LIMIT"
	ReasonRootNotFound  = "CONFIG_ROOT_NOT_FOUND"
	ReasonPanic         = "CONFIG_WALK_PANIC"
)
