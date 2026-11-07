// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LedgerEntry names one thing the scanner withheld and why. It carries
// identifiers only (a reason code and a repository path or symbol), never
// source text or option values. Ledgers are canonical: sorted by (Code,
// Item), without duplicates, at most MaxLedgerEntries entries. Any entry at
// all makes a scan incomplete.
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

// Ledger reason codes.
const (
	ReasonRootNotFound   = "ENVOY_ROOT_NOT_FOUND"
	ReasonParse          = "ENVOY_PARSE_FAILED"
	ReasonFileTooLarge   = "ENVOY_FILE_TOO_LARGE"
	ReasonLimit          = "ENVOY_LIMIT"
	ReasonNotRegular     = "ENVOY_NOT_REGULAR_FILE"
	ReasonDuplicate      = "ENVOY_DUPLICATE_SYMBOL"
	ReasonMemberCharset  = "ENVOY_MEMBER_CHARSET"
	ReasonMemberLong     = "ENVOY_MEMBER_TOO_LONG"
	ReasonMemberInvalid  = "ENVOY_MEMBER_INVALID"
	ReasonOptionValue    = "ENVOY_OPTION_VALUE"
	ReasonPackage        = "ENVOY_PACKAGE"
	ReasonSideIncomplete = "ENVOY_SIDE_INCOMPLETE"
)

// ledgerOf canonicalises entries. An entry that breaks a rule, or too many
// entries, give the single fault entry instead.
func ledgerOf(in []LedgerEntry) []LedgerEntry {
	if len(in) == 0 {
		return []LedgerEntry{}
	}
	out := make([]LedgerEntry, 0, len(in))
	for _, e := range in {
		if !ledgerCodeRE.MatchString(e.Code) || strings.HasPrefix(e.Code, ledgerReservedPrefix) || !ledgerItemRE.MatchString(e.Item) {
			return faultLedger(LedgerInvalid)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Item < out[j].Item
	})
	w := 0
	for i, e := range out {
		if i > 0 && e == out[w-1] {
			continue
		}
		out[w] = e
		w++
	}
	out = out[:w]
	if len(out) > MaxLedgerEntries {
		return faultLedger(LedgerOverflow)
	}
	return out
}

func faultLedger(code string) []LedgerEntry {
	return []LedgerEntry{{Code: code, Item: LedgerFaultItem}}
}
