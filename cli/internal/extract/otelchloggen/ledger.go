// SPDX-License-Identifier: AGPL-3.0-only

package otelchloggen

import (
	"regexp"
	"sort"
	"strconv"
)

// LedgerEntry names one item the reader withheld and why. It carries
// identifiers only, never fragment content: Code is the withhold reason, Item
// the repository path of the fragment. The result ledger is canonical: sorted by
// (Code, Item), without duplicates, at most MaxLedgerEntries entries.
type LedgerEntry struct {
	Code string `json:"code"`
	Item string `json:"item"`
}

// Ledger bounds. Exceeding any of them gives one fault entry, never a
// truncated ledger.
const (
	MaxLedgerEntries = 512
	MaxLedgerItemLen = 200
)

// Withhold reasons. A non-empty ledger means the result is incomplete and
// must not be read as "the fragments name nothing else".
const (
	// ReasonDirMissing: the fragment directory is absent or unlistable.
	ReasonDirMissing = "CHLOG_DIR_MISSING"
	// ReasonTooManyFiles: more entries than MaxFiles.
	ReasonTooManyFiles = "CHLOG_TOO_MANY_FILES"
	// ReasonEntryNotFile: a tree, submodule or symlink entry.
	ReasonEntryNotFile = "CHLOG_ENTRY_NOT_FILE"
	// ReasonUnsafeName: an entry name outside the allowed spelling.
	ReasonUnsafeName = "CHLOG_UNSAFE_NAME"
	// ReasonUnreadable: the blob could not be read.
	ReasonUnreadable = "CHLOG_UNREADABLE"
	// ReasonTooLarge: the fragment exceeds MaxFragmentBytes.
	ReasonTooLarge = "CHLOG_TOO_LARGE"
	// ReasonParse: not one well-formed YAML document, an unknown field, a
	// duplicate key, an alias, a missing required field, or a field of the
	// wrong shape.
	ReasonParse = "CHLOG_PARSE"
	// ReasonChangeTypeUnknown: change_type is not in the reviewed list.
	ReasonChangeTypeUnknown = "CHLOG_CHANGE_TYPE_UNKNOWN"
	// ReasonComponentUnknown: a breaking or deprecation fragment names a
	// component that is not in the hand-written table.
	ReasonComponentUnknown = "CHLOG_COMPONENT_UNKNOWN"
	// ReasonTextTooLarge: the note and subtext exceed MaxQuoteBytes.
	ReasonTextTooLarge = "CHLOG_TEXT_TOO_LARGE"
	// ReasonNoToken: the text says removed or deprecated but names nothing
	// in backticks.
	ReasonNoToken = "CHLOG_SIGNAL_NO_TOKEN"
	// ReasonUnclassified: a backticked token is not a long flag or a config
	// key, or the text quotes a code block.
	ReasonUnclassified = "CHLOG_TOKEN_UNCLASSIFIED"
	// ReasonAmbiguous: modal, planned, conditional, negated or versioned
	// prose, mixed actions, a replacement, default or gate, or a token the
	// action verb does not stand next to.
	ReasonAmbiguous = "CHLOG_ACTION_AMBIGUOUS"
	// ReasonMember: the encoder refused the member.
	ReasonMember = "CHLOG_MEMBER_REFUSED"
	// ReasonTooManyCandidates: a fragment names more than
	// MaxCandidatesPerFragment, or the scan more than MaxCandidates.
	ReasonTooManyCandidates = "CHLOG_TOO_MANY_CANDIDATES"
	// ReasonPanic: an internal fault.
	ReasonPanic = "READER_PANIC"

	// LedgerOverflow and LedgerInvalid are fault entries; the LEDGER_
	// prefix is reserved for them.
	LedgerOverflow  = "LEDGER_OVERFLOW"
	LedgerInvalid   = "LEDGER_INVALID"
	LedgerFaultItem = "ledger"
)

var (
	ledgerCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)
	ledgerItemRE = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=*\[\]-]{1,` + strconv.Itoa(MaxLedgerItemLen) + `}$`)
)

type ledgerSet map[LedgerEntry]bool

func (l ledgerSet) add(code, item string) { l[LedgerEntry{Code: code, Item: item}] = true }

// canonical returns the sorted ledger, or the single fault entry when an
// entry breaks the spelling rules or there are too many.
func (l ledgerSet) canonical() []LedgerEntry {
	out := make([]LedgerEntry, 0, len(l))
	for e := range l {
		if !ledgerCodeRE.MatchString(e.Code) || !ledgerItemRE.MatchString(e.Item) {
			return []LedgerEntry{{Code: LedgerInvalid, Item: LedgerFaultItem}}
		}
		out = append(out, e)
	}
	if len(out) > MaxLedgerEntries {
		return []LedgerEntry{{Code: LedgerOverflow, Item: LedgerFaultItem}}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Item < out[j].Item
	})
	return out
}
