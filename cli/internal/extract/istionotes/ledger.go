// SPDX-License-Identifier: AGPL-3.0-only

package istionotes

import (
	"regexp"
	"sort"
	"strconv"
)

// LedgerEntry names one item the reader withheld and why. It carries
// identifiers only, never note content: Code is the withhold reason, Item
// the repository path of the note. The result ledger is canonical: sorted by
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
// must not be read as "the notes name nothing else".
const (
	// ReasonDirMissing: the notes directory is absent or unlistable.
	ReasonDirMissing = "NOTES_DIR_MISSING"
	// ReasonTooManyFiles: more entries than MaxFiles.
	ReasonTooManyFiles = "NOTES_TOO_MANY_FILES"
	// ReasonEntryNotFile: a tree, submodule, symlink or non-YAML entry.
	ReasonEntryNotFile = "NOTE_ENTRY_NOT_FILE"
	// ReasonUnsafeName: an entry name outside the allowed spelling.
	ReasonUnsafeName = "NOTE_UNSAFE_NAME"
	// ReasonUnreadable: the blob could not be read.
	ReasonUnreadable = "NOTE_UNREADABLE"
	// ReasonTooLarge: the note exceeds MaxNoteBytes.
	ReasonTooLarge = "NOTE_TOO_LARGE"
	// ReasonParse: not one well-formed YAML document, an unknown field, a
	// duplicate key, an alias, or a field of the wrong shape.
	ReasonParse = "NOTE_PARSE"
	// ReasonSchema: apiVersion is not the supported one.
	ReasonSchema = "NOTE_SCHEMA_UNSUPPORTED"
	// ReasonKindUnknown: the note kind is not in the reviewed list.
	ReasonKindUnknown = "NOTE_KIND_UNKNOWN"
	// ReasonTextTooLarge: a text block exceeds MaxQuoteBytes.
	ReasonTextTooLarge = "NOTE_TEXT_TOO_LARGE"
	// ReasonNoToken: the text says removed or deprecated but names nothing
	// in backticks.
	ReasonNoToken = "NOTE_SIGNAL_NO_TOKEN"
	// ReasonUnclassified: a backticked token next to a removal or
	// deprecation signal is not a flag, a known CRD kind or a known field.
	ReasonUnclassified = "NOTE_TOKEN_UNCLASSIFIED"
	// ReasonAmbiguous: the text mixes removal and deprecation, or negates
	// the signal, so the action cannot be stated.
	ReasonAmbiguous = "NOTE_ACTION_AMBIGUOUS"
	// ReasonMember: the encoder refused the member.
	ReasonMember = "NOTE_MEMBER_REFUSED"
	// ReasonTooManyCandidates: a note names more than MaxCandidatesPerNote.
	ReasonTooManyCandidates = "NOTE_TOO_MANY_CANDIDATES"
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
