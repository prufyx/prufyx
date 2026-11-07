// SPDX-License-Identifier: AGPL-3.0-only

package artifacthubchanges

import (
	"regexp"
	"sort"
	"strconv"
)

// LedgerEntry names one item the reader withheld and why. It carries
// identifiers only, never description content: Code is the withhold reason,
// Item the repository path of the Chart.yaml. The result ledger is canonical:
// sorted by (Code, Item), without duplicates, at most MaxLedgerEntries
// entries.
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
// must not be read as "the charts name nothing else".
const (
	// ReasonTooManyCharts: the target lists more charts than MaxCharts.
	ReasonTooManyCharts = "CHART_TOO_MANY"
	// ReasonUnsafePath: a chart path outside the allowed spelling.
	ReasonUnsafePath = "CHART_UNSAFE_PATH"
	// ReasonMissing: the Chart.yaml is absent or unreadable.
	ReasonMissing = "CHART_MISSING"
	// ReasonTooLarge: the Chart.yaml exceeds MaxChartBytes.
	ReasonTooLarge = "CHART_TOO_LARGE"
	// ReasonParse: not one well-formed YAML document, an unknown field, a
	// duplicate key, an alias, a tag, or a field of the wrong shape, in the
	// Chart.yaml or in the annotation document inside it.
	ReasonParse = "CHART_PARSE"
	// ReasonSchema: apiVersion is not the supported one.
	ReasonSchema = "CHART_SCHEMA_UNSUPPORTED"
	// ReasonAnnotationTooLarge: the changes annotation exceeds
	// MaxAnnotationBytes.
	ReasonAnnotationTooLarge = "CHANGES_ANNOTATION_TOO_LARGE"
	// ReasonTooManyChanges: more entries than MaxChanges.
	ReasonTooManyChanges = "CHANGES_TOO_MANY"
	// ReasonKindUnknown: the change kind is not in the reviewed list.
	ReasonKindUnknown = "CHANGE_KIND_UNKNOWN"
	// ReasonTextTooLarge: a description exceeds MaxDescriptionBytes.
	ReasonTextTooLarge = "CHANGE_TEXT_TOO_LARGE"
	// ReasonNoSignal: a deprecated or removed entry whose description does
	// not state the action in words.
	ReasonNoSignal = "CHANGE_NO_SIGNAL"
	// ReasonNoToken: the description names nothing in backticks.
	ReasonNoToken = "CHANGE_NO_TOKEN"
	// ReasonMultipleTokens: more than one distinct backticked identifier, so
	// the action cannot be tied to one of them.
	ReasonMultipleTokens = "CHANGE_MULTIPLE_TOKENS"
	// ReasonUnclassified: the backticked token is not a long flag or a
	// values key path, or the description quotes a code block.
	ReasonUnclassified = "CHANGE_TOKEN_UNCLASSIFIED"
	// ReasonAmbiguous: the description is modal, planned, conditional,
	// negated, versioned, names a replacement or default, mixes actions,
	// contradicts the kind, or the action verb is not next to the token.
	ReasonAmbiguous = "CHANGE_ACTION_AMBIGUOUS"
	// ReasonMember: the encoder refused the member.
	ReasonMember = "CHANGE_MEMBER_REFUSED"
	// ReasonTooManyCandidates: a chart names more than MaxCandidatesPerChart.
	ReasonTooManyCandidates = "CHANGES_TOO_MANY_CANDIDATES"
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
