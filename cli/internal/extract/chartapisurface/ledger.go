// SPDX-License-Identifier: AGPL-3.0-only

// Package chartapisurface reads a pinned chart archive statically and lists
// every (apiVersion, kind) the chart can produce under any values.
//
// It runs in measurement mode: the ledger it writes is a count of what a
// closed reader can and cannot list, never a rule, a trust output or an
// attestation. Completeness is proved from the archive bytes or the chart is
// withheld with a typed code; an empty scan is not a complete scan.
package chartapisurface

import (
	"bytes"
	"encoding/json"
	"sort"
)

// Schema names the ledger layout.
const Schema = "chart-api-surface/v1"

// Status values of a ledger and of a served-API check.
const (
	StatusComplete = "complete"
	StatusWithheld = "withheld"

	ResultWouldBlock = "would-block"
	ResultWouldPass  = "would-pass"
	ResultWithheld   = "withheld"
)

// Withheld codes. Each names one reason the API set cannot be called
// complete; a chart with any code is withheld.
const (
	CodeVersionKindBuilt   = "version_or_kind_built"
	CodeUserValue          = "version_or_kind_user_value"
	CodeVariable           = "version_or_kind_variable"
	CodeExpression         = "version_or_kind_expression"
	CodeInvalidValue       = "version_or_kind_invalid"
	CodeValueSetTooLarge   = "value_set_too_large"
	CodeFilesOrTpl         = "objects_from_files_or_tpl"
	CodeLookup             = "lookup_feeds_version_or_kind"
	CodeDependencyMissing  = "dependency_missing"
	CodeHelperNotFound     = "library_helper_not_found"
	CodeHelperAmbiguous    = "helper_ambiguous"
	CodeTemplateDepth      = "template_depth_exceeded"
	CodeTemplateParse      = "template_parse_error"
	CodeDocumentPairing    = "document_pairing"
	CodeListKind           = "list_kind_items_unscanned"
	CodeEmptyScan          = "empty_scan"
	CodeTooManyEntries     = "too_many_entries"
	CodeOracleUnavailable  = "oracle_unavailable"
	CodeToolBugOracleMatch = "tool_bug_oracle_mismatch"
)

// Entry groups.
const (
	GroupLiteral          = "literal"
	GroupCapabilitySwitch = "capability_switch"
	GroupLibraryHelper    = "library_helper"
	GroupInlineChoice     = "inline_choice"
	GroupTemplatedKindSet = "templated_kind_set"
)

// ChartID names the chart release a ledger describes.
type ChartID struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// Entry is one place a chart can produce an object.
type Entry struct {
	APIVersion   string `json:"api_version"`
	Kind         string `json:"kind"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Conditional  bool   `json:"conditional"`
	VersionGroup string `json:"version_group"`
	KindGroup    string `json:"kind_group"`
}

// Withheld is one typed reason the chart is not complete.
type Withheld struct {
	Code   string `json:"code"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Detail string `json:"detail,omitempty"`
}

// Blocker is an entry a served-API check would block on.
type Blocker struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	File       string `json:"file"`
	Line       int    `json:"line"`
}

// Pair is one (apiVersion, kind) without a location.
type Pair struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
}

// ServedCheck is the measurement result for one Kubernetes line. It is not a
// verdict.
type ServedCheck struct {
	Line     string    `json:"line"`
	Result   string    `json:"result"`
	Blockers []Blocker `json:"blockers"`
	// Notices are conditional entries the line does not serve.
	Notices []Blocker `json:"notices"`
	// NotBuiltin are pairs whose group the served lists do not know (custom
	// resources); they are never decided here.
	NotBuiltin []Pair `json:"not_builtin"`
	// Unknown are built-in pairs a partial served list neither confirms nor
	// refutes.
	Unknown []Pair   `json:"unknown"`
	Reasons []string `json:"reasons"`
}

// OracleResult is the comparison with an offline render of the chart.
type OracleResult struct {
	Result  string `json:"result"`
	Missing []Pair `json:"missing"`
}

// Ledger is the closed output for one chart release.
type Ledger struct {
	Schema       string        `json:"schema"`
	Mode         string        `json:"mode"`
	Chart        ChartID       `json:"chart"`
	Status       string        `json:"status"`
	APIs         []Entry       `json:"apis"`
	Withheld     []Withheld    `json:"withheld"`
	Notes        []string      `json:"notes"`
	ServedChecks []ServedCheck `json:"served_checks"`
	Oracle       *OracleResult `json:"oracle,omitempty"`
}

// Mode is always measurement.
const Mode = "measurement"

// Pairs returns the unique pairs the ledger lists, sorted.
func (l *Ledger) Pairs() []Pair {
	seen := map[Pair]bool{}
	for _, e := range l.APIs {
		seen[Pair{e.APIVersion, e.Kind}] = true
	}
	out := make([]Pair, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sortPairs(out)
	return out
}

func sortPairs(p []Pair) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].APIVersion != p[j].APIVersion {
			return p[i].APIVersion < p[j].APIVersion
		}
		return p[i].Kind < p[j].Kind
	})
}

// Finish sorts every list and sets the status from the withheld codes.
func (l *Ledger) Finish() {
	sort.SliceStable(l.APIs, func(i, j int) bool {
		a, b := l.APIs[i], l.APIs[j]
		switch {
		case a.APIVersion != b.APIVersion:
			return a.APIVersion < b.APIVersion
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.File != b.File:
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	sort.SliceStable(l.Withheld, func(i, j int) bool {
		a, b := l.Withheld[i], l.Withheld[j]
		switch {
		case a.Code != b.Code:
			return a.Code < b.Code
		case a.File != b.File:
			return a.File < b.File
		case a.Line != b.Line:
			return a.Line < b.Line
		}
		return a.Detail < b.Detail
	})
	// drop exact duplicates
	out := l.Withheld[:0]
	for i, w := range l.Withheld {
		if i == 0 || w != l.Withheld[i-1] {
			out = append(out, w)
		}
	}
	l.Withheld = out
	l.Status = StatusComplete
	if len(l.Withheld) > 0 {
		l.Status = StatusWithheld
	}
	if l.APIs == nil {
		l.APIs = []Entry{}
	}
	if l.Withheld == nil {
		l.Withheld = []Withheld{}
	}
	if l.Notes == nil {
		l.Notes = []string{}
	}
	if l.ServedChecks == nil {
		l.ServedChecks = []ServedCheck{}
	}
}

// Marshal renders the ledger deterministically.
func (l *Ledger) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
