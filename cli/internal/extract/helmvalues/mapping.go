// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Withhold reasons of the anchor mapping. A reason is data, never an
// inference: every one names why a line or a pair has no decision.
const (
	// ReasonMappingMissing: no final chart release is mapped to the line.
	ReasonMappingMissing = "mapping-missing"
	// ReasonMappingAmbiguous: more than one final chart release is mapped to
	// the line; the newest one never wins.
	ReasonMappingAmbiguous = "mapping-ambiguous"
	// ReasonMappingTagMissing: the mapped chart's tag is not in the index.
	ReasonMappingTagMissing = "mapping-tag-missing"
	// ReasonMappingCommit: the tag names another commit than the row pins.
	ReasonMappingCommit = "mapping-commit-mismatch"
	// ReasonNoSchemaEarlier and ReasonNoSchemaLater: a side has no
	// values.schema.json. Checked before any derivation; an empty rule list
	// is never read as "nothing refused" when a side has no schema.
	ReasonNoSchemaEarlier = "NO_SCHEMA_EARLIER_SIDE"
	ReasonNoSchemaLater   = "NO_SCHEMA_LATER_SIDE"
	// ReasonSchemaOpen: the root of a side's schema does not set
	// additionalProperties to false, so it refuses no unknown key.
	ReasonSchemaOpen = "schema-open"
	// ReasonMappedInert: the pair was derived for its proof only. The
	// chart-values attestation family does not exist yet, so a mapped target
	// decides no pair and emits no rule.
	ReasonMappedInert = "INERT_NO_ATTESTATION_FAMILY"
)

// mappedTargetsEmitRules is the one switch that lets a mapped target return
// rules. It is false: until the attestation family exists, a mapped target
// derives its proof and withholds every pair. A test pins it.
const mappedTargetsEmitRules = false

// LineStatus is the outcome of resolving one product line of a mapping.
type LineStatus struct {
	Line string `json:"line"`
	// Reason is empty when the line resolved to exactly one pinned chart.
	Reason string `json:"reason,omitempty"`
	Chart  string `json:"chart,omitempty"`
	Tag    string `json:"tag,omitempty"`
	Commit string `json:"commit,omitempty"`
	// Candidates is the number of final chart releases mapped to the line.
	Candidates int `json:"candidates"`
}

// MappedPair is one pair of consecutive lines of the window.
type MappedPair struct {
	FromLine, ToLine string
	// Reason is empty when both lines resolved.
	Reason string
	Pair   extract.VersionPair
}

// resolveLine picks the chart of a line: exactly one final candidate, else a
// named reason. A leading v of an appVersion is ignored and a pre-release is
// not a candidate. The chart's default image tag is not an input: only the
// appVersion of a row maps a chart to a line.
func (m *AnchorMapping) resolveLine(line string) (MappingRow, int, string) {
	var cands []MappingRow
	for _, r := range m.Rows {
		l, final, ok := normalAppVersion(r.AppVersion)
		if r.Line == line && ok && final && l == line {
			cands = append(cands, r)
		}
	}
	switch len(cands) {
	case 0:
		return MappingRow{}, 0, ReasonMappingMissing
	case 1:
		return cands[0], 1, ""
	}
	return MappingRow{}, len(cands), ReasonMappingAmbiguous
}

// lineStatuses resolves every line of the window against the tag index.
func (x *Extractor) lineStatuses(index extract.ReleaseIndex) []LineStatus {
	m := x.target.AnchorMapping
	if m == nil {
		return nil
	}
	tags := map[string]string{}
	for _, t := range index.Tags {
		if extract.IsCommitSHA(t.Commit) {
			tags[t.Name] = t.Commit
		}
	}
	out := make([]LineStatus, 0, len(m.Lines))
	for _, l := range m.Lines {
		row, n, reason := m.resolveLine(l)
		st := LineStatus{Line: l, Reason: reason, Candidates: n}
		if reason == "" {
			st.Chart, st.Tag, st.Commit = row.Chart, x.target.TagPrefix+row.Chart, row.ChartCommit
			switch c, ok := tags[st.Tag]; {
			case !ok:
				st.Reason = ReasonMappingTagMissing
			case c != row.ChartCommit:
				st.Reason = ReasonMappingCommit
			}
		}
		out = append(out, st)
	}
	return out
}

// MappedPairs lists every pair of consecutive lines of the window. A pair
// whose lines both resolved carries its pinned VersionPair; any other pair
// is withheld with the reason of its first unresolved line, both lines
// withheld with it.
func (x *Extractor) MappedPairs(index extract.ReleaseIndex) []MappedPair {
	st := x.lineStatuses(index)
	var out []MappedPair
	for i := 1; i < len(st); i++ {
		a, b := st[i-1], st[i]
		mp := MappedPair{FromLine: a.Line, ToLine: b.Line}
		switch {
		case a.Reason != "":
			mp.Reason = fmt.Sprintf("%s: line %s", a.Reason, a.Line)
		case b.Reason != "":
			mp.Reason = fmt.Sprintf("%s: line %s", b.Reason, b.Line)
		default:
			mp.Pair = extract.VersionPair{
				Repo: index.Repo,
				From: a.Chart, FromTag: a.Tag, FromCommit: a.Commit,
				To: b.Chart, ToTag: b.Tag, ToCommit: b.Commit,
			}
		}
		out = append(out, mp)
	}
	return out
}

// mappedPairs is the pair list of a mapped target: only pairs whose two
// lines resolved to one pinned chart each.
func (x *Extractor) mappedPairs(index extract.ReleaseIndex) []extract.VersionPair {
	x.mu.Lock()
	x.lines, x.lineOf = map[string]*releaseLine{}, map[string]string{}
	x.mapping = x.lineStatuses(index)
	x.mu.Unlock()
	var out []extract.VersionPair
	for _, mp := range x.MappedPairs(index) {
		if mp.Reason == "" {
			out = append(out, mp.Pair)
		}
	}
	return out
}

// MappingRecord is the proof of the mapping: how every line of the window
// resolved, and the pairs that were withheld by the mapping.
type MappingRecord struct {
	Mode     string       `json:"mode"`
	Lines    []LineStatus `json:"lines"`
	Withheld []string     `json:"withheld"`
}

func (x *Extractor) mappingRecord() *MappingRecord {
	x.mu.Lock()
	st := append([]LineStatus(nil), x.mapping...)
	x.mu.Unlock()
	rec := &MappingRecord{Mode: "appVersion", Lines: st, Withheld: []string{}}
	for i := 1; i < len(st); i++ {
		switch {
		case st[i-1].Reason != "":
			rec.Withheld = append(rec.Withheld, fmt.Sprintf("%s>%s: %s", st[i-1].Line, st[i].Line, st[i-1].Reason))
		case st[i].Reason != "":
			rec.Withheld = append(rec.Withheld, fmt.Sprintf("%s>%s: %s", st[i-1].Line, st[i].Line, st[i].Reason))
		}
	}
	sort.Strings(rec.Withheld)
	return rec
}

// schemaGate is checked before any derivation of a mapped pair: a side with
// no schema, or a schema whose root is open, decides nothing.
func schemaGate(from, to *side) string {
	switch {
	case from.schema == nil:
		return ReasonNoSchemaEarlier
	case to.schema == nil:
		return ReasonNoSchemaLater
	case !rootClosed(from.schema) || !rootClosed(to.schema):
		return ReasonSchemaOpen
	}
	return ""
}

// rootClosed reports whether the schema's root sets additionalProperties to
// false.
func rootClosed(s schemaNode) bool {
	v, ok := s["additionalProperties"].(bool)
	return ok && !v
}
