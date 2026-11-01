// SPDX-License-Identifier: AGPL-3.0-only

// Package ledger lists, for the pairs of one helm.values run, everything the
// extractor refused to classify and why. It only reads the extractor's
// proofs; it derives nothing and changes no rule. Its output is
// deterministic: the same proofs give the same bytes.
package ledger

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
)

// Scope says what a refusal is about.
type Scope string

// Scopes.
const (
	// ScopePair: the whole pair was withheld; Key is empty.
	ScopePair Scope = "pair"
	// ScopeRemoved: a key of the earlier chart the later schema might refuse.
	ScopeRemoved Scope = "removed"
	// ScopeRequired: a key the later schema requires.
	ScopeRequired Scope = "required"
	// ScopeTemplates: a template entry that was not scanned.
	ScopeTemplates Scope = "templates"
)

// Reason is the typed cause of a refusal.
type Reason string

// Pair-level reasons: a release did not read completely.
const (
	ChartDirMissing      Reason = "chart-dir-missing"
	ChartYAMLNotFile     Reason = "chart-yaml-not-a-file"
	ChartYAMLInvalid     Reason = "chart-yaml-invalid"
	ChartNameMismatch    Reason = "chart-name-mismatch"
	ChartVersionMismatch Reason = "chart-version-mismatch"
	ValuesNotFile        Reason = "values-not-a-file"
	ValuesOutsideSubset  Reason = "values-outside-strict-subset"
	ValuesNotMapping     Reason = "values-not-a-mapping"
	SchemaNotFile        Reason = "schema-not-a-file"
	SchemaInvalid        Reason = "schema-invalid"
	RequirementsInvalid  Reason = "requirements-invalid"
	RequirementsNotFile  Reason = "requirements-not-a-file"
	TemplatesOverBound   Reason = "templates-over-bound"
	// UnclassifiedProblem is a read problem this package has no name for;
	// it is listed rather than dropped.
	UnclassifiedProblem Reason = "unclassified-problem"
)

// Key-level reasons.
const (
	SchemaOpaque        Reason = "schema-opaque"
	SubchartKey         Reason = "subchart-key"
	PackagedSubchart    Reason = "packaged-subchart"
	MemberUnexpressible Reason = "member-unexpressible"
	MemberOverBound     Reason = "member-over-bound"
	TemplateNotScanned  Reason = "template-not-scanned"
)

// Entry is one refusal.
type Entry struct {
	Pair   string `json:"pair"`
	Scope  Scope  `json:"scope"`
	Key    string `json:"key,omitempty"`
	Reason Reason `json:"reason"`
	// Detail is the extractor's own wording, kept for people; it is bounded
	// public text, never a value from a user's files.
	Detail string `json:"detail,omitempty"`
}

// Ledger is a sorted list of refusals.
type Ledger struct {
	Entries []Entry `json:"entries"`
}

// Collect lists the refusals in one pair's proof. pair names the pair
// ("from->to"). A nil proof gives none.
func Collect(pair string, p *helmvalues.PairProof) []Entry {
	if p == nil {
		return nil
	}
	var out []Entry
	for _, side := range []*helmvalues.SideRecord{p.From, p.To} {
		if side == nil {
			continue
		}
		if side.Problem != "" {
			out = append(out, Entry{Pair: pair, Scope: ScopePair, Reason: pairReason(side.Problem), Detail: side.Tag + ": " + side.Problem})
			continue
		}
		for _, name := range side.Templates.Refused {
			out = append(out, Entry{Pair: pair, Scope: ScopeTemplates, Key: name, Reason: TemplateNotScanned, Detail: side.Tag})
		}
	}
	if p.Required != nil {
		for _, n := range p.Required.Opaque {
			out = append(out, Entry{Pair: pair, Scope: ScopeRequired, Key: n.Path, Reason: SchemaOpaque, Detail: n.Reason})
		}
		for _, k := range p.Required.Keys {
			if r, ok := keyReason(k.Class); ok {
				out = append(out, Entry{Pair: pair, Scope: ScopeRequired, Key: k.Path, Reason: r})
			}
		}
	}
	if p.Removed != nil {
		for _, k := range p.Removed.Keys {
			if r, ok := keyReason(k.Class); ok {
				out = append(out, Entry{Pair: pair, Scope: ScopeRemoved, Key: k.Path, Reason: r, Detail: k.Detail})
			} else if k.Class == helmvalues.ClassRejected && strings.Contains(p.Removed.Outcome, "over the bound") {
				// Every rejected key is held back when the rule would name
				// more members than a rule may hold.
				out = append(out, Entry{Pair: pair, Scope: ScopeRemoved, Key: k.Path, Reason: MemberOverBound, Detail: k.Detail})
			}
		}
	}
	return out
}

// FromAny is Collect for a proof that was stored as JSON.
func FromAny(pair string, proof any) ([]Entry, error) {
	if proof == nil {
		return nil, nil
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("ledger: proof of %s: %w", pair, err)
	}
	var p helmvalues.PairProof
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("ledger: proof of %s: %w", pair, err)
	}
	return Collect(pair, &p), nil
}

// New returns the ledger of the given entries, sorted and without
// duplicates.
func New(entries ...[]Entry) *Ledger {
	var all []Entry
	for _, e := range entries {
		all = append(all, e...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Pair != b.Pair {
			return a.Pair < b.Pair
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Detail < b.Detail
	})
	out := all[:0]
	for i, e := range all {
		if i > 0 && e == all[i-1] {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	return &Ledger{Entries: out}
}

// Counts is the number of refusals per scope and reason, as "scope/reason".
func (l *Ledger) Counts() map[string]int {
	m := map[string]int{}
	for _, e := range l.Entries {
		m[string(e.Scope)+"/"+string(e.Reason)]++
	}
	return m
}

// JSON is the ledger as indented JSON ending in a newline.
func (l *Ledger) JSON() ([]byte, error) {
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// keyReason maps a key class that is a refusal to its reason. A class that
// is a decision (rejected, still defaulted, already rejected, default,
// already required, inactive or empty ancestor, null default) is not one.
func keyReason(class string) (Reason, bool) {
	switch class {
	case helmvalues.ClassOpaque:
		return SchemaOpaque, true
	case helmvalues.ClassSubchart:
		return SubchartKey, true
	case helmvalues.ClassOpaqueSubcharts:
		return PackagedSubchart, true
	case helmvalues.ClassUnexpressible:
		return MemberUnexpressible, true
	case helmvalues.ClassOverBound:
		return MemberOverBound, true
	}
	return "", false
}

// pairReason names a release's read problem from the extractor's wording.
// The tests pin every wording; a new one lands as UnclassifiedProblem.
func pairReason(problem string) Reason {
	has := func(s string) bool { return strings.Contains(problem, s) }
	switch {
	case has("does not exist"):
		return ChartDirMissing
	case has("Chart.yaml is not a file"):
		return ChartYAMLNotFile
	case has("values.yaml is not a file"):
		return ValuesNotFile
	case has("values.schema.json is not a file"):
		return SchemaNotFile
	case has("requirements.yaml is not a file"):
		return RequirementsNotFile
	case has("values.yaml is not a mapping"):
		return ValuesNotMapping
	case has("names chart"):
		return ChartNameMismatch
	case has("declares version"):
		return ChartVersionMismatch
	case has("Chart.yaml: "):
		return ChartYAMLInvalid
	case has("values.yaml: "):
		return ValuesOutsideSubset
	case has("values.schema.json: "):
		return SchemaInvalid
	case has("requirements.yaml: "):
		return RequirementsInvalid
	case strings.HasPrefix(problem, "templates: "):
		return TemplatesOverBound
	}
	return UnclassifiedProblem
}

// All lists every reason this package can give, in a fixed order.
func All() []Reason {
	return []Reason{
		ChartDirMissing, ChartYAMLNotFile, ChartYAMLInvalid, ChartNameMismatch, ChartVersionMismatch,
		ValuesNotFile, ValuesOutsideSubset, ValuesNotMapping, SchemaNotFile, SchemaInvalid,
		RequirementsInvalid, RequirementsNotFile, TemplatesOverBound, UnclassifiedProblem,
		SchemaOpaque, SubchartKey, PackagedSubchart, MemberUnexpressible, MemberOverBound, TemplateNotScanned,
	}
}
