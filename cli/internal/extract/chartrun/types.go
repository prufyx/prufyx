// SPDX-License-Identifier: AGPL-3.0-only

// Package chartrun runs chart extractors: extractors whose rules are about a
// Helm chart (the rule subject names the chart, and from and to are chart
// versions) and may be require_set_member rules or carry a
// require_component_version dependency on another component.
//
// It is a package of its own, next to the extract framework rather than
// inside it, so that the framework's source does not change for it. Every
// extractor's code digest covers the framework's Go files; the Kubernetes
// and CRD extractors import neither this package nor any chart extractor, so
// nothing here can change what they derive and their digests do not cover
// it (extractcli's tests hold both). A chart extractor's digest covers the
// framework, this package and its own package (CodeFiles).
//
// Run, Verify and the output files follow extract.Run, extract.Verify and
// extract.Output exactly (same manifest schema, file names and reads logs);
// the differences are the chart subject, the dependency, the vectors of the
// two operators extract does not generate, and the missing members a
// vector expects. Chart extractors do not attest lines.
package chartrun

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Extractor derives chart rule candidates from pinned upstream bytes. Its
// contract is extract.Extractor's (deterministic, pinned pairs, *Withheld for
// a pair that cannot be established completely) with chart candidates, and
// it always exposes its own source for the code digest.
type Extractor interface {
	ID() string
	Version() string
	Applies(repo extract.RepoRef) bool
	Pairs(index extract.ReleaseIndex) []extract.VersionPair
	Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (Extraction, error)
	SourceFiles() (dir string, files fs.FS)
}

// Extraction is the result for one pair.
type Extraction struct {
	Candidates []Candidate
	// Proof is the extractor's own account of the derivation; it is
	// recorded in the manifest and must marshal deterministically.
	Proof any
}

// Candidate is one chart rule an extractor proposes. The framework adds the
// evidence state, basis, extractor identity, times and source digests.
type Candidate struct {
	Project       string
	Description   string
	RequiredFacts []extract.Fact
	Rule          Rule
	Sources       []extract.SourceRef
	// PassMembers are members that are never forbidden (forbid_set_member)
	// or never required (require_set_member), used for the vectors. They
	// may be empty.
	PassMembers []string
}

// Rule is the part of a chart rule an extractor decides.
type Rule struct {
	ID           string
	Operator     string
	Subject      Subject
	SetCondition *extract.SetCondition
	// Dependency is used by require_component_version rules: the version
	// bound another component must meet.
	Dependency *Dependency
	ReasonCode string
	NextAction string
}

// Subject is the reviewed anchor transition. Chart is set for a rule about
// a Helm chart: the transition is then between chart versions of that
// chart, never application versions.
type Subject struct {
	Component string                     `json:"component"`
	Chart     *constraintengine.ChartRef `json:"chart,omitempty"`
	From      string                     `json:"from"`
	To        string                     `json:"to"`
}

// Dependency is a require_component_version bound on another component.
type Dependency struct {
	Side       string `json:"side"`
	Component  string `json:"component"`
	Comparison string `json:"comparison"`
	Version    string `json:"version"`
}

// Entry is one candidate in exactly the pack entry schema.
type Entry struct {
	Project       string         `json:"project"`
	Description   string         `json:"description"`
	RequiredFacts []extract.Fact `json:"requiredFacts"`
	Rule          RuleJSON       `json:"rule"`
}

// RuleJSON is the full rule as the engine parses it.
type RuleJSON struct {
	ID           string                `json:"id"`
	Operator     string                `json:"operator"`
	Subject      Subject               `json:"subject"`
	SetCondition *extract.SetCondition `json:"setCondition,omitempty"`
	Dependency   *Dependency           `json:"dependency,omitempty"`
	Evidence     extract.Evidence      `json:"evidence"`
	ReasonCode   string                `json:"reasonCode"`
	NextAction   string                `json:"nextAction"`
}

// Vector is one generated test vector: an engine input for the rule's
// transition and the verdict the rule must give.
type Vector struct {
	Name   string          `json:"name"`
	RuleID string          `json:"ruleId"`
	Kind   string          `json:"kind"`
	Input  json.RawMessage `json:"input"`
	Expect VectorExpect    `json:"expect"`
}

// VectorExpect is the expected claim of the vector's rule.
type VectorExpect struct {
	Status         string   `json:"status"`
	ReasonCode     string   `json:"reasonCode"`
	MatchedMembers []string `json:"matchedMembers,omitempty"`
	MissingMembers []string `json:"missingMembers,omitempty"`
}

// errRegistered is what a registered chart extractor answers through the
// extract.Extractor interface.
var errRegistered = errors.New("a chart extractor runs through chartrun only")

// Registered is a chart extractor as the extractor catalog holds it, next
// to the framework's extractors. Through the extract.Extractor interface it
// applies to no repository, names no pair and refuses to extract, so
// extract.Run and extract.Verify refuse it before reading anything; its
// SourceFiles are the extractor's own. Callers run it with Run and Verify
// after Unwrap.
type Registered struct{ x Extractor }

// Register wraps a chart extractor for the catalog.
func Register(x Extractor) extract.Extractor { return Registered{x: x} }

// Unwrap returns the chart extractor ex registers, if it is one.
func Unwrap(ex extract.Extractor) (Extractor, bool) {
	r, ok := ex.(Registered)
	if !ok || r.x == nil {
		return nil, false
	}
	return r.x, true
}

// ID implements extract.Extractor.
func (r Registered) ID() string { return r.x.ID() }

// Version implements extract.Extractor.
func (r Registered) Version() string { return r.x.Version() }

// Applies implements extract.Extractor: never, so extract.Run refuses it.
func (Registered) Applies(extract.RepoRef) bool { return false }

// Pairs implements extract.Extractor: none.
func (Registered) Pairs(extract.ReleaseIndex) []extract.VersionPair { return nil }

// Extract implements extract.Extractor: always refused.
func (Registered) Extract(context.Context, extract.PinnedReader, extract.VersionPair) (extract.Extraction, error) {
	return extract.Extraction{}, errRegistered
}

// SourceFiles implements extract.CodeSource: the extractor's own package.
func (r Registered) SourceFiles() (string, fs.FS) { return r.x.SourceFiles() }
