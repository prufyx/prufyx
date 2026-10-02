// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"bytes"
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Entry is one candidate in exactly the pack entry schema.
type Entry struct {
	Project       string   `json:"project"`
	Description   string   `json:"description"`
	RequiredFacts []Fact   `json:"requiredFacts"`
	Rule          RuleJSON `json:"rule"`
}

// RuleJSON is the full rule as the engine parses it.
type RuleJSON struct {
	ID           string        `json:"id"`
	Operator     string        `json:"operator"`
	Subject      Subject       `json:"subject"`
	SetCondition *SetCondition `json:"setCondition,omitempty"`
	Evidence     Evidence      `json:"evidence"`
	ReasonCode   string        `json:"reasonCode"`
	NextAction   string        `json:"nextAction"`
}

// Evidence is the rule's evidence block for a mechanical rule.
type Evidence struct {
	State      string                            `json:"state"`
	Basis      string                            `json:"basis"`
	Extractor  constraintengine.Extractor        `json:"extractor"`
	DerivedAt  string                            `json:"derivedAt"`
	ReviewedAt string                            `json:"reviewedAt"`
	ValidUntil string                            `json:"validUntil"`
	Sources    []constraintengine.SourceEvidence `json:"sources"`
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
}

// Vector kinds.
const (
	VectorBlocked           = "blocked"
	VectorPassComplete      = "pass-complete"
	VectorUnknownIncomplete = "unknown-incomplete"
)

// Canonical renders v as canonical JSON: object keys sorted by byte order,
// two-space indentation, no HTML escaping, a final newline. Equal values
// always render to equal bytes.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// compact renders v as canonical single-line JSON.
func compact(v any) (json.RawMessage, error) {
	pretty, err := Canonical(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, pretty); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
