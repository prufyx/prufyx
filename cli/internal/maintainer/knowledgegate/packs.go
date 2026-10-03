// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// entry is one pack entry, indexed by its rule id.
type entry struct {
	RuleID    string
	Project   string
	Raw       json.RawMessage
	Canonical []byte
	generic   map[string]any
	Evidence  evidenceView
	Range     json.RawMessage
}

type evidenceView struct {
	State      string                      `json:"state"`
	Basis      string                      `json:"basis"`
	Extractor  *constraintengine.Extractor `json:"extractor"`
	DerivedAt  string                      `json:"derivedAt"`
	ReviewedAt string                      `json:"reviewedAt"`
	ValidUntil string                      `json:"validUntil"`
}

// effectiveBasis is the entry's basis, absent meaning reviewed.
func (e *entry) effectiveBasis() string { return constraintengine.EffectiveBasis(e.Evidence.Basis) }

// loadedPack is one pack as read from one tree.
type loadedPack struct {
	Spec    PackSpec
	Present bool
	Raw     []byte
	Entries map[string]*entry
	Order   []string
}

func loadPack(t Tree, spec PackSpec) (*loadedPack, error) {
	raw, err := t.Read(spec.Path, MaxFileBytes)
	if errors.Is(err, ErrMissing) {
		return &loadedPack{Spec: spec, Entries: map[string]*entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	p := &loadedPack{Spec: spec, Present: true, Raw: raw, Entries: map[string]*entry{}}
	var doc struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", spec.Path, err)
	}
	for i, rawEntry := range doc.Entries {
		var shape struct {
			Project string `json:"project"`
			Rule    struct {
				ID       string          `json:"id"`
				Range    json.RawMessage `json:"range"`
				Evidence evidenceView    `json:"evidence"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(rawEntry, &shape); err != nil || shape.Rule.ID == "" {
			return nil, fmt.Errorf("%s: entry %d has no rule id", spec.Path, i)
		}
		if _, dup := p.Entries[shape.Rule.ID]; dup {
			return nil, fmt.Errorf("%s: rule id %s appears twice", spec.Path, shape.Rule.ID)
		}
		canonical, err := extract.Canonical(rawEntry)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %s: %w", spec.Path, shape.Rule.ID, err)
		}
		generic, err := decodeGeneric(rawEntry)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %s: %w", spec.Path, shape.Rule.ID, err)
		}
		p.Entries[shape.Rule.ID] = &entry{
			RuleID: shape.Rule.ID, Project: shape.Project, Raw: rawEntry, Canonical: canonical,
			generic: generic, Evidence: shape.Rule.Evidence, Range: shape.Rule.Range,
		}
		p.Order = append(p.Order, shape.Rule.ID)
	}
	return p, nil
}

func decodeGeneric(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("entry is not an object")
	}
	return out, nil
}

// deepCopy copies a decoded JSON value.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopy(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCopy(val)
		}
		return out
	default:
		return v
	}
}

// lookup returns the value at a path of object keys, and whether it exists.
func lookup(v any, keys ...string) (any, bool) {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[k]; !ok {
			return nil, false
		}
	}
	return v, true
}

// setOrDelete sets the value at a path of object keys (deleting it when
// present is false). Every parent must exist.
func setOrDelete(v any, value any, present bool, keys ...string) bool {
	for _, k := range keys[:len(keys)-1] {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if v, ok = m[k]; !ok {
			return false
		}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	last := keys[len(keys)-1]
	if present {
		m[last] = value
	} else {
		delete(m, last)
	}
	return true
}

func canonicalOf(v any) []byte {
	raw, err := extract.Canonical(v)
	if err != nil {
		return nil
	}
	return raw
}

func sameAt(a, b any, keys ...string) bool {
	av, aok := lookup(a, keys...)
	bv, bok := lookup(b, keys...)
	if aok != bok {
		return false
	}
	return bytes.Equal(canonicalOf(av), canonicalOf(bv))
}
