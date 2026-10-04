// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
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
	// Members are the pack's top-level members other than entries, as
	// admission reads them.
	Members map[string]json.RawMessage
	Entries map[string]*entry
	Order   []string
	// Records are the pack's line attestations and path policies by
	// record ID, read only for a pack whose spec has Records.
	Records     map[string]*record
	RecordOrder []string
}

// loadPack reads a pack as the engine admits it: a pack with a repeated or
// case-variant member anywhere is refused, and every entry is the one
// admission decodes (re-encoded from the engine's own types), so the gate
// classifies exactly what the engine would admit, never a second reading
// of the same bytes.
func loadPack(t Tree, spec PackSpec) (*loadedPack, error) {
	raw, err := t.Read(spec.Path, MaxFileBytes)
	if errors.Is(err, ErrMissing) {
		return &loadedPack{Spec: spec, Members: map[string]json.RawMessage{}, Entries: map[string]*entry{}, Records: map[string]*record{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return parsePack(spec, raw)
}

// parsePack reads one pack file's bytes as loadPack does.
func parsePack(spec PackSpec, raw []byte) (*loadedPack, error) {
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", spec.Path, err)
	}
	members, entries, err := spec.View(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: the engine cannot read the pack: %w", spec.Path, err)
	}
	p := &loadedPack{Spec: spec, Present: true, Raw: raw, Members: members, Entries: map[string]*entry{}, Records: map[string]*record{}}
	if spec.Records {
		if p.Records, p.RecordOrder, err = loadRecords(raw); err != nil {
			return nil, fmt.Errorf("%s: the pack's records cannot be read: %w", spec.Path, err)
		}
	}
	for i, admitted := range entries {
		e, err := newEntry(admitted)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d: %w", spec.Path, i, err)
		}
		if _, dup := p.Entries[e.RuleID]; dup {
			return nil, fmt.Errorf("%s: rule id %s appears twice", spec.Path, e.RuleID)
		}
		p.Entries[e.RuleID] = e
		p.Order = append(p.Order, e.RuleID)
	}
	return p, nil
}

// newEntry indexes one entry as admission reads it.
func newEntry(admitted json.RawMessage) (*entry, error) {
	if err := strictjson.Check(admitted); err != nil {
		return nil, err
	}
	var shape struct {
		Project string `json:"project"`
		Rule    struct {
			ID       string          `json:"id"`
			Range    json.RawMessage `json:"range"`
			Evidence evidenceView    `json:"evidence"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(admitted, &shape); err != nil || shape.Rule.ID == "" {
		return nil, errors.New("no rule id")
	}
	canonical, err := extract.Canonical(admitted)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", shape.Rule.ID, err)
	}
	generic, err := decodeGeneric(admitted)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", shape.Rule.ID, err)
	}
	return &entry{
		RuleID: shape.Rule.ID, Project: shape.Project, Raw: admitted, Canonical: canonical,
		generic: generic, Evidence: shape.Rule.Evidence, Range: shape.Rule.Range,
	}, nil
}

func decodeAny(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
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
