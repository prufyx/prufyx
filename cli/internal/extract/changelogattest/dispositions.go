// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

// Mark kinds.
const (
	// KindNotOperatorFacing says the item is not a breaking change, removal,
	// rename, deprecation, storage/API format change or minimum-version
	// change. It needs a reasonClass.
	KindNotOperatorFacing = "not-operator-facing"
	// KindRule says a pack rule covers the item. It needs a ruleId and no
	// reasonClass.
	KindRule = "rule"
)

// Who proposed a mark.
const (
	ProposedByModel  = "model"
	ProposedByPerson = "person"
)

// StateReviewed is the only state a mark of a dispositions file may carry. A
// proposal that no person has reviewed is not pack data: it is refused when
// the file is loaded, whoever proposed it.
const StateReviewed = "reviewed"

// ReasonClasses is the closed list of reasons a not-operator-facing mark may
// give.
var ReasonClasses = []string{
	"internal-refactor", "docs", "test-ci", "build-packaging", "new-optional-feature",
	"bugfix-no-contract-change", "performance", "dependency-bump-no-minimum", "component-not-shipped",
}

// Bounds of a dispositions file.
const (
	MaxFileBytes = 4 << 20
	MaxMarks     = 50000
)

// Mark is one reviewed disposition of one changelog item, keyed by the item
// digest and its occurrence number (an identical item repeated under one
// heading has one digest and several occurrences).
type Mark struct {
	ItemDigest  string `json:"itemDigest"`
	Occurrence  int    `json:"occurrence"`
	Tag         string `json:"tag"`
	Kind        string `json:"kind"`
	RuleID      string `json:"ruleId,omitempty"`
	ReasonClass string `json:"reasonClass,omitempty"`
	State       string `json:"state"`
	ReviewedAt  string `json:"reviewedAt"`
	ProposedBy  string `json:"proposedBy"`
}

// Dispositions is the reviewed pack data of one component: pack data, not
// code, so it is not part of the extractor's code digest.
type Dispositions struct {
	Component string `json:"component"`
	Marks     []Mark `json:"marks"`
}

type markKey struct {
	digest string
	occ    int
}

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadDispositions parses and validates a dispositions file for component.
// It is strict: unknown fields, trailing data, a different component, a mark
// that is not in the reviewed state, an unknown kind or reasonClass, a rule
// mark without a rule id, a duplicate and a not-operator-facing mark mixed
// with a rule mark on one item are all refused.
func LoadDispositions(raw []byte, component string) (*Dispositions, error) {
	if len(raw) > MaxFileBytes {
		return nil, fmt.Errorf("dispositions: file is %d bytes, bound %d", len(raw), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Dispositions
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("dispositions: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("dispositions: data after the document")
	}
	if component == "" || d.Component != component {
		return nil, fmt.Errorf("dispositions: component %q, want %q", d.Component, component)
	}
	if d.Marks == nil {
		d.Marks = []Mark{}
	}
	if len(d.Marks) > MaxMarks {
		return nil, fmt.Errorf("dispositions: %d marks, bound %d", len(d.Marks), MaxMarks)
	}
	classes := map[string]bool{}
	for _, c := range ReasonClasses {
		classes[c] = true
	}
	type seenKey struct {
		k    markKey
		kind string
		rule string
	}
	seen := map[seenKey]bool{}
	kinds := map[markKey]map[string]bool{}
	for i, m := range d.Marks {
		at := fmt.Sprintf("dispositions: mark %d", i)
		switch {
		case !digestRE.MatchString(m.ItemDigest):
			return nil, fmt.Errorf("%s: itemDigest is not a sha256 hex digest", at)
		case m.Occurrence < 1:
			return nil, fmt.Errorf("%s: occurrence must be at least 1", at)
		case m.Tag == "":
			return nil, fmt.Errorf("%s: tag is empty", at)
		case m.State != StateReviewed:
			return nil, fmt.Errorf("%s: state %q is not %q: an unreviewed mark is not pack data", at, m.State, StateReviewed)
		case m.ProposedBy != ProposedByModel && m.ProposedBy != ProposedByPerson:
			return nil, fmt.Errorf("%s: proposedBy %q", at, m.ProposedBy)
		}
		if t, err := time.Parse(time.RFC3339, m.ReviewedAt); err != nil || t.Location() != time.UTC || t.Format(time.RFC3339) != m.ReviewedAt {
			return nil, fmt.Errorf("%s: reviewedAt must be an RFC 3339 UTC time", at)
		}
		switch m.Kind {
		case KindNotOperatorFacing:
			if m.RuleID != "" || !classes[m.ReasonClass] {
				return nil, fmt.Errorf("%s: a not-operator-facing mark needs a reasonClass from the closed list and no ruleId", at)
			}
		case KindRule:
			if m.RuleID == "" || m.ReasonClass != "" {
				return nil, fmt.Errorf("%s: a rule mark needs a ruleId and no reasonClass", at)
			}
		default:
			return nil, fmt.Errorf("%s: kind %q", at, m.Kind)
		}
		k := markKey{m.ItemDigest, m.Occurrence}
		sk := seenKey{k, m.Kind, m.RuleID}
		if seen[sk] {
			return nil, fmt.Errorf("%s: duplicate mark", at)
		}
		seen[sk] = true
		if kinds[k] == nil {
			kinds[k] = map[string]bool{}
		}
		kinds[k][m.Kind] = true
		if len(kinds[k]) > 1 {
			return nil, fmt.Errorf("%s: an item is both not-operator-facing and bound to a rule", at)
		}
	}
	sort.SliceStable(d.Marks, func(i, j int) bool {
		a, b := d.Marks[i], d.Marks[j]
		if a.ItemDigest != b.ItemDigest {
			return a.ItemDigest < b.ItemDigest
		}
		if a.Occurrence != b.Occurrence {
			return a.Occurrence < b.Occurrence
		}
		return a.RuleID < b.RuleID
	})
	return &d, nil
}

func (d *Dispositions) index() map[markKey][]Mark {
	out := map[markKey][]Mark{}
	for _, m := range d.Marks {
		k := markKey{m.ItemDigest, m.Occurrence}
		out[k] = append(out[k], m)
	}
	return out
}
