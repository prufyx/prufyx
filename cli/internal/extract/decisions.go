// SPDX-License-Identifier: AGPL-3.0-only
package extract

import (
	"bytes"
	"errors"

	"github.com/prufyx/prufyx/cli/internal/extract/decision"
)

func (o *Output) capture(file, kind string) func(any) error {
	return func(v any) error {
		raw, e := Canonical(v)
		if e != nil {
			return e
		}
		raw, e = decision.Record(raw, kind)
		if e != nil {
			return e
		}
		o.beforeStamp[file] = append(o.beforeStamp[file], raw)
		return nil
	}
}

// DecisionFiles emits the explicit v2 format after checking that every
// stamped record preserves the resolved semantic record captured beforehand.
// It preserves all v1 outputs in the receipt; it does not authorize a pack.
func (o *Output) DecisionFiles() (map[string][]byte, error) {
	if o.beforeStamp == nil {
		return nil, errors.New("output lacks pre-stamp emission")
	}
	groups := []struct {
		file, kind string
		values     []any
	}{{file: FileCandidates, kind: "candidate"}, {file: FileAttestations, kind: "attestation"}, {file: FileDrafts, kind: "draft"}}
	for _, v := range o.Entries {
		groups[0].values = append(groups[0].values, v)
	}
	for _, v := range o.Attestations {
		groups[1].values = append(groups[1].values, v)
	}
	for _, v := range o.Drafts {
		groups[2].values = append(groups[2].values, v)
	}
	for _, g := range groups {
		before := o.beforeStamp[g.file]
		if len(before) != len(g.values) {
			return nil, errors.New("pre-stamp inventory changed")
		}
		used := make([]bool, len(before))
		for _, v := range g.values {
			raw, e := Canonical(v)
			if e != nil {
				return nil, e
			}
			raw, e = decision.Record(raw, g.kind)
			if e != nil {
				return nil, e
			}
			found := false
			for i, b := range before {
				if !used[i] && bytes.Equal(raw, b) {
					used[i] = true
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("semantic record changed after pre-stamp emission")
			}
		}
	}
	legacy, e := o.Files()
	if e != nil {
		return nil, e
	}
	files := []decision.File{}
	for name, b := range legacy {
		files = append(files, decision.File{Path: name, Mode: 0o644, Data: b})
	}
	p, e := decision.Bridge(files)
	if e != nil {
		return nil, e
	}
	return p.Files()
}
