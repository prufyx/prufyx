// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
)

// activeRuleEnds lists the end dates of the entries' active rules. A rule
// whose evidence is withdrawn is not active and never counts; a date that
// does not parse as UTC RFC 3339 was already refused at admission and is
// left out.
func activeRuleEnds(entries []Entry) []time.Time {
	var ends []time.Time
	for _, entry := range entries {
		var shape struct {
			Evidence struct {
				State      string `json:"state"`
				ValidUntil string `json:"validUntil"`
			} `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil || shape.Evidence.State != "active" {
			continue
		}
		if end, err := time.Parse(time.RFC3339, shape.Evidence.ValidUntil); err == nil {
			ends = append(ends, end.UTC())
		}
	}
	return ends
}

// sectionEnds lists the end dates of the evidence in one optional pack
// section (line attestations, served-API lists, path policies). An item
// without an evidence state (mechanical evidence) is applicable; an item
// with a state other than "active" is not and never counts. An item whose
// date is missing or not UTC RFC 3339 is an error, so a gate built on this
// fails closed.
func sectionEnds(section json.RawMessage) ([]time.Time, error) {
	if len(section) == 0 {
		return nil, nil
	}
	var items []struct {
		Evidence struct {
			State      string `json:"state"`
			ValidUntil string `json:"validUntil"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(section, &items); err != nil {
		return nil, ErrIntegrity
	}
	var ends []time.Time
	for _, item := range items {
		if item.Evidence.State != "" && item.Evidence.State != "active" {
			continue
		}
		end, err := time.Parse(time.RFC3339, item.Evidence.ValidUntil)
		if err != nil {
			return nil, ErrIntegrity
		}
		ends = append(ends, end.UTC())
	}
	return ends, nil
}

// strictRuleEnds is activeRuleEnds, except that an unparseable date is an
// error instead of being left out.
func strictRuleEnds(entries []Entry) ([]time.Time, error) {
	var ends []time.Time
	for _, entry := range entries {
		var shape struct {
			Evidence struct {
				State      string `json:"state"`
				ValidUntil string `json:"validUntil"`
			} `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return nil, ErrIntegrity
		}
		if shape.Evidence.State != "active" {
			continue
		}
		end, err := time.Parse(time.RFC3339, shape.Evidence.ValidUntil)
		if err != nil {
			return nil, ErrIntegrity
		}
		ends = append(ends, end.UTC())
	}
	return ends, nil
}

// EmbeddedKnowledgeAge is the end dates of the embedded pack's active rules.
func EmbeddedKnowledgeAge() ([]knowledgeage.Source, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	return []knowledgeage.Source{{ID: "embedded", Expiries: activeRuleEnds(b.pack.Entries)}}, nil
}

// EmbeddedEvidenceAge is the end dates of all evidence the embedded pack
// carries: its active rules and its applicable line attestations, served-API
// lists and path policies, everything that makes an answer UNKNOWN or not
// current once it ends. Unlike EmbeddedKnowledgeAge it fails on a date it
// cannot parse, so a release gate built on it fails closed.
func EmbeddedEvidenceAge() ([]knowledgeage.Source, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	ends, err := strictRuleEnds(b.pack.Entries)
	if err != nil {
		return nil, err
	}
	for _, section := range []json.RawMessage{b.pack.LineAttestations, b.pack.ServedAPIs, b.pack.PathPolicies} {
		more, err := sectionEnds(section)
		if err != nil {
			return nil, err
		}
		ends = append(ends, more...)
	}
	return []knowledgeage.Source{{ID: "embedded", Expiries: ends}}, nil
}

// KnowledgeAge is the end dates of the active rules of the knowledge this
// snapshot serves: the embedded pack, or each opened envelope of a store
// (an envelope shared by several projects is listed once).
func (k *ScanKnowledge) KnowledgeAge() []knowledgeage.Source {
	if k.selected == nil {
		return []knowledgeage.Source{{ID: "embedded", Expiries: activeRuleEnds(k.b.pack.Entries)}}
	}
	seen := map[string]bool{}
	var out []knowledgeage.Source
	for _, b := range k.selected {
		if seen[b.packDigest] {
			continue
		}
		seen[b.packDigest] = true
		out = append(out, knowledgeage.Source{ID: b.packDigest, Expiries: activeRuleEnds(b.pack.Entries)})
	}
	return knowledgeage.Merge(out)
}

// KnowledgeAge is the end dates of the active rules of the envelope.
func (b ExternalBundle) KnowledgeAge() knowledgeage.Source {
	return knowledgeage.Source{ID: b.bundleDigest, Expiries: activeRuleEnds(b.pack.Entries)}
}
