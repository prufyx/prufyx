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

// EmbeddedKnowledgeAge is the end dates of the embedded pack's active rules.
func EmbeddedKnowledgeAge() ([]knowledgeage.Source, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	return []knowledgeage.Source{{ID: "embedded", Expiries: activeRuleEnds(b.pack.Entries)}}, nil
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
