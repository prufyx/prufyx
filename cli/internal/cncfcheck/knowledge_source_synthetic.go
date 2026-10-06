// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// This file is compiled only with the prufyx_synthetic_knowledge build tag,
// which no release build sets. It lets end-to-end tests run the real command
// routes against synthetic rules and facts that are never published.

var syntheticKnowledge struct {
	sync.Mutex
	pack        []byte
	definitions []constraintengine.FactDefinition
}

func packagedRulePack() ([]byte, error) {
	syntheticKnowledge.Lock()
	defer syntheticKnowledge.Unlock()
	if syntheticKnowledge.pack != nil {
		return append([]byte(nil), syntheticKnowledge.pack...), nil
	}
	return packagedFiles.ReadFile("data/rules.json")
}

func additionalDefinitions() []constraintengine.FactDefinition {
	syntheticKnowledge.Lock()
	defer syntheticKnowledge.Unlock()
	return append([]constraintengine.FactDefinition(nil), syntheticKnowledge.definitions...)
}

// UseSyntheticKnowledge adds definitions to the compiled registry and entries
// to the embedded pack, under revision "synthetic-test-only", until the
// returned restore function runs. The resulting knowledge must pass every
// check the embedded knowledge passes.
func UseSyntheticKnowledge(definitions []constraintengine.FactDefinition, entries []Entry) (func(), error) {
	return UseSyntheticRecords(definitions, entries, SyntheticRecords{})
}

// SyntheticRecords are the optional record sections of a synthetic pack, as
// raw JSON documents (line attestations, upgrade-path policies, served-API
// lists). Each is admitted by exactly the checks the embedded pack's
// sections pass; a section that fails them makes UseSyntheticRecords fail.
type SyntheticRecords struct {
	LineAttestations json.RawMessage
	PathPolicies     json.RawMessage
	ServedAPIs       json.RawMessage
}

// UseSyntheticRecords is UseSyntheticKnowledge with record sections added to
// the pack, so a test can run the real loader, the real scan and the real
// pack schema level over knowledge that is never published.
func UseSyntheticRecords(definitions []constraintengine.FactDefinition, entries []Entry, records SyntheticRecords) (func(), error) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		return nil, err
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		return nil, err
	}
	pack.Entries = append(pack.Entries, entries...)
	pack.LineAttestations, pack.PathPolicies, pack.ServedAPIs = records.LineAttestations, records.PathPolicies, records.ServedAPIs
	ruleIDs := make([]string, len(pack.Entries))
	for index, entry := range pack.Entries {
		var shape struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(entry.Rule, &shape); err != nil {
			return nil, ErrInvalid
		}
		ruleIDs[index] = shape.ID
	}
	sort.Sort(entriesByRuleID{pack.Entries, ruleIDs})
	registry, err := constraintengine.NewCompiledRegistry(append(packagedDefinitions(), definitions...))
	if err != nil {
		return nil, err
	}
	rules := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		rules = append(rules, entry.Rule)
	}
	schema, err := requiredPackSchema(pack)
	if err != nil {
		return nil, err
	}
	pack.Schema = schema
	pack.Revision, pack.RegistryDigest = "synthetic-test-only", registry.Digest()
	encoded, err := json.Marshal(pack)
	if err != nil {
		return nil, err
	}
	restore := func() {
		syntheticKnowledge.Lock()
		syntheticKnowledge.pack, syntheticKnowledge.definitions = nil, nil
		syntheticKnowledge.Unlock()
	}
	syntheticKnowledge.Lock()
	syntheticKnowledge.pack, syntheticKnowledge.definitions = encoded, append([]constraintengine.FactDefinition(nil), definitions...)
	syntheticKnowledge.Unlock()
	if _, err := load(); err != nil {
		restore()
		return nil, err
	}
	return restore, nil
}

type entriesByRuleID struct {
	entries []Entry
	ids     []string
}

func (s entriesByRuleID) Len() int           { return len(s.entries) }
func (s entriesByRuleID) Less(i, j int) bool { return s.ids[i] < s.ids[j] }
func (s entriesByRuleID) Swap(i, j int) {
	s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
	s.ids[i], s.ids[j] = s.ids[j], s.ids[i]
}
