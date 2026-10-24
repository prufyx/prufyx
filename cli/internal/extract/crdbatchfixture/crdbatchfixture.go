// SPDX-License-Identifier: AGPL-3.0-only

// Package crdbatchfixture rebuilds, for tests only, the CNCF pack as it was
// before the custom-resource batch crdbatchids states: the batch's rules and
// line attestations removed, at the ranged pack schema. Tests whose fixtures
// are the shipped knowledge but whose subject is not the batch (the
// knowledge gate's base and head trees, for example) build on it, so that a
// schema step or a first attested update they model is the one they state.
// The shipped batch itself is tested on the shipped bytes. No production
// code imports this package.
package crdbatchfixture

import (
	"encoding/json"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

const (
	schemaRanged   = "prufyx.io/cncf-source-rule-pack/v1alpha2"
	schemaAttested = "prufyx.io/cncf-source-rule-pack/v1alpha4"
	// membersServed is the pack member of the served-API lists.
	membersServed = "servedAPIs"
	// membersPolicies is the pack member of the upgrade-path policies.
	membersPolicies = "pathPolicies"
)

// Without returns pack without the batch and, when the pack holds the batch,
// without the mechanical custom-resource version-removal rules the factory
// adds beside it (crdbatchids.Foreign), rendered like the shipped pack. A
// pack that does not hold the batch is returned unchanged. The batch moved
// the pack from the ranged schema to the line attestation schema; Without
// moves it back unless line attestations of other facts remain, drops the
// served-API list and path policy members (not part of the batch), and refuses a
// pack that holds anything else that would need a schema above the ranged
// one (a set rule outside the batch, another section), so it never yields a
// pack its loader would refuse for a reason the batch did not bring.
func Without(pack []byte) ([]byte, error) {
	held, err := crdbatchids.Holds(pack)
	if err != nil || !held {
		return pack, err
	}
	p, err := extractpack.ParsePack(pack)
	if err != nil {
		return nil, err
	}
	// The served-API lists are not part of the batch: the pack the tests
	// model has none, and without them the pack is again at the line
	// attestation schema.
	// The same holds for the upgrade-path policies.
	for _, member := range []string{membersServed, membersPolicies} {
		if _, ok := p.Members[member]; ok {
			delete(p.Members, member)
			p.Members["schema"] = json.RawMessage(`"` + schemaAttested + `"`)
		}
	}
	var schema string
	if err := json.Unmarshal(p.Members["schema"], &schema); err != nil || schema != schemaAttested {
		return nil, fmt.Errorf("crdbatchfixture: pack schema %q, want %s", schema, schemaAttested)
	}
	for member := range p.Members {
		switch member {
		case "schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "lineAttestations":
		default:
			return nil, fmt.Errorf("crdbatchfixture: pack member %s is not handled", member)
		}
	}
	batch := map[string]bool{}
	for _, id := range crdbatchids.IDs() {
		batch[id] = true
	}
	// The mechanical custom-resource rules of other projects (the factory's)
	// are set rules too: the pack the tests model, before the batch, has none.
	foreign := map[string]bool{}
	for _, id := range crdbatchids.ForeignIDs(pack) {
		foreign[id] = true
	}
	var kept []json.RawMessage
	for _, raw := range p.Entries {
		var e struct {
			Rule struct {
				ID       string `json:"id"`
				Operator string `json:"operator"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		if batch[e.Rule.ID] || foreign[e.Rule.ID] {
			continue
		}
		if e.Rule.Operator == "forbid_set_member" {
			return nil, fmt.Errorf("crdbatchfixture: set rule %s is not of the batch", e.Rule.ID)
		}
		kept = append(kept, raw)
	}
	var atts []json.RawMessage
	if err := json.Unmarshal(p.Members["lineAttestations"], &atts); err != nil {
		return nil, err
	}
	var keptAtts []json.RawMessage
	for _, raw := range atts {
		var a struct {
			FactFamily string `json:"factFamily"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		if a.FactFamily != crdbatchids.FactFamily {
			keptAtts = append(keptAtts, raw)
		}
	}
	p.Entries = kept
	if len(keptAtts) > 0 {
		// Attestations of other facts stay, and with them the schema that
		// admits them.
		out, err := json.Marshal(keptAtts)
		if err != nil {
			return nil, err
		}
		p.Members["lineAttestations"] = out
		return p.Render()
	}
	delete(p.Members, "lineAttestations")
	p.Members["schema"] = json.RawMessage(`"` + schemaRanged + `"`)
	return p.Render()
}

// WithoutForeign returns pack without the mechanical custom-resource
// version-removal rules of other projects (crdbatchids.ForeignIDs) and the
// quiet line attestations of the family that the factory states for the
// components of those rules, rendered like the shipped pack. Tests that pin
// figures over the reviewed pack use it to state them over the pack as it was
// reviewed. It drops every family line of those components, so a reviewed
// quiet line of such a component would leave the baseline too.
func WithoutForeign(pack []byte) ([]byte, error) {
	foreign := map[string]bool{}
	for _, id := range crdbatchids.ForeignIDs(pack) {
		foreign[id] = true
	}
	if len(foreign) == 0 {
		return pack, nil
	}
	components := crdbatchids.ForeignComponents(pack)
	p, err := extractpack.ParsePack(pack)
	if err != nil {
		return nil, err
	}
	var kept []json.RawMessage
	for _, raw := range p.Entries {
		var e struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		if !foreign[e.Rule.ID] {
			kept = append(kept, raw)
		}
	}
	p.Entries = kept
	if _, has := p.Members["lineAttestations"]; !has {
		return p.Render()
	}
	var atts []json.RawMessage
	if err := json.Unmarshal(p.Members["lineAttestations"], &atts); err != nil {
		return nil, err
	}
	var keptAtts []json.RawMessage
	for _, raw := range atts {
		var a struct {
			Component  string `json:"component"`
			FactFamily string `json:"factFamily"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		if a.FactFamily == crdbatchids.FactFamily && components[a.Component] {
			continue
		}
		keptAtts = append(keptAtts, raw)
	}
	out, err := json.Marshal(keptAtts)
	if err != nil {
		return nil, err
	}
	p.Members["lineAttestations"] = out
	return p.Render()
}
