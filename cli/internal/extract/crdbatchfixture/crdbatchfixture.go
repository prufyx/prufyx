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
)

// Without returns pack without the batch, rendered like the shipped pack. A
// pack that does not hold the batch is returned unchanged. The batch moved
// the pack from the ranged schema to the line attestation schema; Without
// moves it back and refuses a pack that holds anything else that would need
// a schema above the ranged one (another line attestation, a set rule
// outside the batch, another section), so it never yields a pack its loader
// would refuse for a reason the batch did not bring.
func Without(pack []byte) ([]byte, error) {
	held, err := crdbatchids.Holds(pack)
	if err != nil || !held {
		return pack, err
	}
	p, err := extractpack.ParsePack(pack)
	if err != nil {
		return nil, err
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
		if batch[e.Rule.ID] {
			continue
		}
		if e.Rule.Operator == "forbid_set_member" {
			return nil, fmt.Errorf("crdbatchfixture: set rule %s is not of the batch", e.Rule.ID)
		}
		kept = append(kept, raw)
	}
	var atts []struct {
		Component  string `json:"component"`
		Line       string `json:"line"`
		FactFamily string `json:"factFamily"`
	}
	if err := json.Unmarshal(p.Members["lineAttestations"], &atts); err != nil {
		return nil, err
	}
	for _, a := range atts {
		if a.FactFamily != crdbatchids.FactFamily {
			return nil, fmt.Errorf("crdbatchfixture: line attestation %s %s %s is not of the batch", a.Component, a.Line, a.FactFamily)
		}
	}
	p.Entries = kept
	delete(p.Members, "lineAttestations")
	p.Members["schema"] = json.RawMessage(`"` + schemaRanged + `"`)
	return p.Render()
}
