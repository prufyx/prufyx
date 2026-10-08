// SPDX-License-Identifier: AGPL-3.0-only

// Package supersedefixture holds, for tests only, the 25 reviewed Kubernetes
// API-removal rules the served-API supersede replaces, and rebuilds the pack
// as it was before the change. Tests of the supersede machinery need reviewed
// rules to replace; once the shipped pack holds only mechanical rules this is
// where they come from. Tests that merely name a rule of the pack use
// supersedeids instead. No production code imports this package.
package supersedefixture

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

//go:embed reviewed-kubernetes-entries.json
var reviewedEntries []byte

// Reviewed returns pack as it was before the served-API supersede: its
// mechanical served-API rules removed and the 25 reviewed Kubernetes rules
// added back, rendered like the shipped pack. A pack that already holds the
// reviewed rules is returned unchanged.
func Reviewed(pack []byte) ([]byte, error) {
	superseded, err := supersedeids.Generation(pack)
	if err != nil {
		return nil, err
	}
	if !superseded {
		return pack, nil
	}
	p, err := extractpack.ParsePack(pack)
	if err != nil {
		return nil, err
	}
	var old []json.RawMessage
	if err := json.Unmarshal(reviewedEntries, &old); err != nil {
		return nil, err
	}
	var kept []json.RawMessage
	for _, raw := range p.Entries {
		id, err := ruleID(raw)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(id, supersedeids.MechanicalPrefix) {
			kept = append(kept, raw)
		}
	}
	p.Entries = append(kept, old...)
	return p.Render()
}

// ReviewedEntries returns the 25 reviewed rule entries as shipped before the
// supersede.
func ReviewedEntries() []json.RawMessage {
	var old []json.RawMessage
	if err := json.Unmarshal(reviewedEntries, &old); err != nil {
		panic("supersedefixture: " + err.Error())
	}
	return old
}

func ruleID(entry json.RawMessage) (string, error) {
	var e struct {
		Rule struct {
			ID string `json:"id"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(entry, &e); err != nil {
		return "", err
	}
	return e.Rule.ID, nil
}
