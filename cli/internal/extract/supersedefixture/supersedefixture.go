// SPDX-License-Identifier: AGPL-3.0-only

// Package supersedefixture holds, for tests only, the 25 reviewed Kubernetes
// API-removal rules the served-API supersede replaces, and rebuilds the pack
// as it was before the change. Tests of the supersede machinery need reviewed
// rules to replace; once the shipped pack holds only mechanical rules this is
// where they come from. Tests that merely name a rule of the pack use
// supersedeids instead. While the shipped pack holds the reviewed rules a test
// checks that the 25 entries here are byte-equal to the shipped ones. No
// production code imports this package.
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
// reviewed rules is returned unchanged. The 25 rules are appended after the
// kept ones: in the pack as it was they sat at positions 94 to 119, so the
// rebuilt pack is the same rules, not the same bytes, as the pack before the
// supersede (the tests that use it do not depend on the position).
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
	if err := dropRuleAttestations(p); err != nil {
		return nil, err
	}
	// The served-API lists came after the supersede: the pack as it was
	// has none, and is at the line attestation schema again.
	if _, ok := p.Members["servedAPIs"]; ok {
		delete(p.Members, "servedAPIs")
		p.Members["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha4"`)
	}
	return p.Render()
}

// dropRuleAttestations removes the line attestations that list rules: they
// name mechanical rules the rebuilt pack no longer holds. The empty-list
// attestations (lines with no removal) stay, as they sat in the pack before.
func dropRuleAttestations(p *extractpack.Pack) error {
	raw, ok := p.Members["lineAttestations"]
	if !ok {
		return nil
	}
	var atts []json.RawMessage
	if err := json.Unmarshal(raw, &atts); err != nil {
		return err
	}
	var kept []json.RawMessage
	for _, a := range atts {
		var v struct {
			RuleIDs []string `json:"ruleIds"`
		}
		if err := json.Unmarshal(a, &v); err != nil {
			return err
		}
		if len(v.RuleIDs) == 0 {
			kept = append(kept, a)
		}
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	p.Members["lineAttestations"] = out
	return nil
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
