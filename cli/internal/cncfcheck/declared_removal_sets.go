// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
)

// The declared-removal set facts are caller-supplied sets of the command-line
// flags one binary is started with, read by rules that forbid flags a release
// removed. No reviewed list says which other flags the same release stopped
// accepting, so such a set is never the complete answer: on both sides it is
// handed to the engine as not complete, whatever the caller declared. A
// listed forbidden member still BLOCKS; every other result is UNKNOWN, never
// PASS. Members are the long flag names without leading dashes, in lower
// case; a set with an upper-case member is refused (ErrMemberSpelling).
//
// The guard is keyed by the fact id, not by a rule: every rule that reads one
// of these facts is held to it, including a rule of a newer external bundle.
// A fact listed here must be registered as a set in the same change.
const (
	factCRIOFlags           = "component.crio.crio_cli_flags_set"
	factEtcdServerFlags     = "component.etcd.server_cli_flags_set"
	factVitessVTGateFlags   = "component.vitess.vtgate_cli_flags_set"
	factVitessVTTabletFlags = "component.vitess.vttablet_cli_flags_set"
)

// declaredRemovalGuardedFacts are the declared-removal set facts.
var declaredRemovalGuardedFacts = map[string]bool{factCRIOFlags: true, factEtcdServerFlags: true, factVitessVTGateFlags: true, factVitessVTTabletFlags: true}

const declaredRemovalNextAction = "a declared flag set of this kind is never read as the complete list of flags: a listed removed flag blocks the upgrade, and without one the rule stays UNKNOWN: retain UNKNOWN"

// guardDeclaredRemovalSets returns the input to evaluate and whether any
// complete set was handed to the engine as not complete. Inputs that need no
// change come back byte for byte. Like guardRelnotesSets it decodes the
// document, so an escaped fact id or member is read as the engine reads it,
// and the caller must have had these bytes accepted by the engine first
// (parseGuarded). A document it cannot read is refused, never passed on.
func guardDeclaredRemovalSets(raw []byte) ([]byte, bool, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, false, ErrInvalid
	}
	downgraded := false
	for _, side := range []string{"current", "proposed"} {
		sideDoc, _ := doc[side].(map[string]any)
		components, _ := sideDoc["components"].([]any)
		for _, rawComponent := range components {
			component, _ := rawComponent.(map[string]any)
			facts, _ := component["facts"].([]any)
			for _, rawFact := range facts {
				fact, _ := rawFact.(map[string]any)
				id, _ := fact["id"].(string)
				if !declaredRemovalGuardedFacts[id] {
					continue
				}
				value, ok := fact["setValue"].(map[string]any)
				if !ok {
					continue // an undeclared fact carries no set
				}
				members, _ := value["members"].([]any)
				for _, member := range members {
					name, ok := member.(string)
					if !ok {
						return nil, false, ErrInvalid
					}
					if name != strings.ToLower(name) {
						return nil, false, ErrMemberSpelling
					}
				}
				if complete, ok := value["complete"].(bool); !ok || complete {
					value["complete"] = false
					downgraded = true
				}
			}
		}
	}
	if !downgraded {
		return raw, false, nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return nil, false, ErrInvalid
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), true, nil
}
