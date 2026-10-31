// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"slices"
	"strings"
)

// The release-note removal rules read caller-supplied sets of flags and config
// keys. Two properties of those sets are held here, before the engine sees
// the input, and both can only turn a result into an error or UNKNOWN, never
// into a PASS:
//
//   - Spelling. A member is compared byte for byte, so a case variant of a
//     forbidden name would never match. The names these facts hold are
//     lower-case (Go flags, YAML keys, falco long options); falco also has
//     single-letter options that differ by case (-m, -M), which stay exact.
//     A set with any other upper-case member is not a set of real names and
//     is refused (ErrInvalid) instead of being compared.
//   - Unreviewed siblings. A release that removes one flag with a rule often
//     removes others that no rule covers. A complete declared set that holds
//     such a sibling cannot be PASS for the release-note rule: the set is
//     handed to the engine as not complete, so the rule is UNKNOWN (a
//     forbidden member still BLOCKS).
const (
	factCortexFlags    = "component.cortex.cli_flags_set"
	factFalcoFlags     = "component.falco.cli_flags_set"
	factFalcoConfigKey = "component.falco.config_keys_set"
	factThanosFlags    = "component.thanos.cli_flags_set"
)

// relnotesGuardedFacts are the set facts of the release-note rules.
var relnotesGuardedFacts = map[string]bool{factCortexFlags: true, factFalcoFlags: true, factFalcoConfigKey: true, factThanosFlags: true}

// relnotesUnreviewedRemovals lists, per set fact, members removed by a
// release that a shipped release-note rule crosses while no shipped rule
// covers them (ascending, as every member list). Sources: the cortex 1.9.0
// CHANGELOG (the -cluster.* flags are the Alertmanager's deprecated ones, the
// -limits.* and postings-compression options are listed on their own lines)
// and falco.yaml of 0.36.2, which holds metadata_download, against 0.37.0,
// which does not. The falco 0.37.0 command-line removals (-u/--userspace,
// -k/-K, --k8s-api, --k8s-api-cert, --k8s-node) are not listed: no shipped
// rule reads falco's flag set across 0.37.0, and the one that reads it
// (mesos-api) is not decided for a hop that goes beyond its reviewed horizon.
var relnotesUnreviewedRemovals = map[string][]string{
	factCortexFlags: {
		"blocks-storage.bucket-store.index-cache.postings-compression-enabled",
		"cluster.advertise-address",
		"cluster.listen-address",
		"cluster.peer",
		"cluster.peer-timeout",
		"limits.per-user-override-config",
		"limits.per-user-override-period",
	},
	factFalcoConfigKey: {
		"metadata_download.chunk_wait_us",
		"metadata_download.max_mb",
		"metadata_download.watch_freq_sec",
	},
}

const relnotesUnreviewedNextAction = "a declared set holds flags or keys that the same release removed and no reviewed rule covers; the rule stays UNKNOWN for them: remove them, or retain UNKNOWN"

// guardRelnotesSets returns the input to evaluate and whether any complete
// set was handed to the engine as not complete. Inputs that need no change
// come back byte for byte. It always decodes: a fact id may be spelled with
// JSON escapes, which the engine's parser unescapes. When the input is
// rewritten, the engine-level input digest inside the report is that of the
// rewritten document; the file digest stays that of the original bytes, and
// Replay takes the same deterministic path. The caller must have had the
// original bytes accepted by the engine first (parseGuarded), because the
// re-encoding does not keep what the engine's gate refuses (duplicate keys,
// trailing data, invalid UTF-8).
func guardRelnotesSets(raw []byte) ([]byte, bool, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return raw, false, nil // the engine's own parser reports it
	}
	changed, downgraded := false, false
	for _, side := range []string{"current", "proposed"} {
		sideDoc, _ := doc[side].(map[string]any)
		components, _ := sideDoc["components"].([]any)
		for _, rawComponent := range components {
			component, _ := rawComponent.(map[string]any)
			facts, _ := component["facts"].([]any)
			for _, rawFact := range facts {
				fact, _ := rawFact.(map[string]any)
				id, _ := fact["id"].(string)
				if !relnotesGuardedFacts[id] {
					continue
				}
				value, _ := fact["setValue"].(map[string]any)
				members, _ := value["members"].([]any)
				names := make([]string, 0, len(members))
				for _, member := range members {
					name, ok := member.(string)
					if !ok {
						return raw, false, nil // the engine's own parser reports it
					}
					if !relnotesSpelling(id, name) {
						return nil, false, ErrInvalid
					}
					names = append(names, name)
				}
				if complete, _ := value["complete"].(bool); complete && side == "current" && unreviewedSibling(id, names) {
					value["complete"] = false
					changed, downgraded = true, true
				}
			}
		}
	}
	if !changed {
		return raw, false, nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return nil, false, ErrInvalid
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), downgraded, nil
}

func relnotesSpelling(factID, name string) bool {
	if name == strings.ToLower(name) {
		return true
	}
	return factID == factFalcoFlags && len(name) == 1
}

func unreviewedSibling(factID string, names []string) bool {
	for _, name := range names {
		if slices.Contains(relnotesUnreviewedRemovals[factID], name) {
			return true
		}
	}
	return false
}

// parseGuarded parses raw with the engine's own gate first, so a rewrite of a
// guarded set never makes an input valid that the engine refuses, then parses
// the guarded document. downgraded reports whether a set was rewritten.
func parseGuarded(raw []byte, registry constraintengine.Registry) (input constraintengine.Input, downgraded bool, err error) {
	input, err = constraintengine.ParseInput(raw, registry)
	if err != nil {
		return constraintengine.Input{}, false, ErrInvalid
	}
	guarded, downgraded, err := guardRelnotesSets(raw)
	if err != nil {
		return constraintengine.Input{}, false, ErrInvalid
	}
	if !downgraded {
		return input, false, nil
	}
	input, err = constraintengine.ParseInput(guarded, registry)
	if err != nil {
		return constraintengine.Input{}, false, ErrInvalid
	}
	return input, true, nil
}
