// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	CubeFSComponent             = "pkg:github/cubefs/cubefs"
	CubeFSUpgradePhaseFact      = "component.cubefs.metanode_upgrade_phase"
	CubeFSRaftSnapshotZeroFact  = "component.cubefs.raft_sync_snapshot_format_zero"
	CubeFSPhaseMetaNodeUpgrade  = "metanode-upgrade"
	CubeFSFrom                  = "3.2.1"
	CubeFSTo                    = "3.3.2"
	cubeFSRoleKey               = "role"
	cubeFSRaftSnapshotFormatKey = "raftSyncSnapFormatVersion"
)

const (
	ReasonCubeFSMetaNodeGuardAbsent Reason = "CUBEFS_METANODE_RAFT_SNAPSHOT_GUARD_ABSENT"
	ReasonCubeFSMetaNodeGuardZero   Reason = "CUBEFS_METANODE_RAFT_SNAPSHOT_GUARD_ZERO"
	ReasonCubeFSMetaNodeGuardOne    Reason = "CUBEFS_METANODE_RAFT_SNAPSHOT_GUARD_ONE"
	ReasonCubeFSInputUnsupported    Reason = "CUBEFS_METANODE_CONFIG_SHAPE_UNSUPPORTED"
	ReasonCubeFSInputAmbiguous      Reason = "CUBEFS_METANODE_CONFIG_AMBIGUOUS"
)

// PrepareCubeFSMetaNode derives one planned-phase declaration and one target
// snapshot-format guard from a caller-supplied CubeFS MetaNode JSON config.
// It does not inspect peers, run CubeFS, or change the supplied file.
func PrepareCubeFSMetaNode(raw []byte, from, to, phase string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, ambiguous, err := decodeCubeFSJSON(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	phaseFact := inputFact{ID: CubeFSUpgradePhaseFact, State: "unsupported"}
	if phase == CubeFSPhaseMetaNodeUpgrade {
		value := true
		phaseFact = inputFact{ID: CubeFSUpgradePhaseFact, State: "declared", BoolValue: &value}
	}
	guardFact := inputFact{ID: CubeFSRaftSnapshotZeroFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonCubeFSInputUnsupported
	root, rootOK := value.(map[string]any)
	if ambiguous {
		reason = ReasonCubeFSInputAmbiguous
	} else if rootOK {
		role, roleOK := root[cubeFSRoleKey].(string)
		if roleOK && role == "metanode" {
			if rawGuard, present := root[cubeFSRaftSnapshotFormatKey]; !present {
				zero := false
				guardFact = inputFact{ID: CubeFSRaftSnapshotZeroFact, State: "declared", BoolValue: &zero}
				state, reason = StatePrepared, ReasonCubeFSMetaNodeGuardAbsent
			} else if number, ok := rawGuard.(json.Number); ok {
				parsed, parseErr := number.Int64()
				if parseErr == nil && (parsed == 0 || parsed == 1) {
					zero := parsed == 0
					guardFact = inputFact{ID: CubeFSRaftSnapshotZeroFact, State: "declared", BoolValue: &zero}
					state = StatePrepared
					if zero {
						reason = ReasonCubeFSMetaNodeGuardZero
					} else {
						reason = ReasonCubeFSMetaNodeGuardOne
					}
				}
			}
		}
	}
	canonical, err := marshalComponentInput(CubeFSComponent, from, to, []inputFact{phaseFact, guardFact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"UPGRADE_PHASE_IS_CALLER_DECLARED_NOT_RUNTIME_OBSERVED",
			"PEER_VERSIONS_ROLLOUT_COMPLETION_AND_RESTARTS_NOT_EVALUATED",
			"CLIENT_ORDER_MOUNTS_AND_DATA_SAFETY_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// decodeCubeFSJSON retains the package JSON bounds while classifying duplicate
// or case-fold-colliding object members as ambiguous. A valid but ambiguous
// config produces UNKNOWN instead of allowing one duplicate value to win.
func decodeCubeFSJSON(raw []byte) (any, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, ambiguous, err := decodeCubeFSValue(decoder, 0)
	if err != nil {
		return nil, false, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, false, ErrInvalid
	}
	return value, ambiguous, nil
}

func decodeCubeFSValue(decoder *json.Decoder, depth int) (any, bool, error) {
	if depth > maxJSONDepth {
		return nil, false, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, false, err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			object := make(map[string]any)
			keys := make(map[string]bool)
			ambiguous := false
			for members := 0; decoder.More(); members++ {
				if members >= maxObjectMembers {
					return nil, false, ErrInvalid
				}
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || key == "" {
					return nil, false, ErrInvalid
				}
				folded := strings.ToLower(key)
				if keys[folded] {
					ambiguous = true
				}
				keys[folded] = true
				item, itemAmbiguous, err := decodeCubeFSValue(decoder, depth+1)
				if err != nil {
					return nil, false, err
				}
				ambiguous = ambiguous || itemAmbiguous
				if _, exists := object[key]; !exists {
					object[key] = item
				}
			}
			if _, err := decoder.Token(); err != nil {
				return nil, false, err
			}
			return object, ambiguous, nil
		case '[':
			array := make([]any, 0)
			ambiguous := false
			for decoder.More() {
				if len(array) >= maxArrayItems {
					return nil, false, ErrInvalid
				}
				item, itemAmbiguous, err := decodeCubeFSValue(decoder, depth+1)
				if err != nil {
					return nil, false, err
				}
				array = append(array, item)
				ambiguous = ambiguous || itemAmbiguous
			}
			if _, err := decoder.Token(); err != nil {
				return nil, false, err
			}
			return array, ambiguous, nil
		default:
			return nil, false, ErrInvalid
		}
	default:
		return token, false, nil
	}
}
