// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"testing"
)

func TestPrepareCubeFSMetaNode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, phase, state, phaseState, guardState string
		guard                                           *bool
		wantErr                                         bool
	}{
		{"zero-with-unrelated-native-fields", `{"role":"metanode","listen":"17210","masterAddr":["private.example:17010"],"raftSyncSnapFormatVersion":0}`, CubeFSPhaseMetaNodeUpgrade, StatePrepared, "declared", "declared", boolPointer(true), false},
		{"one", `{"role":"metanode","raftSyncSnapFormatVersion":1}`, CubeFSPhaseMetaNodeUpgrade, StatePrepared, "declared", "declared", boolPointer(false), false},
		{"absent-target-default", `{"role":"metanode","listen":"17210"}`, CubeFSPhaseMetaNodeUpgrade, StatePrepared, "declared", "declared", boolPointer(false), false},
		{"missing-phase", `{"role":"metanode","raftSyncSnapFormatVersion":0}`, "", StatePrepared, "unsupported", "declared", boolPointer(true), false},
		{"other-phase", `{"role":"metanode","raftSyncSnapFormatVersion":0}`, "client-upgrade", StatePrepared, "unsupported", "declared", boolPointer(true), false},
		{"wrong-role", `{"role":"master","raftSyncSnapFormatVersion":0}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"missing-role", `{"raftSyncSnapFormatVersion":0}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"string-zero-is-unsupported", `{"role":"metanode","raftSyncSnapFormatVersion":"0"}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"null-is-unsupported", `{"role":"metanode","raftSyncSnapFormatVersion":null}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"outside-qualified-range", `{"role":"metanode","raftSyncSnapFormatVersion":2}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"fractional-number", `{"role":"metanode","raftSyncSnapFormatVersion":1.0}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"case-ambiguous-role", `{"role":"metanode","Role":"metanode","raftSyncSnapFormatVersion":0}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"duplicate-guard", `{"role":"metanode","raftSyncSnapFormatVersion":0,"raftSyncSnapFormatVersion":1}`, CubeFSPhaseMetaNodeUpgrade, StateUnknown, "declared", "unsupported", nil, false},
		{"malformed", `{"role":`, CubeFSPhaseMetaNodeUpgrade, "", "", "", nil, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := PrepareCubeFSMetaNode([]byte(tt.raw), CubeFSFrom, CubeFSTo, tt.phase)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got.State != tt.state || got.SourceDigest != digestBytes([]byte(tt.raw)) || got.InputDigest != digestBytes(got.CanonicalInputJSON) {
				t.Fatalf("PrepareCubeFSMetaNode() = %#v, %v", got, err)
			}
			var document struct {
				Proposed struct {
					Components []struct {
						Facts []inputFact `json:"facts"`
					} `json:"components"`
				} `json:"proposed"`
			}
			if json.Unmarshal(got.CanonicalInputJSON, &document) != nil || len(document.Proposed.Components) != 1 || len(document.Proposed.Components[0].Facts) != 2 {
				t.Fatalf("unexpected canonical input: %s", got.CanonicalInputJSON)
			}
			facts := document.Proposed.Components[0].Facts
			if facts[0].ID != CubeFSUpgradePhaseFact || facts[0].State != tt.phaseState || facts[1].ID != CubeFSRaftSnapshotZeroFact || facts[1].State != tt.guardState {
				t.Fatalf("unexpected facts: %#v", facts)
			}
			if tt.guard == nil {
				if facts[1].BoolValue != nil {
					t.Fatalf("unsupported guard exposed value: %#v", facts[1])
				}
			} else if facts[1].BoolValue == nil || *facts[1].BoolValue != *tt.guard {
				t.Fatalf("guard = %#v, want %t", facts[1].BoolValue, *tt.guard)
			}
			if string(got.CanonicalInputJSON) == "" || containsPrivateCubeFSValue(string(got.CanonicalInputJSON)) {
				t.Fatalf("canonical input leaked unrelated config: %s", got.CanonicalInputJSON)
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }

func containsPrivateCubeFSValue(value string) bool {
	return value != "" && (contains(value, "private.example") || contains(value, "17210"))
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
