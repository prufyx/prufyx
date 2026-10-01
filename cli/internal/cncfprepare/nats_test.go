// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"testing"
)

func TestPrepareNATSLiteralSelectedNames(t *testing.T) {
	tests := []struct {
		name, raw, wantReason string
		wantSpace             bool
	}{
		{"server name with space", `{"server_name":"edge node"}`, string(ReasonNATSNameSpacePresent), true},
		{"cluster name without space", `{"cluster":{"name":"edge"}}`, string(ReasonNATSNameSpaceAbsent), false},
		{"gateway name with space", `{"gateway":{"name":"edge gateway"}}`, string(ReasonNATSNameSpacePresent), true},
		{"all supported names no space", `{"server_name":"edge","cluster":{"name":"cluster"},"gateway":{"name":"gateway"}}`, string(ReasonNATSNameSpaceAbsent), false},
		{"one supported name has space", `{"server_name":"edge","cluster":{"name":"cluster member"}}`, string(ReasonNATSNameSpacePresent), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareNATS([]byte(tc.raw), NATSFrom, NATSTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != Reason(tc.wantReason) {
				t.Fatalf("PrepareNATS() = %#v, %v", prepared, err)
			}
			if got, state := natsCanonicalFact(t, prepared.CanonicalInputJSON); state != "declared" || got != tc.wantSpace {
				t.Fatalf("fact=(%t,%q), want=(%t,declared)", got, state, tc.wantSpace)
			}
		})
	}
}

func TestPrepareNATSUnknownForUnresolvedSelectedConfiguration(t *testing.T) {
	tests := []string{
		`{}`,
		`{"server_name":"$NAME"}`,
		`{"include":"other.conf","server_name":"edge"}`,
		`{"cluster.name":"edge"}`,
		`{"server_name":"edge","cluster":{"name.child":"cluster"}}`,
		`{"server_name":"edge","gateway":{"name.child":"gateway"}}`,
		`{"gateway":{"name":1}}`,
		`{"cluster":[]}`,
		`{"server_name":{"child":"edge"}}`,
		`{"server\u005fname":"edge"}`,
		`{"server_name":"edge\u0020west"}`,
		`{"server_name":"edge\/west"}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			prepared, err := PrepareNATS([]byte(raw), NATSFrom, NATSTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonNATSConfigUnsupported {
				t.Fatalf("PrepareNATS(%s) = %#v, %v", raw, prepared, err)
			}
			if _, state := natsCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
				t.Fatalf("fact state=%q, want unsupported", state)
			}
		})
	}
	for _, raw := range []string{
		`{"server_name":"edge","server_name":"other"}`,
		`{"server_name":"edge","Server_Name":"other"}`,
		`{"cluster":{"name":"edge","NAME":"other"}}`,
	} {
		if _, err := PrepareNATS([]byte(raw), NATSFrom, NATSTo); err == nil {
			t.Fatalf("duplicate or case-colliding selected key was accepted: %s", raw)
		}
	}
}

func natsCanonicalFact(t *testing.T, raw []byte) (bool, string) {
	t.Helper()
	var document struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, component := range document.Proposed.Components {
		for _, fact := range component.Facts {
			if fact.ID == NATSFact {
				if fact.BoolValue == nil {
					return false, fact.State
				}
				return *fact.BoolValue, fact.State
			}
		}
	}
	t.Fatalf("missing %s", NATSFact)
	return false, ""
}
