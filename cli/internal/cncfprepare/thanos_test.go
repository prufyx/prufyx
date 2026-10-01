// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"testing"
)

func TestPrepareThanosLiteralReceiveAndStoreFlags(t *testing.T) {
	tests := []struct {
		name, raw, wantReason string
		wantPresent           bool
	}{
		{"receive removed flag", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--shipper.ignore-unequal-block-size"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"store removed flag true", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["store","--debug.advertise-compatibility-label=true"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"removed false spelling remains present", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--shipper.ignore-unequal-block-size=false"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"receive negative Boolean alias remains present", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--no-shipper.ignore-unequal-block-size"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"store negative Boolean alias remains present", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["store","--no-debug.advertise-compatibility-label"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"duplicate removed spelling remains present", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--shipper.ignore-unequal-block-size=","--shipper.ignore-unequal-block-size"]}`), string(ReasonThanosRemovedFlagPresent), true},
		{"receive literal absence with sidecar", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--log.level=info"]},{"name":"config-reloader","image":"example.invalid/reloader:v1"}`), string(ReasonThanosRemovedFlagAbsent), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareThanos([]byte(tc.raw), ThanosFrom, ThanosTo)
			if err != nil || prepared.State != StatePrepared || string(prepared.Reason) != tc.wantReason {
				t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
			}
			if got, state := thanosCanonicalFact(t, prepared.CanonicalInputJSON); state != "declared" || got != tc.wantPresent {
				t.Fatalf("fact=(%t,%q), want=(%t,declared)", got, state, tc.wantPresent)
			}
		})
	}
}

func TestPrepareThanosUnknownForAmbiguousOrUnsupportedWorkload(t *testing.T) {
	valid := `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--log.level=info"]}`
	tests := []struct{ name, raw string }{
		{"missing explicit command", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","args":["receive"]}`)},
		{"shell wrapper", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["sh","-c"],"args":["receive"]}`)},
		{"unproven binary alias", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["/bin/thanos"],"args":["receive"]}`)},
		{"wrong target image", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.41.0","command":["thanos"],"args":["receive"]}`)},
		{"unrelated image with matching tag", thanosWorkload(`{"name":"thanos","image":"docker.io/library/nginx:v0.42.0","command":["thanos"],"args":["receive"]}`)},
		{"environment expression", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--shipper.ignore-unequal-block-size=${VALUE}"]}`)},
		{"global flags before subcommand", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["--log.level=info","receive"]}`)},
		{"nonliteral argument", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive",1]}`)},
		{"argument delimiter", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--","--shipper.ignore-unequal-block-size"]}`)},
		{"Kingpin argument file expansion", thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","@private-args"]}`)},
		{"two thanos containers", thanosWorkload(valid + `,` + valid)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareThanos([]byte(tc.raw), ThanosFrom, ThanosTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonThanosWorkloadUnsupported {
				t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
			}
			if _, state := thanosCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
				t.Fatalf("fact state=%q, want unsupported", state)
			}
		})
	}
}

func TestPrepareThanosLatestTargetPairsHaveBlockedPassAndUnknownOutcomes(t *testing.T) {
	for _, from := range []string{"0.37.2", "0.38.0", "0.39.2", "0.40.1", "0.41.0"} {
		for _, tc := range []struct {
			name, container string
			state           State
			reason          Reason
		}{
			{"blocker", `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":["receive","--shipper.ignore-unequal-block-size"]}`, StatePrepared, ReasonThanosRemovedFlagPresent},
			{"scoped absence", `{"name":"thanos","image":"thanosio/thanos:v0.42.4","command":["/bin/thanos"],"args":["store","--log.level=info"]}`, StatePrepared, ReasonThanosRemovedFlagAbsent},
			{"legacy command spelling is unsupported", `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["thanos"],"args":["receive"]}`, StateUnknown, ReasonThanosWorkloadUnsupported},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				prepared, err := PrepareThanos([]byte(thanosWorkload(tc.container)), from, ThanosLatestTo)
				if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
					t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
				}
			})
		}
	}
}

func TestPrepareThanosLatestTargetAdmitsSourceDerivedEntrypoint(t *testing.T) {
	tests := []struct {
		name, container, wantOmission string
	}{
		{"source-derived", `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","args":["receive","--log.level=info"]}`, "DEFAULT_ENTRYPOINT_SOURCE_DERIVED_FOR_EXACT_ADMITTED_IMAGE_NOT_RUNTIME_OBSERVATION"},
		{"explicit", `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":["receive","--log.level=info"]}`, "DEFAULT_ENTRYPOINT_NOT_INFERRED"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareThanos([]byte(thanosWorkload(tc.container)), "0.41.0", ThanosLatestTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonThanosRemovedFlagAbsent {
				t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
			}
			for _, omission := range prepared.Omissions {
				if omission == tc.wantOmission {
					return
				}
			}
			t.Fatalf("omissions = %#v, want %q", prepared.Omissions, tc.wantOmission)
		})
	}
}

func TestPrepareThanosLatestTargetRejectsBareOptionBeforeRemovedLookingValue(t *testing.T) {
	raw := thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":["receive","--config.file","--shipper.ignore-unequal-block-size"]}`)
	prepared, err := PrepareThanos([]byte(raw), "0.41.0", ThanosLatestTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonThanosWorkloadUnsupported {
		t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
	}
}

func TestPrepareThanosRejectsUnreviewedVersionPair(t *testing.T) {
	raw := thanosWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":["receive"]}`)
	prepared, err := PrepareThanos([]byte(raw), "0.41.1", ThanosLatestTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonThanosTransitionUnsupported {
		t.Fatalf("PrepareThanos() = %#v, %v", prepared, err)
	}
}

func thanosWorkload(containers string) string {
	return `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"receive","namespace":"observability"},"spec":{"template":{"spec":{"containers":[` + containers + `]}}}}`
}

func thanosCanonicalFact(t *testing.T, raw []byte) (bool, string) {
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
			if fact.ID == ThanosFact {
				if fact.BoolValue == nil {
					return false, fact.State
				}
				return *fact.BoolValue, fact.State
			}
		}
	}
	t.Fatalf("missing %s", ThanosFact)
	return false, ""
}
