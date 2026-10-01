// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"testing"
)

func TestPrepareCortexLiteralAtModifierFlag(t *testing.T) {
	tests := []struct {
		name, raw, wantReason string
		wantPresent           bool
	}{
		{"removed flag", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-querier.at-modifier-enabled"]}`), string(ReasonCortexRemovedFlagPresent), true},
		{"false spelling remains present", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--querier.at-modifier-enabled=false"]}`), string(ReasonCortexRemovedFlagPresent), true},
		{"empty spelling remains present", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-querier.at-modifier-enabled="]}`), string(ReasonCortexRemovedFlagPresent), true},
		{"source-derived omitted command retains removed flag", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","args":["--querier.at-modifier-enabled=true"]}`), string(ReasonCortexRemovedFlagPresent), true},
		{"source-derived omitted command retains scoped absence", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","args":["-target=all"]}`), string(ReasonCortexRemovedFlagAbsent), false},
		{"literal absence with sidecar", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-target=all"]},{"name":"config-reloader","image":"example.invalid/reloader:v1"}`), string(ReasonCortexRemovedFlagAbsent), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCortex([]byte(tc.raw), CortexFrom, CortexTo)
			if err != nil || prepared.State != StatePrepared || string(prepared.Reason) != tc.wantReason {
				t.Fatalf("PrepareCortex() = %#v, %v", prepared, err)
			}
			if got, state := cortexCanonicalFact(t, prepared.CanonicalInputJSON); state != "declared" || got != tc.wantPresent {
				t.Fatalf("fact=(%t,%q), want=(%t,declared)", got, state, tc.wantPresent)
			}
		})
	}
}

func TestPrepareCortexOmissionsDescribeSourceDerivedEntrypoint(t *testing.T) {
	tests := []struct {
		name, container string
		want            string
	}{
		{"source-derived", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","args":["-target=all"]}`, "DEFAULT_ENTRYPOINT_SOURCE_DERIVED_FOR_EXACT_ADMITTED_IMAGE_NOT_RUNTIME_OBSERVATION"},
		{"explicit", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-target=all"]}`, "DEFAULT_ENTRYPOINT_NOT_INFERRED"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCortex([]byte(cortexWorkload(tc.container)), CortexFrom, CortexTo)
			if err != nil || prepared.State != StatePrepared {
				t.Fatalf("PrepareCortex() = %#v, %v", prepared, err)
			}
			for _, omission := range prepared.Omissions {
				if omission == tc.want {
					return
				}
			}
			t.Fatalf("omissions = %#v, want %q", prepared.Omissions, tc.want)
		})
	}
}

func TestPrepareCortexUnknownForUnresolvedWorkload(t *testing.T) {
	valid := `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-target=all"]}`
	tests := []struct{ name, raw string }{
		{"null command", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":null,"args":["-target=all"]}`)},
		{"empty command", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":[],"args":["-target=all"]}`)},
		{"shell wrapper", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["sh","-c"],"args":["-target=all"]}`)},
		{"wrong explicit binary", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["cortex"],"args":["-target=all"]}`)},
		{"wrong target image", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.17.2","command":["/bin/cortex"],"args":["-target=all"]}`)},
		{"custom image", cortexWorkload(`{"name":"cortex","image":"registry.example/cortex:v1.21.1","command":["/bin/cortex"],"args":["-target=all"]}`)},
		{"dynamic argument", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-target=${TARGET}"]}`)},
		{"argument delimiter", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--","-querier.at-modifier-enabled"]}`)},
		{"bare preceding option can consume removed spelling", cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-config.file","--querier.at-modifier-enabled"]}`)},
		{"two cortex containers", cortexWorkload(valid + `,` + valid)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCortex([]byte(tc.raw), CortexFrom, CortexTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCortexWorkloadUnsupported {
				t.Fatalf("PrepareCortex() = %#v, %v", prepared, err)
			}
			if _, state := cortexCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
				t.Fatalf("fact state=%q, want unsupported", state)
			}
		})
	}
}

func TestPrepareCortexLatestTargetPairsHaveBlockedPassAndUnknownOutcomes(t *testing.T) {
	for _, from := range []string{"1.16.1", "1.17.2", "1.18.1", "1.19.1", "1.20.1"} {
		for _, tc := range []struct {
			name, container string
			state           State
			reason          Reason
		}{
			{"blocker", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--querier.at-modifier-enabled=true"]}`, StatePrepared, ReasonCortexRemovedFlagPresent},
			{"scoped absence", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`, StatePrepared, ReasonCortexRemovedFlagAbsent},
			{"unsupported image", `{"name":"cortex","image":"registry.example/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`, StateUnknown, ReasonCortexWorkloadUnsupported},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				prepared, err := PrepareCortex([]byte(cortexWorkload(tc.container)), from, CortexTo)
				if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
					t.Fatalf("PrepareCortex() = %#v, %v", prepared, err)
				}
			})
		}
	}
}

func TestPrepareCortexRejectsUnreviewedVersionPair(t *testing.T) {
	raw := cortexWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`)
	prepared, err := PrepareCortex([]byte(raw), "1.20.2", CortexTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCortexTransitionUnsupported {
		t.Fatalf("PrepareCortex() = %#v, %v", prepared, err)
	}
}

func cortexWorkload(containers string) string {
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"cortex","namespace":"observability"},"spec":{"template":{"spec":{"containers":[` + containers + `]}}}}`
}

func cortexCanonicalFact(t *testing.T, raw []byte) (bool, string) {
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
			if fact.ID == CortexFact {
				if fact.BoolValue == nil {
					return false, fact.State
				}
				return *fact.BoolValue, fact.State
			}
		}
	}
	t.Fatalf("missing %s", CortexFact)
	return false, ""
}
