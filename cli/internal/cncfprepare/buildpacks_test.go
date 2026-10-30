// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func lifecycleOCIConfig(t *testing.T, version string, supported, deprecated []string, mutate func(map[string]any)) []byte {
	t.Helper()
	if deprecated == nil {
		deprecated = []string{}
	}
	apis, _ := json.Marshal(map[string]any{"buildpack": map[string]any{"supported": []string{"0.9"}, "deprecated": []string{}}, "platform": map[string]any{"supported": supported, "deprecated": deprecated}})
	metadata, _ := json.Marshal(map[string]any{"lifecycle": map[string]any{"version": version}, "api": map[string]any{"platform": "0.3"}})
	root := map[string]any{"architecture": "arm64", "os": "linux", "config": map[string]any{"Labels": map[string]any{"io.buildpacks.lifecycle.version": version, "io.buildpacks.lifecycle.apis": string(apis), "io.buildpacks.builder.metadata": string(metadata), "private.example/canary": "DO_NOT_RETAIN"}}, "history": []any{map[string]any{"created_by": "PRIVATE_HISTORY"}}}
	if mutate != nil {
		mutate(root)
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var (
	realDeprecated = []string{"0.3", "0.4", "0.5", "0.6"}
	realSupported0 = []string{"0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "0.10", "0.11"}
	realSupported1 = append(append([]string{}, realSupported0...), "0.12")
)

func TestPrepareBuildpacksLifecyclePlan(t *testing.T) {
	current := lifecycleOCIConfig(t, BuildpacksFrom, realSupported0, realDeprecated, nil)
	target := lifecycleOCIConfig(t, BuildpacksTo, realSupported1, realDeprecated, nil)
	for _, tc := range []struct {
		name, proposed string
		want           bool
	}{
		{"unsupported requested API", "0.13", false}, {"declared supported API", "0.12", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareBuildpacksLifecycle(current, target, BuildpacksFrom, BuildpacksTo, "0.11", tc.proposed)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonBuildpacksMetadataObserved {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			var envelope inputEnvelope
			if json.Unmarshal(prepared.CanonicalInputJSON, &envelope) != nil {
				t.Fatal("decode")
			}
			if len(envelope.Current.Components) != 1 || len(envelope.Proposed.Components) != 1 || *envelope.Current.Components[0].Facts[0].BoolValue != true || *envelope.Proposed.Components[0].Facts[0].BoolValue != tc.want {
				t.Fatalf("input=%s", prepared.CanonicalInputJSON)
			}
			for _, private := range []string{"DO_NOT_RETAIN", "PRIVATE_HISTORY", "architecture", "builder.metadata"} {
				if strings.Contains(string(prepared.CanonicalInputJSON), private) {
					t.Fatalf("private data retained: %q", private)
				}
			}
		})
	}
}

func TestPrepareBuildpacksLifecycleUnsupportedMetadataStaysUnknown(t *testing.T) {
	validCurrent := lifecycleOCIConfig(t, BuildpacksFrom, realSupported0, realDeprecated, nil)
	validTarget := lifecycleOCIConfig(t, BuildpacksTo, realSupported1, realDeprecated, nil)
	tests := []struct {
		name            string
		current, target []byte
	}{
		{"wrong current identity", lifecycleOCIConfig(t, "0.16.4", realSupported0, realDeprecated, nil), validTarget},
		{"wrong target identity", validCurrent, lifecycleOCIConfig(t, "0.17.6", realSupported1, realDeprecated, nil)},
		{"deprecated outside supported", validCurrent, lifecycleOCIConfig(t, BuildpacksTo, realSupported1, []string{"0.13"}, nil)},
		{"deprecated differs from pinned", validCurrent, lifecycleOCIConfig(t, BuildpacksTo, realSupported1, []string{"0.11"}, nil)},
		{"missing labels", validCurrent, []byte(`{"config":{"Labels":{}}}`)},
		{"wrong-PASS: target claims 0.13", validCurrent, lifecycleOCIConfig(t, BuildpacksTo, append(append([]string{}, realSupported1...), "0.13"), realDeprecated, nil)},
		{"target claims only up to 0.11", validCurrent, lifecycleOCIConfig(t, BuildpacksTo, realSupported0, realDeprecated, nil)},
		{"target deprecated differs", validCurrent, lifecycleOCIConfig(t, BuildpacksTo, realSupported1, []string{"0.3"}, nil)},
		{"current lacks 0.11", lifecycleOCIConfig(t, BuildpacksFrom, realSupported0[:8], realDeprecated, nil), validTarget},
		{"current claims 0.12", lifecycleOCIConfig(t, BuildpacksFrom, realSupported1, realDeprecated, nil), validTarget},
		{"nested duplicate", validCurrent, []byte(`{"config":{"Labels":{"io.buildpacks.lifecycle.version":"0.17.7","io.buildpacks.lifecycle.apis":"{\"platform\":{\"supported\":[\"0.12\"],\"Supported\":[\"0.12\"],\"deprecated\":[]}}"}}}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareBuildpacksLifecycle(tc.current, tc.target, BuildpacksFrom, BuildpacksTo, "0.11", "0.13")
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonBuildpacksMetadataUnsupported {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if !strings.Contains(string(prepared.CanonicalInputJSON), `"state":"unsupported"`) {
				t.Fatalf("input=%s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareBuildpacksLifecycleSetOrderIrrelevantAndUnreviewedVersion(t *testing.T) {
	rev := []string{"0.12", "0.11", "0.10", "0.9", "0.8", "0.7", "0.6", "0.5", "0.4", "0.3"}
	current := lifecycleOCIConfig(t, BuildpacksFrom, realSupported0, realDeprecated, nil)
	target := lifecycleOCIConfig(t, BuildpacksTo, rev, []string{"0.6", "0.5", "0.4", "0.3"}, nil)
	prepared, err := PrepareBuildpacksLifecycle(current, target, BuildpacksFrom, BuildpacksTo, "0.11", "0.12")
	if err != nil || prepared.State != StatePrepared {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	var value map[string]any
	if json.Unmarshal(lifecycleOCIConfig(t, "0.19.6", append(append([]string{}, realSupported1...), "0.13"), realDeprecated, nil), &value) != nil {
		t.Fatal("decode")
	}
	if support, ok := inspectLifecycleConfig(value, "0.19.6", "0.13"); support || ok {
		t.Fatalf("unreviewed version accepted: %v %v", support, ok)
	}
}

func TestPrepareBuildpacksLifecycleRejectsInvalidInput(t *testing.T) {
	valid := lifecycleOCIConfig(t, BuildpacksFrom, realSupported0, realDeprecated, nil)
	for _, tc := range []struct{ raw, api string }{{`{`, "0.11"}, {string(valid), "00.11"}} {
		if _, err := PrepareBuildpacksLifecycle([]byte(tc.raw), valid, BuildpacksFrom, BuildpacksTo, tc.api, "0.13"); err == nil {
			t.Fatalf("accepted raw=%q api=%q", tc.raw, tc.api)
		}
	}
}
