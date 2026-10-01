// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func knativeService(t *testing.T, containerPort, probePort any, mutate func(map[string]any)) []byte {
	t.Helper()
	container := map[string]any{
		"name":         "user-container",
		"image":        "private.registry.invalid/canary",
		"ports":        []any{map[string]any{"name": containerPort, "containerPort": 8080}},
		"startupProbe": map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": probePort}},
		"env":          []any{map[string]any{"name": "PRIVATE_CANARY", "value": "must-not-cross-output"}},
	}
	root := map[string]any{
		"apiVersion": knativeServiceAPIVersion,
		"kind":       knativeServiceKind,
		"metadata":   map[string]any{"name": "private-name", "namespace": "private-namespace"},
		"spec": map[string]any{"template": map[string]any{
			"spec": map[string]any{"containers": []any{container}},
		}},
	}
	if mutate != nil {
		mutate(root)
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPrepareKnativeServingNamedStartupPort(t *testing.T) {
	for _, tc := range []struct {
		name, containerPort, probePort string
		wantMismatch                   bool
	}{
		{"mismatch", "http1", "h2c", true},
		{"match", "http1", "http1", false},
		{"h2c match", "h2c", "h2c", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := knativeService(t, tc.containerPort, tc.probePort, nil)
			prepared, err := PrepareKnativeServing(raw, KnativeFrom, KnativeTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKnativeStartupPortWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := preparedFacts(t, prepared)[KnativeStartupPortFact]
			if fact["state"] != "declared" || fact["boolValue"] != tc.wantMismatch {
				t.Fatalf("fact=%v", fact)
			}
			for _, private := range []string{"private-name", "private-namespace", "private.registry", "must-not-cross-output", "/healthz", tc.containerPort, tc.probePort} {
				if strings.Contains(string(prepared.CanonicalInputJSON), private) {
					t.Fatalf("private or raw detail retained: %q in %s", private, prepared.CanonicalInputJSON)
				}
			}
		})
	}
}

func TestPrepareKnativeServingUnsupportedShapesStayUnknown(t *testing.T) {
	tests := []struct {
		name string
		raw  func(*testing.T) []byte
	}{
		{"wrong resource", func(t *testing.T) []byte {
			return []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"x"}}`)
		}},
		{"numeric probe", func(t *testing.T) []byte { return knativeService(t, "http1", 8080, nil) }},
		{"unsupported container name", func(t *testing.T) []byte { return knativeService(t, "http", "http", nil) }},
		{"multiple containers", func(t *testing.T) []byte {
			return knativeService(t, "http1", "h2c", func(root map[string]any) {
				spec := root["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				spec["containers"] = append(spec["containers"].([]any), map[string]any{"name": "sidecar"})
			})
		}},
		{"multiple ports", func(t *testing.T) []byte {
			return knativeService(t, "http1", "h2c", func(root map[string]any) {
				container := root["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				container["ports"] = append(container["ports"].([]any), map[string]any{"name": "h2c", "containerPort": 8081})
			})
		}},
		{"other handler", func(t *testing.T) []byte {
			return knativeService(t, "http1", "h2c", func(root map[string]any) {
				container := root["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				container["startupProbe"] = map[string]any{"tcpSocket": map[string]any{"port": "http1"}}
			})
		}},
		{"competing handlers", func(t *testing.T) []byte {
			return knativeService(t, "http1", "h2c", func(root map[string]any) {
				container := root["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				container["startupProbe"].(map[string]any)["tcpSocket"] = map[string]any{"port": "http1"}
			})
		}},
		{"missing startup probe", func(t *testing.T) []byte {
			return knativeService(t, "http1", "h2c", func(root map[string]any) {
				container := root["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				delete(container, "startupProbe")
			})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKnativeServing(tc.raw(t), KnativeFrom, KnativeTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKnativeResourceUnsupported || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareKnativeServingObservationIsIndependentOfRuleTuple(t *testing.T) {
	prepared, err := PrepareKnativeServing(knativeService(t, "http1", "h2c", nil), "1.22.1", KnativeTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKnativeStartupPortWitness {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	fact := preparedFacts(t, prepared)[KnativeStartupPortFact]
	if fact["state"] != "declared" || fact["boolValue"] != true {
		t.Fatalf("fact=%v", fact)
	}
}

func TestPrepareKnativeServingMalformedInput(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`[]`), []byte(`{"apiVersion":`), []byte(`{"apiVersion":"serving.knative.dev/v1","apiVersion":"v1"}`)} {
		if _, err := PrepareKnativeServing(raw, KnativeFrom, KnativeTo); err == nil {
			t.Fatalf("malformed input accepted: %q", raw)
		}
	}
}
