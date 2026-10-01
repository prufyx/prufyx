// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func TestPrepareEnvoyBootstrapDirectV2Only(t *testing.T) {
	for _, tc := range []struct {
		name, raw, reason string
		prepared          bool
	}{
		{"ads", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`, string(ReasonEnvoyV2TransportWitness), true},
		{"lds", `{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"DELTA_GRPC","transport_api_version":"V2"}}}}`, string(ReasonEnvoyV2TransportWitness), true},
		{"cds", `{"dynamic_resources":{"cds_config":{"api_config_source":{"api_type":"REST","transport_api_version":"V2"}}}}`, string(ReasonEnvoyV2TransportWitness), true},
		{"absent", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC"}}}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"v3", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V3"}}}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"auto", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"AUTO"}}}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"numeric", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":1}}}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"lowercase", `{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"v2"}}}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"typed only", `{"bootstrap_extensions":[{"typed_config":{"@type":"type.googleapis.com/example.V2"}}]}`, string(ReasonEnvoyBootstrapUnsupported), false},
		{"yaml", "dynamic_resources:\n  ads_config:\n    api_type: GRPC\n    transport_api_version: V2\n", string(ReasonEnvoyBootstrapUnsupported), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEnvoyBootstrap([]byte(tc.raw), "1.38.4", EnvoyLatestTo, true)
			if err != nil || prepared.State == StatePrepared != tc.prepared || string(prepared.Reason) != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if tc.prepared != strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"v2"`) {
				t.Fatalf("canonical=%s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareEnvoyBootstrapAmbiguityAndInputBounds(t *testing.T) {
	for _, raw := range []string{
		`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"},"adsConfig":{}}}`,
		`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2"},"ads":{}}}}`,
		`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2"},"pathConfigSource":{}}}}`,
		`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2"},"apiConfigSource":{}}}}`,
		`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2","transportApiVersion":"V3"}}}}`,
		`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}},"dynamicResources":{}}`,
	} {
		prepared, err := PrepareEnvoyBootstrap([]byte(raw), "1.38.4", EnvoyLatestTo, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEnvoyBootstrapUnsupported {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
	}
	if _, err := PrepareEnvoyBootstrap([]byte(`{"dynamic_resources":`), "1.38.4", EnvoyLatestTo, true); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if _, err := PrepareEnvoyBootstrap([]byte(`[`), "1.38.4", EnvoyLatestTo, true); err == nil {
		t.Fatal("malformed JSON array accepted")
	}
	preparedArray, err := PrepareEnvoyBootstrap([]byte(`[]`), "1.38.4", EnvoyLatestTo, true)
	if err != nil || preparedArray.State != StateUnknown || preparedArray.Reason != ReasonEnvoyBootstrapUnsupported {
		t.Fatalf("array=%+v err=%v", preparedArray, err)
	}
	prepared, err := PrepareEnvoyBootstrap([]byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`), "1.38.4", EnvoyLatestTo, false)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEnvoyBootstrapUnselected {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	prepared, err = PrepareEnvoyBootstrap([]byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`), "1.33.0", EnvoyLatestTo, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEnvoyPairUnsupported {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
}
