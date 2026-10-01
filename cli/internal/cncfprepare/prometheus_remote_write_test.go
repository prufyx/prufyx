// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"testing"
)

func TestPreparePrometheusRemoteWriteHTTP2Policy(t *testing.T) {
	trueValue, falseValue := true, false
	tests := []struct {
		name        string
		raw         string
		required    *bool
		wantSetting string
		wantBlocked bool
		wantReason  Reason
	}{
		{"required explicit true", "remote_write:\n  - name: primary\n    url: https://example.invalid/write\n    enable_http2: true\n", &trueValue, "true", false, ReasonPrometheusRemoteWriteHTTP2Satisfied},
		{"required explicit false", "remote_write:\n  - name: primary\n    url: https://example.invalid/write\n    enable_http2: false\n", &trueValue, "false", true, ReasonPrometheusRemoteWriteHTTP2Unsatisfied},
		{"required omitted target default", "remote_write:\n  - name: primary\n    url: https://example.invalid/write\n", &trueValue, "omitted", true, ReasonPrometheusRemoteWriteHTTP2Unsatisfied},
		{"not required explicit true", "remote_write:\n  - name: primary\n    enable_http2: true\n", &falseValue, "true", false, ReasonPrometheusRemoteWriteHTTP2Satisfied},
		{"not required explicit false", "remote_write:\n  - name: primary\n    enable_http2: false\n", &falseValue, "false", false, ReasonPrometheusRemoteWriteHTTP2Satisfied},
		{"not required omitted", "remote_write:\n  - name: primary\n", &falseValue, "omitted", false, ReasonPrometheusRemoteWriteHTTP2Satisfied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PreparePrometheusRemoteWriteConfig([]byte(test.raw), "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, test.required)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != test.wantReason {
				t.Fatalf("state=%s reason=%s err=%v", prepared.State, prepared.Reason, err)
			}
			setting, blocked := prometheusRemoteWriteCanonicalFacts(t, prepared.CanonicalInputJSON)
			if setting != test.wantSetting || blocked == nil || *blocked != test.wantBlocked {
				t.Fatalf("setting=%q blocked=%v", setting, blocked)
			}
		})
	}
}

func TestPreparePrometheusRemoteWriteHTTP2UnknownBoundaries(t *testing.T) {
	trueValue := true
	valid := "remote_write:\n  - name: primary\n    enable_http2: true\n"
	tests := []struct {
		name       string
		raw        string
		selected   string
		from, to   string
		complete   bool
		precedence bool
		required   *bool
	}{
		{"missing selected name", valid, "", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"wrong pair", valid, "primary", PrometheusFrom, PrometheusTo, true, true, &trueValue},
		{"missing completeness", valid, "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, false, true, &trueValue},
		{"missing precedence", valid, "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, false, &trueValue},
		{"missing policy authority", valid, "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, nil},
		{"ambiguous selected name", "remote_write:\n  - name: primary\n    enable_http2: true\n  - name: primary\n    enable_http2: true\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"duplicate key", "remote_write:\n  - name: primary\n    enable_http2: true\n    enable_http2: false\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"alias", "entry: &entry\n  name: primary\n  enable_http2: true\nremote_write:\n  - *entry\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"merge", "defaults: &defaults\n  enable_http2: true\nremote_write:\n  - name: primary\n    <<: *defaults\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"custom tag", "remote_write:\n  - name: primary\n    enable_http2: !policy true\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"substitution", "remote_write:\n  - name: primary\n    url: ${PRIVATE_URL}\n    enable_http2: true\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"nested lookalike", "remote_write:\n  - name: primary\n    http_config:\n      enable_http2: true\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
		{"nonliteral", "remote_write:\n  - name: primary\n    enable_http2: 'true'\n", "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PreparePrometheusRemoteWriteConfig([]byte(test.raw), test.selected, test.from, test.to, test.complete, test.precedence, test.required)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusRemoteWriteHTTP2Unsupported {
				t.Fatalf("state=%s reason=%s err=%v", prepared.State, prepared.Reason, err)
			}
			setting, blocked := prometheusRemoteWriteCanonicalFacts(t, prepared.CanonicalInputJSON)
			if setting != "" || blocked != nil {
				t.Fatalf("unsupported facts leaked setting=%q blocked=%v", setting, blocked)
			}
		})
	}
}

func TestPreparePrometheusRemoteWriteHTTP2RejectsInvalidEnvelope(t *testing.T) {
	trueValue := true
	for name, call := range map[string]func() (Prepared, error){
		"empty input": func() (Prepared, error) {
			return PreparePrometheusRemoteWriteConfig(nil, "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue)
		},
		"invalid name": func() (Prepared, error) {
			return PreparePrometheusRemoteWriteConfig([]byte("remote_write: []\n"), "${PRIVATE_NAME}", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2To, true, true, &trueValue)
		},
		"same version": func() (Prepared, error) {
			return PreparePrometheusRemoteWriteConfig([]byte("remote_write: []\n"), "primary", PrometheusRemoteWriteHTTP2From, PrometheusRemoteWriteHTTP2From, true, true, &trueValue)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := call(); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}

func prometheusRemoteWriteCanonicalFacts(t *testing.T, raw []byte) (string, *bool) {
	t.Helper()
	var input inputEnvelope
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Proposed.Components) != 1 {
		t.Fatalf("components=%d", len(input.Proposed.Components))
	}
	var setting string
	var blocked *bool
	for _, fact := range input.Proposed.Components[0].Facts {
		switch fact.ID {
		case PrometheusRemoteWriteHTTP2Fact:
			setting = fact.EnumValue
		case PrometheusRemoteWriteHTTP2UnsatisfiedFact:
			blocked = fact.BoolValue
		}
	}
	return setting, blocked
}
