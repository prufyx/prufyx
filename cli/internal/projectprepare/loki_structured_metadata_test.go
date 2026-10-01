// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"testing"
)

func TestPrepareLokiStructuredMetadataBoundedNativeSubset(t *testing.T) {
	valid := "limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"
	for _, tc := range []struct {
		name, raw, from, to, state        string
		complete, precedence, defaultUsed bool
		value                             *bool
	}{
		{"valid-tsdb-v13", valid, LokiFrom, LokiTo, "PREPARED", true, true, false, boolPointer(false)},
		{"invalid-store-schema", "limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: '2024-01-01'\n      store: boltdb-shipper\n      schema: v12\n", LokiFrom, LokiTo, "PREPARED", true, true, false, boolPointer(true)},
		{"explicit-false-scoped-pass", "limits_config:\n  allow_structured_metadata: false\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: boltdb-shipper\n      schema: v11\n", LokiFrom, LokiTo, "PREPARED", true, true, false, boolPointer(false)},
		{"omitted-default-opt-in", "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", LokiFrom, LokiTo, "PREPARED", true, true, true, boolPointer(false)},
		{"omitted-no-default", "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", LokiFrom, LokiTo, "UNKNOWN", true, true, false, nil},
		{"default-wrong-pair", "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", "2.9.7", LokiTo, "UNKNOWN", true, true, true, nil},
		{"explicit-wrong-pair", "limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", "2.9.7", LokiTo, "UNKNOWN", true, true, false, nil},
		{"unsupported-schema", "limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v14\n", LokiFrom, LokiTo, "UNKNOWN", true, true, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareLokiStructuredMetadata([]byte(tc.raw), tc.from, tc.to, tc.complete, tc.precedence, tc.defaultUsed)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, LokiStructuredMetadataFact, tc.value)
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("boltdb-shipper")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("2024-01-01")) {
				t.Fatal("raw selected values leaked")
			}
			if tc.defaultUsed && tc.state == "PREPARED" && !containsString(prepared.Omissions, "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG") {
				t.Fatal("default derivation omission missing")
			}
		})
	}
}

func TestPrepareLokiStructuredMetadataRejectsAmbiguousShapes(t *testing.T) {
	inputs := []string{
		"Limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config:\n  allow-structured-metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n    - from: 2025-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01T00:00:00Z\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-02-30\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: TSDB\n      schema: v13\n",
		"limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n  configs: []\n",
		"limits_config: &x {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nconfig_file: ${LOKI_CONFIG}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n      include: extra.yml\n",
		"limits_config:\n  note: '{{ .Values.allow }}'\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"? &limits limits_config\n: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"!!str limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"allow_structured_metadata: false\nlimits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config:\n  extra:\n    allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
		"limits_config:\n  schema_config:\n    configs: []\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n",
	}
	for _, raw := range inputs {
		prepared, err := PrepareLokiStructuredMetadata([]byte(raw), LokiFrom, LokiTo, true, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous input state=%q err=%v raw=%q", prepared.State, err, raw)
		}
		assertCanonicalFact(t, prepared.CanonicalInputJSON, LokiStructuredMetadataFact, nil)
	}
}

func TestPrepareLokiStructuredMetadataInputBounds(t *testing.T) {
	if _, err := PrepareLokiStructuredMetadata([]byte{0xff}, LokiFrom, LokiTo, true, true, false); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	prepared, err := PrepareLokiStructuredMetadata([]byte("limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"), LokiFrom, LokiTo, false, false, false)
	if err != nil || prepared.State != "UNKNOWN" {
		t.Fatalf("incomplete state=%q err=%v", prepared.State, err)
	}
	wrongPair, err := PrepareLokiStructuredMetadata([]byte("limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"), "2.9.7", LokiTo, true, true, false)
	if err != nil || wrongPair.Reason != "LOKI_SCHEMA_UNSUPPORTED_VERSION_PAIR" {
		t.Fatalf("wrong-pair reason=%q err=%v", wrongPair.Reason, err)
	}
	missingDefault, err := PrepareLokiStructuredMetadata([]byte("limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"), LokiFrom, LokiTo, true, true, false)
	if err != nil || missingDefault.Reason != "LOKI_TARGET_DEFAULT_REQUIRES_EXPLICIT_OPT_IN" {
		t.Fatalf("missing-default reason=%q err=%v", missingDefault.Reason, err)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
