// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"testing"
)

const otelNativeConfig = `receivers:
  otlp: {}
exporters:
  logging/example: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [logging/example]
`

func TestPrepareOpenTelemetryCollectorSelectedExporter(t *testing.T) {
	prepared, err := PrepareOpenTelemetryCollector([]byte(otelNativeConfig), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonOpenTelemetryPresent {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"enumValue":"official"`)) || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
		t.Fatalf("facts=%s", prepared.CanonicalInputJSON)
	}
	if bytes.Contains(prepared.CanonicalInputJSON, []byte("logging/example")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("otlp")) {
		t.Fatal("native values leaked into minimized input")
	}
}

func TestPrepareOpenTelemetryCollectorAbsenceRequiresExporterMap(t *testing.T) {
	for _, raw := range []string{
		"receivers: {}\n",
		"exporters: {}\n",
		"exporters:\n  debug: {}\nservice:\n  pipelines:\n    traces:\n      exporters: [logging]\n",
	} {
		prepared, err := PrepareOpenTelemetryCollector([]byte(raw), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonOpenTelemetryUnsupported {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
	prepared, err := PrepareOpenTelemetryCollector([]byte("exporters:\n  debug: {}\n"), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonOpenTelemetryAbsent {
		t.Fatalf("debug-only exporter should be a scoped absence: %+v err=%v", prepared, err)
	}
}

func TestPrepareOpenTelemetryCollectorConnectorDoesNotBecomeExporter(t *testing.T) {
	raw := `connectors:
  logging: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      exporters: [logging]
`
	prepared, err := PrepareOpenTelemetryCollector([]byte(raw), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonOpenTelemetryUnsupported || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
		t.Fatalf("connector result=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
	}
}

func TestPrepareOpenTelemetryCollectorRequiresExactPairAndDeclarations(t *testing.T) {
	tests := []struct {
		name                 string
		from, to             string
		distribution         string
		complete, precedence bool
		wantReason           Reason
	}{
		{"wrong pair", "0.109.0", OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true, ReasonOpenTelemetryUnsupported},
		{"custom distribution", OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryCustomDistribution, true, true, ReasonOpenTelemetryUnsupported},
		{"missing completeness", OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, false, true, ReasonOpenTelemetryIncomplete},
		{"missing precedence", OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, false, ReasonOpenTelemetryIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareOpenTelemetryCollector([]byte(otelNativeConfig), test.from, test.to, test.distribution, test.complete, test.precedence)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != test.wantReason || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue"`)) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareOpenTelemetryCollectorRejectsInvalidUTF8AndReplacementRune(t *testing.T) {
	invalid := []byte("exporters:\n  logging: {\xff}\n")
	if _, err := PrepareOpenTelemetryCollector(invalid, OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true); err != ErrInvalid {
		t.Fatalf("invalid UTF-8 err=%v", err)
	}
	for _, raw := range []string{
		"exporters:\n  logging:\n    value: \"\\ud800\"\n",
		"exporters:\n  logging:\n    value: \"replacement �\"\n",
	} {
		prepared, err := PrepareOpenTelemetryCollector([]byte(raw), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
		if err != nil || prepared.State != StateUnknown || bytes.Contains(prepared.CanonicalInputJSON, []byte(`\"boolValue\":true`)) {
			t.Fatalf("replacement input admitted: prepared=%+v err=%v", prepared, err)
		}
	}
}

func TestPrepareOpenTelemetryCollectorUnknownBoundaries(t *testing.T) {
	base := "exporters:\n  debug: {}\n"
	for _, raw := range []string{
		"Exporters:\n  logging: {}\n",
		"exporters:\n  Logging: {}\n",
		"exporters:\n  Logging/example: {}\n",
		"exporters:\n  logging: {}\nexporters:\n  debug: {}\n",
		"exporters:\n  logging: &x {}\n",
		"exporters:\n  logging: !custom {}\n",
		"exporters:\n  logging: {}\nservice:\n  pipelines:\n    traces:\n      exporters: [missing]\n",
		"exporters:\n  logging: {}\nservice:\n  pipelines:\n    traces:\n      exporters: [logging, logging]\n",
		"connectors:\n  logging: {}\nexporters:\n  logging: {}\n",
		"exporters:\n  logging: {}\ninclude: secret.yaml\n",
		"receivers:\n  exporters:\n    logging: {}\n" + base,
		base + "service:\n  pipelines:\n    traces:\n      exporters: [logging]\n",
	} {
		prepared, err := PrepareOpenTelemetryCollector([]byte(raw), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, true, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonOpenTelemetryUnsupported {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
	for _, test := range []struct {
		name                 string
		complete, precedence bool
	}{
		{"missing completeness", false, true},
		{"missing precedence", true, false},
	} {
		raw := []byte(otelNativeConfig)
		prepared, err := PrepareOpenTelemetryCollector(raw, OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, test.complete, test.precedence)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonOpenTelemetryIncomplete {
			t.Fatalf("%s incomplete prepared=%+v err=%v", test.name, prepared, err)
		}
	}
}

func TestPrepareOpenTelemetryInternalMetricsTruthTableAndPrivacy(t *testing.T) {
	raw := []byte("exporters:\n  debug: {}\nservice:\n  telemetry:\n    # PRIVATE_OTEL must never enter the canonical projection.\n    logs:\n      level: info\n")
	tests := []struct {
		name, gate, remote   string
		complete, precedence bool
		wantState            State
		wantReason           Reason
	}{
		{"wildcard default with remote intent", "false", "true", true, true, StatePrepared, ReasonOpenTelemetryMetricsPrepared},
		{"localhost default with remote intent", "true", "true", true, true, StatePrepared, ReasonOpenTelemetryMetricsPrepared},
		{"local scrape does not require migration", "true", "false", true, true, StatePrepared, ReasonOpenTelemetryMetricsPrepared},
		{"wildcard default without remote intent", "false", "false", true, true, StatePrepared, ReasonOpenTelemetryMetricsPrepared},
		{"missing gate authority", "", "true", true, true, StateUnknown, ReasonOpenTelemetryMetricsAuthorityMissing},
		{"invalid remote authority", "false", "yes", true, true, StateUnknown, ReasonOpenTelemetryMetricsAuthorityMissing},
		{"incomplete config declaration", "false", "true", false, true, StateUnknown, ReasonOpenTelemetryIncomplete},
		{"unresolved precedence declaration", "false", "true", true, false, StateUnknown, ReasonOpenTelemetryIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareOpenTelemetryInternalMetrics(raw, OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, test.gate, test.remote, test.complete, test.precedence)
			if err != nil || prepared.State != test.wantState || prepared.Reason != test.wantReason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("PRIVATE_OTEL")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("debug")) {
				t.Fatalf("private/native value leaked: %s", prepared.CanonicalInputJSON)
			}
			for _, fact := range []string{OpenTelemetryMetricsOverrideAbsentFact, OpenTelemetryMetricsGateFact, OpenTelemetryMetricsRemoteRequiredFact, OpenTelemetryMetricsConflictFact, OpenTelemetryConfigCompleteFact, OpenTelemetryConfigPrecedenceFact} {
				if !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"id":"`+fact+`"`)) {
					t.Fatalf("canonical input omitted %s: %s", fact, prepared.CanonicalInputJSON)
				}
			}
		})
	}
}

func TestPrepareOpenTelemetryInternalMetricsRejectsOverrideAndScopeAmbiguity(t *testing.T) {
	for _, raw := range []string{
		"exporters:\n  debug: {}\nservice:\n  telemetry:\n    metrics:\n      address: 0.0.0.0:8888\n",
		"exporters:\n  debug: {}\nservice:\n  telemetry: !custom {}\n",
		"exporters: &shared\n  debug: {}\nservice:\n  telemetry:\n    metrics: {}\n",
	} {
		prepared, err := PrepareOpenTelemetryInternalMetrics([]byte(raw), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryOfficialDistribution, "false", "true", true, true)
		if err != nil || prepared.State != StateUnknown {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
	prepared, err := PrepareOpenTelemetryInternalMetrics([]byte("exporters:\n  debug: {}\n"), OpenTelemetryFrom, OpenTelemetryTo, OpenTelemetryCustomDistribution, "false", "true", true, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonOpenTelemetryCustomDistribution {
		t.Fatalf("custom distribution prepared=%+v err=%v", prepared, err)
	}
}
