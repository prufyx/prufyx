// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func tektonConfigMap(data string) []byte {
	return []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: config-observability
  namespace: tekton-pipelines
  labels:
    app.kubernetes.io/part-of: tekton-pipelines
` + data)
}

func tektonBool(value bool) *bool { return &value }

func TestPrepareTektonConfigObservabilityMetricsProtocol(t *testing.T) {
	for _, test := range []struct {
		name      string
		raw       []byte
		state     State
		reason    Reason
		factState string
		factValue string
	}{
		{
			name: "exact prometheus protocol resolves true",
			raw: tektonConfigMap(`data:
  metrics-protocol: prometheus
`),
			state: StatePrepared, reason: ReasonTektonPrometheusDeclared, factState: "declared", factValue: "true",
		},
		{
			// The pinned upstream default ConfigMap keeps its whole _example
			// block; its text must never be scanned for the reviewed key.
			name: "example block is never scanned",
			raw: tektonConfigMap(`data:
  metrics-protocol: prometheus
  _example: |
    metrics-protocol: grpc
    metrics.backend-destination: stackdriver
`),
			state: StatePrepared, reason: ReasonTektonPrometheusDeclared, factState: "declared", factValue: "true",
		},
		{
			// The pinned v1.10 DefaultConfig returns ProtocolNone and the parser
			// reads only metrics-protocol, so a definite absence is false.
			name: "definite absence resolves false",
			raw: tektonConfigMap(`data:
  runtime-profiling: disabled
`),
			state: StatePrepared, reason: ReasonTektonPrometheusAbsent, factState: "declared", factValue: "false",
		},
		{
			// The removed OpenCensus spelling is not a protocol at the target.
			name: "legacy backend-destination alone resolves false",
			raw: tektonConfigMap(`data:
  metrics.backend-destination: prometheus
`),
			state: StatePrepared, reason: ReasonTektonPrometheusAbsent, factState: "declared", factValue: "false",
		},
		{
			name:  "absent data block resolves false",
			raw:   tektonConfigMap(""),
			state: StatePrepared, reason: ReasonTektonPrometheusAbsent, factState: "declared", factValue: "false",
		},
		{
			name: "recognized non-prometheus protocol stays unknown",
			raw: tektonConfigMap(`data:
  metrics-protocol: grpc
`),
			state: StateUnknown, reason: ReasonTektonProtocolNotPrometheus, factState: "unsupported",
		},
		{
			name: "protocol none stays unknown",
			raw: tektonConfigMap(`data:
  metrics-protocol: none
`),
			state: StateUnknown, reason: ReasonTektonProtocolNotPrometheus, factState: "unsupported",
		},
		{
			name: "empty protocol value stays unknown",
			raw: tektonConfigMap(`data:
  metrics-protocol: ""
`),
			state: StateUnknown, reason: ReasonTektonProtocolUnsupported, factState: "unsupported",
		},
		{
			name: "padded protocol value stays unknown",
			raw: tektonConfigMap(`data:
  metrics-protocol: " prometheus"
`),
			state: StateUnknown, reason: ReasonTektonProtocolUnsupported, factState: "unsupported",
		},
		{
			name: "differently-cased protocol value stays unknown",
			raw: tektonConfigMap(`data:
  metrics-protocol: Prometheus
`),
			state: StateUnknown, reason: ReasonTektonProtocolUnsupported, factState: "unsupported",
		},
		{
			name: "near-miss key spelling stays unknown",
			raw: tektonConfigMap(`data:
  Metrics-Protocol: prometheus
`),
			state: StateUnknown, reason: ReasonTektonProtocolUnsupported, factState: "unsupported",
		},
		{
			name: "binaryData overlap leaves the document unresolved",
			raw: tektonConfigMap(`data:
  metrics-protocol: prometheus
binaryData:
  metrics-protocol: cHJvbWV0aGV1cw==
`),
			state: StateUnknown, reason: ReasonTektonIdentityUnresolved, factState: "unsupported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTektonConfigObservability(test.raw, TektonFrom, TektonTo, TektonDistributionOfficial, "tekton-pipelines", tektonBool(true), tektonBool(true))
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			canonical := string(prepared.CanonicalInputJSON)
			want := `"id":"` + TektonPrometheusFact + `","state":"` + test.factState + `"`
			if test.factValue != "" {
				want += `,"boolValue":` + test.factValue
			}
			if !strings.Contains(canonical, want) {
				t.Fatalf("expected %s in %s", want, canonical)
			}
			if strings.Contains(canonical, "stackdriver") || strings.Contains(canonical, "runtime-profiling") {
				t.Fatalf("private ConfigMap content retained: %s", canonical)
			}
		})
	}
}

func TestPrepareTektonConfigObservabilityIdentityBinding(t *testing.T) {
	prometheus := `data:
  metrics-protocol: prometheus
`
	for _, test := range []struct {
		name      string
		raw       []byte
		namespace string
		reason    Reason
	}{
		{"wrong ConfigMap name is unbound", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config-defaults\n  namespace: tekton-pipelines\n" + prometheus), "tekton-pipelines", ReasonTektonIdentityUnresolved},
		{"wrong namespace is unbound", tektonConfigMap(prometheus), "other-namespace", ReasonTektonIdentityUnresolved},
		{"missing namespace is unbound", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config-observability\n" + prometheus), "tekton-pipelines", ReasonTektonIdentityUnresolved},
		{"wrong kind is unbound", []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: config-observability\n  namespace: tekton-pipelines\n" + prometheus), "tekton-pipelines", ReasonTektonIdentityUnresolved},
		{"wrong apiVersion is unbound", []byte("apiVersion: v2\nkind: ConfigMap\nmetadata:\n  name: config-observability\n  namespace: tekton-pipelines\n" + prometheus), "tekton-pipelines", ReasonTektonIdentityUnresolved},
		{"templated value is unresolved", tektonConfigMap("data:\n  metrics-protocol: \"{{ .Values.protocol }}\"\n"), "tekton-pipelines", ReasonTektonIdentityUnresolved},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTektonConfigObservability(test.raw, TektonFrom, TektonTo, TektonDistributionOfficial, test.namespace, tektonBool(true), tektonBool(true))
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			if !strings.Contains(string(prepared.CanonicalInputJSON), `"id":"`+TektonIdentityBoundFact+`","state":"unsupported"`) {
				t.Fatalf("identity fact should stay unsupported: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareTektonConfigObservabilityGuardsAreNeverInferred(t *testing.T) {
	raw := tektonConfigMap("data:\n  metrics-protocol: prometheus\n")
	for _, test := range []struct {
		name                    string
		distribution, namespace string
		complete, retain        *bool
		from, to                string
		reason                  Reason
	}{
		{"missing distribution", "", "tekton-pipelines", tektonBool(true), tektonBool(true), TektonFrom, TektonTo, ReasonTektonGuardMissing},
		{"missing namespace declaration", TektonDistributionOfficial, "", tektonBool(true), tektonBool(true), TektonFrom, TektonTo, ReasonTektonGuardMissing},
		{"missing completeness declaration", TektonDistributionOfficial, "tekton-pipelines", nil, tektonBool(true), TektonFrom, TektonTo, ReasonTektonGuardMissing},
		{"missing retention declaration", TektonDistributionOfficial, "tekton-pipelines", tektonBool(true), nil, TektonFrom, TektonTo, ReasonTektonGuardMissing},
		{"unreviewed pair", TektonDistributionOfficial, "tekton-pipelines", tektonBool(true), tektonBool(true), "1.9.1", TektonTo, ReasonTektonPairUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTektonConfigObservability(raw, test.from, test.to, test.distribution, test.namespace, test.complete, test.retain)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			if !strings.Contains(string(prepared.CanonicalInputJSON), `"id":"`+TektonPrometheusFact+`","state":"unsupported"`) {
				t.Fatalf("protocol fact should stay unsupported: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareTektonConfigObservabilityRejectsMalformedInput(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		[]byte(``),
	} {
		if _, err := PrepareTektonConfigObservability(raw, TektonFrom, TektonTo, TektonDistributionOfficial, "tekton-pipelines", tektonBool(true), tektonBool(true)); err == nil {
			t.Fatalf("accepted empty input %q", raw)
		}
	}
	raw := tektonConfigMap("data:\n  metrics-protocol: prometheus\n")
	if _, err := PrepareTektonConfigObservability(raw, TektonFrom, TektonTo, "unreviewed", "tekton-pipelines", tektonBool(true), tektonBool(true)); err == nil {
		t.Fatal("accepted an unregistered distribution token")
	}
	if _, err := PrepareTektonConfigObservability(raw, "1.9", TektonTo, TektonDistributionOfficial, "tekton-pipelines", tektonBool(true), tektonBool(true)); err == nil {
		t.Fatal("accepted a non-canonical version")
	}
	if _, err := PrepareTektonConfigObservability(raw, TektonFrom, TektonTo, TektonDistributionOfficial, " tekton-pipelines ", tektonBool(true), tektonBool(true)); err == nil {
		t.Fatal("accepted a padded namespace declaration")
	}
}
