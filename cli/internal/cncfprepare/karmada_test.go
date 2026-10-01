// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func karmadaResource(t *testing.T, kind string, spec map[string]any, extra map[string]any) []byte {
	t.Helper()
	root := map[string]any{
		"apiVersion": karmadaAPIVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": "private-name", "labels": map[string]any{"private": "canary"}},
		"spec":       spec,
	}
	for key, value := range extra {
		root[key] = value
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func karmadaSpec(value any) map[string]any {
	return map[string]any{"failover": map[string]any{"application": map[string]any{"purgeMode": value}}}
}

func karmadaFacts(t *testing.T, prepared Prepared) []map[string]any {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
		t.Fatal(err)
	}
	items := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)["facts"].([]any)
	result := make([]map[string]any, len(items))
	for i, item := range items {
		result[i] = item.(map[string]any)
	}
	return result
}

func TestPrepareKarmadaOnlyWitnessesLegacyPresence(t *testing.T) {
	for _, tc := range []struct{ name, kind, mode, state, check string }{
		{"policy immediately", "PropagationPolicy", "Immediately", StatePrepared, "BLOCKED"},
		{"policy graciously", "PropagationPolicy", "Graciously", StatePrepared, "BLOCKED"},
		{"cluster immediately", "ClusterPropagationPolicy", "Immediately", StatePrepared, "BLOCKED"},
		{"cluster graciously", "ClusterPropagationPolicy", "Graciously", StatePrepared, "BLOCKED"},
		{"directly unknown", "PropagationPolicy", "Directly", StateUnknown, "UNKNOWN"},
		{"gracefully unknown", "ClusterPropagationPolicy", "Gracefully", StateUnknown, "UNKNOWN"},
		{"never unknown", "PropagationPolicy", "Never", StateUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKarmada(karmadaResource(t, tc.kind, karmadaSpec(tc.mode), nil), KarmadaFrom, KarmadaTo, KarmadaDistributionOfficial, KarmadaAdmissionRequired)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			facts := karmadaFacts(t, prepared)
			if len(facts) != 4 || facts[0]["id"] != KarmadaDistributionFact || facts[1]["id"] != KarmadaSurfaceFact || facts[2]["id"] != KarmadaLegacyFact || facts[3]["id"] != KarmadaAdmissionFact {
				t.Fatalf("facts=%v", facts)
			}
			condition := facts[2]
			if tc.check == "BLOCKED" {
				if condition["state"] != "declared" || condition["boolValue"] != true {
					t.Fatalf("condition=%v", condition)
				}
			} else if condition["state"] != "unsupported" || condition["boolValue"] != nil {
				t.Fatalf("safe singleton derived false: %v", condition)
			}
			got, err := cncfcheck.Check("karmada", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 4, 55, 0, 0, time.UTC))
			if err != nil || len(got.Check.Claims) != 1 || got.Check.Claims[0].Status != tc.check || got.Check.Assessment != "UNKNOWN" {
				t.Fatalf("check=%+v err=%v", got.Check, err)
			}
		})
	}
}

func TestPrepareKarmadaUnknownPathAndGuardStates(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		spec                               map[string]any
		distribution, admission, condition string
		state                              State
	}{
		{"failover absent", map[string]any{}, KarmadaDistributionOfficial, KarmadaAdmissionRequired, "missing", StateUnknown},
		{"application absent", map[string]any{"failover": map[string]any{}}, KarmadaDistributionOfficial, KarmadaAdmissionRequired, "missing", StateUnknown},
		{"purge absent", map[string]any{"failover": map[string]any{"application": map[string]any{}}}, KarmadaDistributionOfficial, KarmadaAdmissionRequired, "missing", StateUnknown},
		{"failover null", map[string]any{"failover": nil}, KarmadaDistributionOfficial, KarmadaAdmissionRequired, "unsupported", StateUnknown},
		{"application null", map[string]any{"failover": map[string]any{"application": nil}}, KarmadaDistributionOfficial, KarmadaAdmissionRequired, "unsupported", StateUnknown},
		{"purge null", karmadaSpec(nil), KarmadaDistributionOfficial, KarmadaAdmissionRequired, "unsupported", StateUnknown},
		{"purge other", karmadaSpec("unknown"), KarmadaDistributionOfficial, KarmadaAdmissionRequired, "unsupported", StateUnknown},
		{"missing distribution", karmadaSpec("Immediately"), "", KarmadaAdmissionRequired, "declared", StateUnknown},
		{"missing admission", karmadaSpec("Immediately"), KarmadaDistributionOfficial, "", "declared", StateUnknown},
		{"custom distribution", karmadaSpec("Immediately"), KarmadaDistributionCustom, KarmadaAdmissionRequired, "declared", StatePrepared},
		{"disabled admission", karmadaSpec("Immediately"), KarmadaDistributionOfficial, KarmadaAdmissionDisabled, "declared", StatePrepared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKarmada(karmadaResource(t, "PropagationPolicy", tc.spec, nil), KarmadaFrom, KarmadaTo, tc.distribution, tc.admission)
			if err != nil {
				t.Fatal(err)
			}
			facts := karmadaFacts(t, prepared)
			if prepared.State != tc.state || facts[2]["state"] != tc.condition {
				t.Fatalf("prepared=%+v facts=%v", prepared, facts)
			}
			got, err := cncfcheck.Check("karmada", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 4, 55, 0, 0, time.UTC))
			if err != nil || got.Check.Claims[0].Status != "UNKNOWN" || got.Check.Assessment != "UNKNOWN" {
				t.Fatalf("check=%+v err=%v", got.Check, err)
			}
		})
	}
}

func TestPrepareKarmadaAcceptsBoundedDiscardedSiblingsAndRejectsRoots(t *testing.T) {
	good := karmadaResource(t, "PropagationPolicy", karmadaSpec("Immediately"), nil)
	var root map[string]any
	if err := json.Unmarshal(good, &root); err != nil {
		t.Fatal(err)
	}
	root["spec"].(map[string]any)["unrelated"] = map[string]any{"null": nil, "items": []any{"private"}}
	root["spec"].(map[string]any)["failover"].(map[string]any)["sibling"] = nil
	root["spec"].(map[string]any)["failover"].(map[string]any)["application"].(map[string]any)["other"] = "private"
	withSiblings, _ := json.Marshal(root)
	prepared, err := PrepareKarmada(withSiblings, KarmadaFrom, KarmadaTo, KarmadaDistributionOfficial, KarmadaAdmissionRequired)
	if err != nil || prepared.State != StatePrepared || bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	for name, raw := range map[string][]byte{
		"root array":       []byte(`[]`),
		"unknown root":     []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","spec":{},"status":{}}`),
		"wrong version":    []byte(`{"apiVersion":"policy.karmada.io/v1","kind":"PropagationPolicy","spec":{}}`),
		"wrong kind":       []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","kind":"List","spec":{}}`),
		"duplicate folded": []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","APIversion":"x","kind":"PropagationPolicy","spec":{}}`),
		"trailing":         []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","spec":{}} {}`),
		"metadata null":    []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","metadata":null,"spec":{}}`),
		"spec null":        []byte(`{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","spec":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := PrepareKarmada(raw, KarmadaFrom, KarmadaTo, KarmadaDistributionOfficial, KarmadaAdmissionRequired)
			if err == nil || len(got.CanonicalInputJSON) != 0 || got.SourceDigest != "" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestPrepareKarmadaOutsidePairAndLegacyNullDecoderCompatibility(t *testing.T) {
	raw := karmadaResource(t, "PropagationPolicy", karmadaSpec("Immediately"), nil)
	prepared, err := PrepareKarmada(raw, "1.19.0", "1.20.0", KarmadaDistributionOfficial, KarmadaAdmissionRequired)
	if err != nil || prepared.State != StateUnknown || karmadaFacts(t, prepared)[2]["state"] != "unsupported" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if _, err := PrepareLinkerd([]byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":{"identities":null}}`), LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired); err == nil {
		t.Fatal("legacy strict decoder accepted null")
	}
}
