// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func argoCDBool(value bool) *bool { return &value }

func argoCDConfigMap(t *testing.T, value any, include bool) []byte {
	t.Helper()
	data := map[string]any{"private-token": "must-not-retain"}
	if include {
		data[argoCDInheritanceConfigurationKey] = value
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "argocd-cm", "namespace": "private-system"},
		"data":     data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func argoCDFacts(t *testing.T, prepared Prepared) []map[string]any {
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

func TestPrepareArgoCDExplicitConfigurationFeedsExistingRule(t *testing.T) {
	for _, tc := range []struct {
		name                string
		value               any
		intent              *bool
		prepareState, check string
	}{
		{"true requires inheritance blocks", "true", argoCDBool(true), StatePrepared, "BLOCKED"},
		{"false preserves v2 predicate", "false", argoCDBool(true), StatePrepared, "PASS"},
		{"true access intent changed", "true", argoCDBool(false), StatePrepared, "UNKNOWN"},
		{"missing intent unknown", "true", nil, StateUnknown, "UNKNOWN"},
		{"missing field unknown", "true", nil, StateUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := argoCDConfigMap(t, tc.value, tc.name != "missing field unknown")
			prepared, err := PrepareArgoCD(raw, ArgoCDFrom, ArgoCDTo, tc.intent)
			if err != nil || prepared.State != tc.prepareState || bytes.Contains(prepared.CanonicalInputJSON, []byte("must-not-retain")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("private-system")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			facts := argoCDFacts(t, prepared)
			if len(facts) != 2 || facts[0]["id"] != ArgoCDInheritanceDisabledFact || facts[1]["id"] != ArgoCDInheritedPermissionsFact {
				t.Fatalf("facts=%v", facts)
			}
			got, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC))
			claims := map[string]struct{ status, reason string }{}
			for _, claim := range got.Check.Claims {
				claims[claim.RuleID] = struct{ status, reason string }{claim.Status, claim.ReasonCode}
			}
			rbac, rbacOK := claims["argo-cd.required-rbac-inheritance.3-0"]
			exclusions, exclusionsOK := claims["argo-cd.resource-exclusions-v2-visibility-preservation.3-0"]
			if err != nil || len(got.Check.Claims) != 2 || !rbacOK || rbac.status != tc.check || !exclusionsOK || exclusions.status != "UNKNOWN" || exclusions.reason != "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW" || got.Check.Assessment != "UNKNOWN" {
				t.Fatalf("check=%+v err=%v", got.Check, err)
			}
			if tc.name == "false preserves v2 predicate" && cncfcheck.ClaimExit(got) != 11 {
				t.Fatalf("generic false-preserves exit=%d", cncfcheck.ClaimExit(got))
			}
		})
	}
}

func TestPrepareArgoCDKeepsAbsentMalformedAndOutsideInputsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		from string
		to   string
	}{
		{"absent data", []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"argocd-cm"}}`), ArgoCDFrom, ArgoCDTo},
		{"non-string value", argoCDConfigMap(t, true, true), ArgoCDFrom, ArgoCDTo},
		{"other spelling", argoCDConfigMap(t, "False", true), ArgoCDFrom, ArgoCDTo},
		{"outside pair", argoCDConfigMap(t, "true", true), "3.0.0", "3.1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareArgoCD(tc.raw, tc.from, tc.to, argoCDBool(true))
			if err != nil || prepared.State != StateUnknown {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			facts := argoCDFacts(t, prepared)
			if facts[0]["state"] == "declared" {
				t.Fatalf("configuration unexpectedly declared: %v", facts[0])
			}
			got, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC))
			if err != nil || got.Check.Claims[0].Status != "UNKNOWN" || got.Check.Assessment != "UNKNOWN" {
				t.Fatalf("check=%+v err=%v", got.Check, err)
			}
		})
	}
}

func TestPrepareArgoCDRejectsWrongResourceAndDuplicateKeys(t *testing.T) {
	for name, raw := range map[string][]byte{
		"wrong kind":       []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"argocd-cm"}}`),
		"wrong name":       []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"other"}}`),
		"wrong version":    []byte(`{"apiVersion":"v2","kind":"ConfigMap","metadata":{"name":"argocd-cm"}}`),
		"unknown root":     []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"argocd-cm"},"binaryData":{}}`),
		"duplicate folded": []byte(`{"apiVersion":"v1","APIversion":"v1","kind":"ConfigMap","metadata":{"name":"argocd-cm"}}`),
		"trailing":         []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"argocd-cm"}} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := PrepareArgoCD(raw, ArgoCDFrom, ArgoCDTo, argoCDBool(true))
			if err == nil || got.CanonicalInputJSON != nil || got.SourceDigest != "" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}
