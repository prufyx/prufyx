// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func argoCDLatestSecret(url, forceHTTP, insecure string) []byte {
	data := map[string]any{"type": "helm", "enableOCI": "true", "url": url, "username": "private-user", "password": "private-secret"}
	if forceHTTP != "" {
		data["insecureOCIForceHttp"] = forceHTTP
	}
	if insecure != "" {
		data["insecure"] = insecure
	}
	raw, _ := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata":   map[string]any{"name": "private-repository", "labels": map[string]any{"argocd.argoproj.io/secret-type": "repository"}},
		"stringData": data,
	})
	return raw
}

func mutateArgoCDLatestSecret(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPrepareArgoCDLatestFiveOriginMatrix(t *testing.T) {
	now := time.Date(2026, 9, 12, 11, 30, 0, 0, time.UTC)
	resolved, plainHTTP := true, true
	for _, from := range argoCDLatestOrigins {
		for _, tc := range []struct {
			name, url, forceHTTP, insecure, status string
		}{
			{"missing-force", "private.invalid/charts", "", "", "BLOCKED"},
			{"force-enabled", "private.invalid/charts", "true", "false", "PASS"},
			{"conflicting-flags", "private.invalid/charts", "true", "true", "BLOCKED"},
			{"force-disabled", "private.invalid/charts", "false", "false", "BLOCKED"},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				prepared, err := PrepareArgoCDLatestRepository(argoCDLatestSecret(tc.url, tc.forceHTTP, tc.insecure), from, ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, &resolved, &plainHTTP)
				if err != nil || prepared.State != StatePrepared || bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) {
					t.Fatalf("prepared=%+v err=%v", prepared, err)
				}
				report, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, now)
				if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != tc.status || report.Check.Assessment != "UNKNOWN" {
					t.Fatalf("report=%+v err=%v", report.Check, err)
				}
			})
		}
	}
}

func TestPrepareArgoCDLatestUnknownAndInvalidInputs(t *testing.T) {
	valid := argoCDLatestSecret("private.invalid/charts", "", "")
	resolved, plainHTTP := true, true
	nativeOCI := mutateArgoCDLatestSecret(t, valid, func(root map[string]any) {
		root["stringData"].(map[string]any)["type"] = "oci"
	})
	unresolvedData := mutateArgoCDLatestSecret(t, valid, func(root map[string]any) {
		root["data"] = map[string]any{"url": "cHJpdmF0ZS5pbnZhbGlk"}
	})
	badBool := mutateArgoCDLatestSecret(t, valid, func(root map[string]any) {
		root["stringData"].(map[string]any)["insecureOCIForceHttp"] = "TRUE"
	})
	for _, tc := range []struct {
		name, from, to, distribution string
		raw                          []byte
	}{
		{"missing-guard", "3.4.8", ArgoCDLatestTo, "", valid},
		{"custom-build", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionCustom, valid},
		{"wrong-origin", "3.4.7", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, valid},
		{"wrong-target", "3.4.8", "3.5.1", ArgoCDLatestDistributionOfficial, valid},
		{"git-secret", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private"},"stringData":{"type":"git","url":"http://private.invalid"}}`)},
		{"native-oci-needs-separate-context", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, nativeOCI},
		{"unresolved-data", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, unresolvedData},
		{"unknown-url", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, argoCDLatestSecret("oci://private.invalid", "true", "false")},
		{"bad-bool", "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, badBool},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareArgoCDLatestRepository(tc.raw, tc.from, tc.to, tc.distribution, &resolved, &plainHTTP)
			if err != nil || prepared.State != StateUnknown || bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			report, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 11, 30, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("report=%+v err=%v", report.Check, err)
			}
			for _, claim := range report.Check.Claims {
				if claim.Status != "UNKNOWN" {
					t.Fatalf("out-of-scope input emitted %s: %+v", claim.Status, report.Check)
				}
			}
		})
	}
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"v1","apiVersion":"v1"}`),
		[]byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"x"},"stringData":null}`),
		[]byte(`{"apiVersion":"v1","kind":"Secret"} {}`),
	} {
		if prepared, err := PrepareArgoCDLatestRepository(raw, "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, &resolved, &plainHTTP); err == nil || len(prepared.CanonicalInputJSON) != 0 {
			t.Fatalf("invalid input admitted: prepared=%+v err=%v", prepared, err)
		}
	}
	for _, repositoryURL := range []string{"http://private.invalid/charts", "HTTPS://private.invalid/charts"} {
		prepared, err := PrepareArgoCDLatestRepository(argoCDLatestSecret(repositoryURL, "true", "false"), "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, &resolved, &plainHTTP)
		if err != nil || prepared.State != StateUnknown {
			t.Fatalf("protocol-prefixed URL %q admitted: prepared=%+v err=%v", repositoryURL, prepared, err)
		}
	}
	for _, guards := range []struct {
		name                      string
		settings, plainHTTPIntent *bool
	}{
		{"settings-missing", nil, &plainHTTP},
		{"plain-http-missing", &resolved, nil},
	} {
		prepared, err := PrepareArgoCDLatestRepository(valid, "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, guards.settings, guards.plainHTTPIntent)
		if err != nil || prepared.State != StateUnknown {
			t.Fatalf("%s guard admitted: prepared=%+v err=%v", guards.name, prepared, err)
		}
		report, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 11, 30, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		for _, claim := range report.Check.Claims {
			if claim.Status != "UNKNOWN" {
				t.Fatalf("%s guard emitted %s", guards.name, claim.Status)
			}
		}
	}
	plainHTTP = false
	prepared, err := PrepareArgoCDLatestRepository(valid, "3.4.8", ArgoCDLatestTo, ArgoCDLatestDistributionOfficial, &resolved, &plainHTTP)
	if err != nil || prepared.State != StateUnknown {
		t.Fatalf("non-plain-HTTP declaration admitted: prepared=%+v err=%v", prepared, err)
	}
	report, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 11, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range report.Check.Claims {
		if claim.Status != "UNKNOWN" {
			t.Fatalf("non-plain-HTTP declaration emitted %s", claim.Status)
		}
	}
}
