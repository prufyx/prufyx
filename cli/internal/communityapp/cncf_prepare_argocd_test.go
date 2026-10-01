// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func argoCDPreparationResource(t *testing.T, value any, include bool) []byte {
	t.Helper()
	data := map[string]any{"private": "argo-canary-never-retain"}
	if include {
		data["server.rbac.disableApplicationFineGrainedRBACInheritance"] = value
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "argocd-cm", "namespace": "private-argo"},
		"data":     data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func argoCDPreparationArgs(path string) []string {
	return []string{"prepare", "cncf", "--project", "argo-cd", "--input", path, "--from", "2.14.0", "--to", "3.0.0"}
}

func TestArgoCDPreparationFeedsScopedExistingRule(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		value                  any
		include, requires      bool
		prepareCode, checkCode int
		status                 string
	}{
		{"true plus required inheritance blocks", "true", true, true, ExitOK, ExitBlocked, "BLOCKED"},
		{"false preserves scoped predicate", "false", true, true, ExitOK, ExitUnknown, "PASS"},
		{"field absent remains unknown", "true", false, true, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"intent omitted remains unknown", "true", true, false, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"malformed setting remains unknown", "False", true, true, ExitUnknown, ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := argoCDPreparationResource(t, tc.value, tc.include)
			path := writeCNCFFile(t, "argocd-cm.json", raw, 0o600)
			args := argoCDPreparationArgs(path)
			if tc.requires {
				args = append(args, "--requires-inherited-application-permissions", "true")
			}
			code, input, stderr := runCNCFCLI(t, append(args, "--format", "input", "--input-digest", cncfDigest(raw))...)
			if code != tc.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, "argo-canary-never-retain") || strings.Contains(input, "private-argo") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "argo-cd", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-09T06:00:00Z", "--format", "json")
			if code != tc.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, "argo-canary-never-retain") || strings.Contains(report, "private-argo") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
			if tc.name == "false preserves scoped predicate" {
				var document struct {
					Check struct {
						Claims []struct{ RuleID, Status, ReasonCode string } `json:"claims"`
					} `json:"check"`
				}
				if json.Unmarshal([]byte(report), &document) != nil || len(document.Check.Claims) != 2 {
					t.Fatalf("generic Argo report=%s", report)
				}
				claims := map[string]struct{ status, reason string }{}
				for _, claim := range document.Check.Claims {
					claims[claim.RuleID] = struct{ status, reason string }{claim.Status, claim.ReasonCode}
				}
				if claims["argo-cd.required-rbac-inheritance.3-0"].status != "PASS" || claims["argo-cd.resource-exclusions-v2-visibility-preservation.3-0"].status != "UNKNOWN" || claims["argo-cd.resource-exclusions-v2-visibility-preservation.3-0"].reason != "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW" {
					t.Fatalf("generic Argo claims=%v", claims)
				}
			}
		})
	}
}

func TestArgoCDPreparationRejectsUnsafeFlagsAndBadPin(t *testing.T) {
	raw := argoCDPreparationResource(t, "true", true)
	path := writeCNCFFile(t, "argocd-cm.json", raw, 0o600)
	for _, extra := range [][]string{
		{"--requires-inherited-application-permissions", "yes"},
		{"--container", "private"},
		{"--distribution", "official_upstream"},
		{"--schema-validation", "required"},
		{"--target-policy-crd-admission", "required"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(argoCDPreparationArgs(path), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private") {
			t.Fatalf("extra=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, append(argoCDPreparationArgs(path), "--requires-inherited-application-permissions", "true", "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("bad pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, format := range []string{"human", "json", "input"} {
		var stderr bytes.Buffer
		code := Run(context.TODO(), append(append(argoCDPreparationArgs(path), "--requires-inherited-application-permissions", "true", "--format", format), []string{}...), failedPreparationWriter{}, &stderr, "test")
		if code != ExitIntegrity || stderr.String() != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
			t.Fatalf("format=%s output failure code=%d stderr=%q", format, code, stderr.String())
		}
	}
}

func TestArgoCDLatestPreparationFiveOriginsAndPrivacy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "argocd-35-plain-http-repository-secret.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := writeCNCFFile(t, "private-argocd-repository.json", raw, 0o600)
	for _, from := range []string{"3.0.23", "3.1.16", "3.2.12", "3.3.14", "3.4.8"} {
		args := []string{"prepare", "cncf", "--project", "argo-cd", "--input", path, "--from", from, "--to", "3.5.2", "--distribution", "official_upstream", "--repository-settings-resolved", "true", "--repository-uses-plain-http", "true", "--format", "input"}
		code, input, stderr := runCNCFCLI(t, args...)
		if code != ExitOK || stderr != "" || !json.Valid([]byte(input)) {
			t.Fatalf("from=%s prepare code=%d stderr=%q input=%q", from, code, stderr, input)
		}
		for _, private := range []string{path, "synthetic-helm-repository", "charts.example.invalid"} {
			if strings.Contains(input+stderr, private) {
				t.Fatalf("private value leaked: %q", private)
			}
		}
		inputPath := writeCNCFFile(t, "prepared-"+strings.ReplaceAll(from, ".", "-")+".json", []byte(input), 0o600)
		code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "argo-cd", "--input", inputPath, "--now", "2026-09-12T11:30:00Z", "--format", "json")
		if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) || strings.Contains(report, "private") {
			t.Fatalf("from=%s check code=%d stderr=%q report=%s", from, code, stderr, report)
		}
	}
}

func TestArgoCDLatestPreparationGuardAndRoutingPreflight(t *testing.T) {
	raw := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"private.invalid/charts","insecureOCIForceHttp":"true"}}`)
	path := writeCNCFFile(t, "private-argocd-repository.json", raw, 0o600)
	base := []string{"prepare", "cncf", "--project", "argo-cd", "--input", path, "--from", "3.4.8", "--to", "3.5.2"}
	for _, extra := range [][]string{
		{"--distribution", "official_upstream"},
		{"--repository-settings-resolved", "true"},
		{"--distribution", "custom_build", "--repository-settings-resolved", "true"},
		{"--distribution", "official_upstream", "--repository-settings-resolved", "false"},
		{"--distribution", "official_upstream", "--repository-settings-resolved", "true", "--repository-uses-plain-http", "false"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, base...), extra...)...)
		if code != ExitUnknown || stderr != "" || strings.Contains(stdout, "private-repository") || strings.Contains(stdout, "private.invalid") {
			t.Fatalf("extra=%v code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	for _, extra := range [][]string{
		{"--requires-inherited-application-permissions", "true"},
		{"--distribution", "official_upstream", "--repository-settings-resolved", "maybe"},
		{"--distribution", "official_upstream", "--repository-settings-resolved", "true", "--repository-uses-plain-http", "maybe"},
		{"--distribution", "official_upstream", "--repository-settings-resolved", "true", "--container", "private"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, base...), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private") {
			t.Fatalf("extra=%v code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
}
