// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeArgoCDOperatorConfig(t *testing.T, path, setting string, include bool) []byte {
	t.Helper()
	data := map[string]any{"unrelated.private.example": "must-not-cross-output"}
	if include {
		data["server.rbac.disableApplicationFineGrainedRBACInheritance"] = setting
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": "argocd-cm", "namespace": "private-argo"},
		"data":       data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func argoCDRawReviewArgs(path, from, to string, intent *string, format string) []string {
	args := []string{
		"check", "cncf", "--project", "argo-cd", "--config-map", path,
		"--from", from, "--to", to, "--now", "2026-09-10T15:28:00Z", "--format", format,
	}
	if intent != nil {
		args = append(args, "--requires-inherited-application-permissions", *intent)
	}
	return args
}

func TestArgoCDRawConfigReviewSupportsEditAndRepeatWithoutIntermediateFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator-chosen-name.json")
	writeArgoCDOperatorConfig(t, path, "true", true)
	intent := "true"
	args := argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human")

	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "setting server.rbac.disableApplicationFineGrainedRBACInheritance: true (read from ConfigMap)") || !strings.Contains(before, "requires inherited application update/delete permissions: true (operator-declared)") || !strings.Contains(before, "scoped result: BLOCKED (REVIEWED_SOURCE_CONSTRAINT)") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "raw ConfigMap digest: sha256:") || !strings.Contains(before, "prepared input digest: sha256:") || !strings.Contains(before, "evaluated at: 2026-09-10T15:28:00Z") || !strings.Contains(before, "knowledge: embedded revision ") || !strings.Contains(before, "knowledge pack digest: sha256:") || !strings.Contains(before, "docs/operator-manual/upgrading/2.14-3.0.md") || !strings.Contains(before, "lines 12-24") || !strings.Contains(before, "permission impact: false restores v2 inheritance behavior") {
		t.Fatalf("before code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertArgoCDRawReviewRedacted(t, before, path)

	writeArgoCDOperatorConfig(t, path, "false", true)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "setting server.rbac.disableApplicationFineGrainedRBACInheritance: false (read from ConfigMap)") || !strings.Contains(after, "scoped result: PASS (REVIEWED_SOURCE_CONSTRAINT)") || !strings.Contains(after, "aggregate: UNKNOWN") {
		t.Fatalf("after code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertArgoCDRawReviewRedacted(t, after, path)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("raw review persisted intermediate files: entries=%v err=%v", entries, err)
	}
}

func TestArgoCDRawConfigReviewExplainsUnknownBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argocd-cm.json")
	trueIntent, falseIntent := "true", "false"
	tests := []struct {
		name, setting, from, to string
		include                 bool
		intent                  *string
		want                    []string
		forbid                  []string
	}{
		{
			name: "missing intent asks the permission question", setting: "true", include: true, from: "2.14.0", to: "3.0.0",
			want:   []string{"scoped result: UNKNOWN (RULE_APPLICABILITY_FACT_UNAVAILABLE)", "decision needed: do managed resources need to inherit application-level update/delete permissions?", "--requires-inherited-application-permissions true or false"},
			forbid: []string{"component.argo_cd.requires_inherited_application_permissions"},
		},
		{
			name: "explicit false intent does not recommend a change", setting: "true", include: true, from: "2.14.0", to: "3.0.0", intent: &falseIntent,
			want:   []string{"requires inherited application update/delete permissions: false (operator-declared)", "scoped result: UNKNOWN (RULE_APPLICABILITY_NOT_MATCHED)", "do not change the setting based on this UNKNOWN result"},
			forbid: []string{"permission impact:"},
		},
		{
			name: "missing setting remains unknown", setting: "true", include: false, from: "2.14.0", to: "3.0.0", intent: &trueIntent,
			want: []string{"setting server.rbac.disableApplicationFineGrainedRBACInheritance: missing", "scoped result: UNKNOWN (RULE_FACT_UNAVAILABLE)", "provide the exact string true or false"},
		},
		{
			name: "malformed setting remains unknown", setting: "False", include: true, from: "2.14.0", to: "3.0.0", intent: &trueIntent,
			want: []string{"setting server.rbac.disableApplicationFineGrainedRBACInheritance: unsupported", "scoped result: UNKNOWN (RULE_FACT_UNAVAILABLE)", "provide the exact string true or false"},
		},
		{
			name: "wrong pair remains unknown", setting: "true", include: true, from: "2.15.0", to: "3.0.0", intent: &trueIntent,
			want:   []string{"scoped result: UNKNOWN (RULE_TRANSITION_NOT_REVIEWED)", "reviewed scope pkg:github/argoproj/argo-cd 2.14.0 -> 3.0.0"},
			forbid: []string{"permission impact:"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeArgoCDOperatorConfig(t, path, tc.setting, tc.include)
			code, stdout, stderr := runCNCFCLI(t, argoCDRawReviewArgs(path, tc.from, tc.to, tc.intent, "human")...)
			if code != ExitUnknown || stderr != "" {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, stdout)
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout, want) {
					t.Fatalf("missing %q in %s", want, stdout)
				}
			}
			for _, forbidden := range tc.forbid {
				if strings.Contains(stdout, forbidden) {
					t.Fatalf("unexpected %q in %s", forbidden, stdout)
				}
			}
			assertArgoCDRawReviewRedacted(t, stdout, path)
		})
	}
}

func TestArgoCDRawConfigReviewPreservesJSONReportAndRejectsMixedModes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argocd-cm.json")
	raw := writeArgoCDOperatorConfig(t, path, "true", true)
	intent := "true"
	code, stdout, stderr := runCNCFCLI(t, argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "json")...)
	var report map[string]any
	if code != ExitBlocked || stderr != "" || json.Unmarshal([]byte(stdout), &report) != nil || report["schema"] != "prufyx.io/cncf-source-check/v1alpha1" || report["project"] != "argo-cd" {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, stdout)
	}
	assertArgoCDRawReviewRedacted(t, stdout, path)
	matchingDigestArgs := append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "json"), "--config-map-digest", digestCommunityBytes(raw))
	matchingCode, matchingOutput, matchingStderr := runCNCFCLI(t, matchingDigestArgs...)
	if matchingCode != ExitBlocked || matchingStderr != "" || matchingOutput != stdout {
		t.Fatalf("matching digest code=%d stderr=%q same-report=%t", matchingCode, matchingStderr, matchingOutput == stdout)
	}

	bad := [][]string{
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--input", path),
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--input-digest", digestCommunityBytes(raw)),
		{"check", "cncf", "--project", "etcd", "--config-map", path, "--from", "2.14.0", "--to", "3.0.0", "--now", "2026-09-10T15:28:00Z"},
		{"check", "cncf", "--project", "argo-cd", "--input", path, "--now", "2026-09-10T15:28:00Z", "--from", "2.14.0"},
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--knowledge-db", dir),
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--knowledge-revision", "7"),
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--knowledge-bundle-digest", digestCommunityBytes(raw)),
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--knowledge-trust-receipt-digest", digestCommunityBytes(raw)),
		append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--replay-report", path),
	}
	for _, args := range bad {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, path) || strings.Contains(stderr, "must-not-cross-output") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	args := append(argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human"), "--config-map-digest", digestCommunityBytes([]byte("different")))
	code, stdout, stderr = runCNCFCLI(t, args...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" || strings.Contains(stderr, path) {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestArgoCDRawConfigReviewRequiresCanonicalExplicitTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argocd-cm.json")
	writeArgoCDOperatorConfig(t, path, "true", true)
	intent := "true"
	for _, now := range []string{"", "2026-09-10T15:28:00+00:00", "2026-09-10T15:28:00.1Z", "not-a-time"} {
		args := argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "human")
		for index := 0; index < len(args)-1; index++ {
			if args[index] == "--now" {
				args[index+1] = now
				break
			}
		}
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("now=%q code=%d stdout=%q stderr=%q", now, code, stdout, stderr)
		}
	}
}

func assertArgoCDRawReviewRedacted(t *testing.T, output, path string) {
	t.Helper()
	for _, forbidden := range []string{path, "private-argo", "must-not-cross-output", `"apiVersion"`, `"data"`} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("private or internal input crossed output boundary: %q in %s", forbidden, output)
		}
	}
}

func TestArgoCDRawConfigReviewDoesNotChangeExistingCanonicalMode(t *testing.T) {
	raw := argoCDPreparationResource(t, "true", true)
	path := writeCNCFFile(t, "argocd-cm.json", raw, 0o600)
	preparedCode, input, stderr := runCNCFCLI(t, append(argoCDPreparationArgs(path), "--requires-inherited-application-permissions", "true", "--format", "input")...)
	if preparedCode != ExitOK || stderr != "" {
		t.Fatalf("prepare code=%d stderr=%q", preparedCode, stderr)
	}
	prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
	args := []string{"check", "cncf", "--project", "argo-cd", "--input", prepared, "--now", "2026-09-10T15:28:00Z", "--format", "json"}
	code1, stdout1, stderr1 := runCNCFCLI(t, args...)
	code2, stdout2, stderr2 := runCNCFCLI(t, args...)
	if code1 != ExitBlocked || code2 != code1 || stderr1 != "" || stderr2 != "" || stdout1 != stdout2 || stdout1 == "" {
		t.Fatalf("canonical mode changed: %d/%d %q/%q equal=%t", code1, code2, stderr1, stderr2, stdout1 == stdout2)
	}
}

func TestArgoCDRawConfigReviewKeepsOldRuleSealedAtGenericClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argocd-cm.json")
	writeArgoCDOperatorConfig(t, path, "false", true)
	intent := "true"
	args := argoCDRawReviewArgs(path, "2.14.0", "3.0.0", &intent, "json")
	for i := range args {
		if args[i] == "--now" {
			args[i+1] = "2026-09-09T06:00:00Z"
			break
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	var report struct {
		RequestedRuleID string `json:"requestedRuleId"`
		SelectedRuleID  string `json:"selectedRuleId"`
		Check           struct {
			Claims []struct{ RuleID, Status string } `json:"claims"`
		} `json:"check"`
	}
	if code != ExitOK || stderr != "" || json.Unmarshal([]byte(stdout), &report) != nil || report.RequestedRuleID != "argo-cd.required-rbac-inheritance.3-0" || report.SelectedRuleID != report.RequestedRuleID || len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != report.RequestedRuleID || report.Check.Claims[0].Status != "PASS" {
		t.Fatalf("code=%d stderr=%q report=%s", code, stderr, stdout)
	}
	assertArgoCDRawReviewRedacted(t, stdout, path)
}
