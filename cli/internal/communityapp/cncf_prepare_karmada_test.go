// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func karmadaPreparationResource(t *testing.T, kind, mode, canary string) []byte {
	t.Helper()
	spec := map[string]any{"failover": map[string]any{"application": map[string]any{}}}
	if mode != "" {
		spec["failover"].(map[string]any)["application"].(map[string]any)["purgeMode"] = mode
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "policy.karmada.io/v1alpha1", "kind": kind,
		"metadata": map[string]any{"name": canary, "labels": map[string]any{"private": canary}},
		"spec":     spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func karmadaPreparationArgs(path string) []string {
	return []string{"prepare", "cncf", "--project", "karmada", "--input", path, "--from", "1.18.3", "--to", "1.19.0", "--distribution", "official_upstream", "--target-policy-crd-admission", "required"}
}

func TestKarmadaPreparationFeedsOnlyBlockerWitnesses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, mode string
		prepare, check   int
		status           string
	}{
		{"policy immediately", "PropagationPolicy", "Immediately", ExitOK, ExitBlocked, "BLOCKED"},
		{"policy graciously", "PropagationPolicy", "Graciously", ExitOK, ExitBlocked, "BLOCKED"},
		{"cluster immediately", "ClusterPropagationPolicy", "Immediately", ExitOK, ExitBlocked, "BLOCKED"},
		{"cluster graciously", "ClusterPropagationPolicy", "Graciously", ExitOK, ExitBlocked, "BLOCKED"},
		{"directly unknown", "PropagationPolicy", "Directly", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"gracefully unknown", "ClusterPropagationPolicy", "Gracefully", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"never unknown", "PropagationPolicy", "Never", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"missing unknown", "PropagationPolicy", "", ExitUnknown, ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := karmadaPreparationResource(t, tc.kind, tc.mode, "private-karmada-canary")
			path := writeCNCFFile(t, "karmada.json", raw, 0o600)
			code, input, stderr := runCNCFCLI(t, append(karmadaPreparationArgs(path), "--format", "input", "--input-digest", cncfDigest(raw))...)
			if code != tc.prepare || stderr != "" || !strings.HasSuffix(input, "\n") || strings.HasSuffix(input, "\n\n") || strings.Contains(input, "private-karmada-canary") || (tc.status == "UNKNOWN" && strings.Contains(input, `"boolValue":false`)) {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "karmada", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-09T05:00:00Z", "--format", "json")
			if code != tc.check || stderr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, "private-karmada-canary") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestKarmadaPreparationFlagsAndInputStayPrivate(t *testing.T) {
	t.Parallel()
	path := "/private/karmada-canary.json"
	for _, args := range [][]string{
		append(karmadaPreparationArgs(path), "--container", "selected"),
		append(karmadaPreparationArgs(path), "--schema-validation", "required"),
		append(karmadaPreparationArgs(path), "--distribution="),
		append(karmadaPreparationArgs(path), "--target-policy-crd-admission="),
		append(karmadaPreparationArgs(path), "--distribution", "bad"),
		append(karmadaPreparationArgs(path), "--target-policy-crd-admission", "bad"),
		append(karmadaPreparationArgs(path), "--distribution", "official_upstream", "--distribution", "custom_build"),
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || !strings.HasPrefix(stderr, "prufyx: ") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	raw := karmadaPreparationResource(t, "PropagationPolicy", "Immediately", "private-error-canary")
	private := writeCNCFFile(t, "karmada-private.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, append(karmadaPreparationArgs(private), "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" || strings.Contains(stderr, private) || strings.Contains(stderr, "private-error-canary") {
		t.Fatalf("integrity code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKarmadaPreparationJSONHumanAndWriteFailures(t *testing.T) {
	t.Parallel()
	raw := karmadaPreparationResource(t, "PropagationPolicy", "Immediately", "private-human-karmada")
	path := writeCNCFFile(t, "karmada.json", raw, 0o600)
	for _, format := range []string{"json", "human"} {
		code, stdout, stderr := runCNCFCLI(t, append(karmadaPreparationArgs(path), "--format", format)...)
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, "CRD_SCHEMA_VALIDATION_NOT_PERFORMED") || strings.Contains(stdout, "private-human-karmada") {
			t.Fatalf("format=%s code=%d stderr=%q stdout=%q", format, code, stderr, stdout)
		}
	}
	for _, format := range []string{"human", "json", "input"} {
		var stderr bytes.Buffer
		code := Run(context.TODO(), append(karmadaPreparationArgs(path), "--format", format), failedPreparationWriter{}, &stderr, "test")
		if code != ExitIntegrity || stderr.String() != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
			t.Fatalf("format=%s code=%d stderr=%q", format, code, stderr.String())
		}
	}
}
