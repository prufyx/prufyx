// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKnativeOperatorService(t *testing.T, path, containerPort, probePort string) []byte {
	t.Helper()
	container := map[string]any{
		"name":         "user-container",
		"image":        "private.registry.invalid/operator-image:canary",
		"ports":        []any{map[string]any{"name": containerPort, "containerPort": 8080}},
		"startupProbe": map[string]any{"httpGet": map[string]any{"path": "/private-health", "port": probePort}},
		"env":          []any{map[string]any{"name": "PRIVATE_TOKEN_NAME", "value": "PRIVATE_TOKEN_VALUE"}},
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "serving.knative.dev/v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name": "private-knative-name", "namespace": "private-knative-namespace",
			"annotations": map[string]any{"private.example/canary": "must-not-cross-output"},
		},
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"annotations": map[string]any{"autoscaling.knative.dev/min-scale": "1"}},
			"spec":     map[string]any{"containers": []any{container}},
		}},
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

func knativeRawReviewArgs(path, from, to, format string) []string {
	return []string{
		"check", "cncf", "--project", "knative", "--service", path,
		"--from", from, "--to", to, "--now", "2026-09-10T17:00:00Z", "--format", format,
	}
}

func TestKnativeRawServiceReviewSupportsEditAndRepeatWithoutIntermediateFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator-chosen-service.json")
	writeKnativeOperatorService(t, path, "http1", "h2c")
	args := knativeRawReviewArgs(path, "1.22.0", "1.23.0", "human")

	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "Knative Serving Service upgrade review") || !strings.Contains(before, "ports[0].name versus spec.template.spec.containers[0].startupProbe.httpGet.port: mismatch (read from Service)") || !strings.Contains(before, "scoped result: BLOCKED (REVIEWED_SOURCE_CONSTRAINT)") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "raw Service digest: sha256:") || !strings.Contains(before, "prepared input digest: sha256:") || !strings.Contains(before, "evaluated at: 2026-09-10T17:00:00Z") || !strings.Contains(before, "k8s_validation.go") || !strings.Contains(before, "lines 875-893") || !strings.Contains(before, "set spec.template.spec.containers[0].startupProbe.httpGet.port to the same supported name") || !strings.Contains(before, "other admission rules") {
		t.Fatalf("before code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertKnativeRawReviewRedacted(t, before, path)

	writeKnativeOperatorService(t, path, "http1", "http1")
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "startupProbe.httpGet.port: match (read from Service)") || !strings.Contains(after, "scoped result: PASS (REVIEWED_SOURCE_CONSTRAINT)") || !strings.Contains(after, "aggregate: UNKNOWN") {
		t.Fatalf("after code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertKnativeRawReviewRedacted(t, after, path)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("raw review persisted intermediate files: entries=%v err=%v", entries, err)
	}
}

func TestKnativeRawServiceReviewPreservesUnknownBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.json")
	tests := []struct {
		name, from, to string
		write          func()
		want           []string
	}{
		{"wrong pair", "1.22.1", "1.23.0", func() { writeKnativeOperatorService(t, path, "http1", "h2c") }, []string{"UNKNOWN (RULE_TRANSITION_NOT_REVIEWED)", "reviewed scope pkg:github/knative/serving 1.22.0 -> 1.23.0"}},
		{"wrong resource", "1.22.0", "1.23.0", func() {
			writeCNCFFileAt(t, path, []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"private-knative-name"}}`))
		}, []string{"UNKNOWN (RULE_FACT_UNAVAILABLE)", "unsupported", "outside the reviewed named HTTP startup-probe port condition", "Do not add a probe or reshape the Service only to obtain a Prufyx result"}},
		{"numeric probe", "1.22.0", "1.23.0", func() {
			raw := writeKnativeOperatorService(t, path, "http1", "h2c")
			var document map[string]any
			if json.Unmarshal(raw, &document) != nil {
				t.Fatal("decode fixture")
			}
			container := document["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			container["startupProbe"].(map[string]any)["httpGet"].(map[string]any)["port"] = 8080
			mutated, _ := json.Marshal(document)
			writeCNCFFileAt(t, path, mutated)
		}, []string{"UNKNOWN (RULE_FACT_UNAVAILABLE)", "unsupported"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.write()
			code, stdout, stderr := runCNCFCLI(t, knativeRawReviewArgs(path, tc.from, tc.to, "human")...)
			if code != ExitUnknown || stderr != "" {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, stdout)
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout, want) {
					t.Fatalf("missing %q in %s", want, stdout)
				}
			}
			assertKnativeRawReviewRedacted(t, stdout, path)
		})
	}
}

func TestKnativeRawServiceReviewJSONDigestAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.json")
	raw := writeKnativeOperatorService(t, path, "h2c", "http1")
	args := knativeRawReviewArgs(path, "1.22.0", "1.23.0", "json")
	code, stdout, stderr := runCNCFCLI(t, args...)
	var report map[string]any
	if code != ExitBlocked || stderr != "" || json.Unmarshal([]byte(stdout), &report) != nil || report["schema"] != "prufyx.io/cncf-source-check/v1alpha1" || report["project"] != "knative" {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, stdout)
	}
	assertKnativeRawReviewRedacted(t, stdout, path)
	matching := append(args, "--service-digest", digestCommunityBytes(raw))
	matchingCode, matchingOutput, matchingStderr := runCNCFCLI(t, matching...)
	if matchingCode != code || matchingStderr != "" || matchingOutput != stdout {
		t.Fatalf("matching digest code=%d stderr=%q same=%t", matchingCode, matchingStderr, matchingOutput == stdout)
	}

	bad := [][]string{
		append(args, "--input", path),
		append(args, "--input-digest", digestCommunityBytes(raw)),
		append(args, "--config-map", path),
		append(args, "--requires-inherited-application-permissions", "true"),
		append(args, "--knowledge-db", dir),
		append(args, "--knowledge-revision", "7"),
		append(args, "--knowledge-bundle-digest", digestCommunityBytes(raw)),
		append(args, "--knowledge-trust-receipt-digest", digestCommunityBytes(raw)),
		append(args, "--replay-report", path),
		{"check", "cncf", "--project", "argo-cd", "--service", path, "--from", "1.22.0", "--to", "1.23.0", "--now", "2026-09-10T17:00:00Z"},
	}
	for _, invalid := range bad {
		code, stdout, stderr := runCNCFCLI(t, invalid...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, path) || strings.Contains(stderr, "PRIVATE_TOKEN") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", invalid, code, stdout, stderr)
		}
	}
	badDigest := append(args, "--service-digest", digestCommunityBytes([]byte("different")))
	code, stdout, stderr = runCNCFCLI(t, badDigest...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("bad digest code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, now := range []string{"", "2026-09-10T17:00:00+00:00", "2026-09-10T17:00:00.1Z", "not-a-time"} {
		invalid := append([]string(nil), args...)
		for index := range invalid {
			if invalid[index] == "--now" {
				invalid[index+1] = now
				break
			}
		}
		code, stdout, stderr := runCNCFCLI(t, invalid...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("now=%q code=%d stdout=%q stderr=%q", now, code, stdout, stderr)
		}
	}
}

func writeCNCFFileAt(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertKnativeRawReviewRedacted(t *testing.T, output, path string) {
	t.Helper()
	for _, forbidden := range []string{path, "private-knative", "private.registry", "must-not-cross-output", "PRIVATE_TOKEN", "/private-health", `"apiVersion"`, `"spec"`} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("private or raw Service data crossed output boundary: %q in %s", forbidden, output)
		}
	}
}
