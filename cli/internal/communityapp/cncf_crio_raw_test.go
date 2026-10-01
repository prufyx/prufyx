// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func crioRawArgs(path, operation, format string) []string {
	args := []string{"check", "cncf", "--project", "cri-o", "--image-status-request", path, "--from", "1.34.0", "--to", "1.35.0", "--now", "2026-09-11T03:00:00Z", "--format", format}
	if operation != "" {
		args = append(args, "--artifact-operation", operation)
	}
	return args
}

func TestCRIOArtifactNameRawEditAndRepeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image-status-request.json")
	shortRaw := []byte(`{"image":{"image":"private-repository/widget:v1"},"auth":{"password":"PRIVATE_CRIO"}}`)
	writeCNCFFileAt(t, path, shortRaw)
	// The embedded rule's evidence is withdrawn (unverifiable vendored
	// distribution/reference citations), so the embedded route now always
	// reports UNKNOWN (RULE_EVIDENCE_WITHDRAWN), whether the supplied
	// reference is short or fully qualified: editing the request no longer
	// changes the verdict. The rest of this test's invariants (redaction,
	// the checker never modifying the supplied file, repeat idempotency)
	// still hold and are still exercised.
	args := crioRawArgs(path, "named-reference-resolution", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(before, "short explicit-tag reference") || !strings.Contains(before, "scoped result: UNKNOWN (RULE_EVIDENCE_WITHDRAWN)") || !strings.Contains(before, "aggregate readiness: UNKNOWN") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertCRIORedacted(t, before, path)
	got, _ := os.ReadFile(path)
	if string(got) != string(shortRaw) {
		t.Fatal("checker modified the supplied request")
	}
	fullRaw := []byte(`{"image":{"image":"registry.example/repository/widget:v1"},"auth":{"password":"PRIVATE_CRIO"}}`)
	writeCNCFFileAt(t, path, fullRaw)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(after, "fully-qualified explicit-tag reference") || !strings.Contains(after, "scoped result: UNKNOWN (RULE_EVIDENCE_WITHDRAWN)") || !strings.Contains(after, "aggregate readiness: UNKNOWN") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertCRIORedacted(t, after, path)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestCRIOArtifactNameRawUnknownPrivacyAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image-status-request.json")
	tests := []struct {
		name, raw, operation string
	}{
		{"missing intent", `{"image":{"image":"widget:v1"},"secret":"PRIVATE_CRIO"}`, ""},
		{"other intent", `{"image":{"image":"widget:v1"},"secret":"PRIVATE_CRIO"}`, "ordinary-image"},
		{"missing image", `{"image":{},"secret":"PRIVATE_CRIO"}`, "named-reference-resolution"},
		{"case ambiguity", `{"image":{"image":"widget:v1"},"Image":{"image":"widget:v1"}}`, "named-reference-resolution"},
		{"nested ambiguity", `{"image":{"image":"widget:v1","Image":"widget:v1"}}`, "named-reference-resolution"},
		{"unsupported digest", `{"image":{"image":"widget@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`, "named-reference-resolution"},
		{"unsupported no tag", `{"image":{"image":"registry.example/repository/widget"}}`, "named-reference-resolution"},
		{"unsupported port", `{"image":{"image":"registry.example:5000/repository/widget:v1"}}`, "named-reference-resolution"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, []byte(tc.raw))
			code, out, errout := runCNCFCLI(t, crioRawArgs(path, tc.operation, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertCRIORedacted(t, out, path)
		})
	}
	writeCNCFFileAt(t, path, []byte(`{"image":`))
	code, out, errout := runCNCFCLI(t, crioRawArgs(path, "named-reference-resolution", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: CRIO_IMAGE_STATUS_REQUEST_PREPARATION_INPUT_INVALID\n" {
		t.Fatalf("malformed code=%d stdout=%q stderr=%q", code, out, errout)
	}
	raw := []byte(`{"image":{"image":"registry.example/repository/widget:v1"},"secret":"PRIVATE_CRIO"}`)
	writeCNCFFileAt(t, path, raw)
	base := crioRawArgs(path, "named-reference-resolution", "json")
	matching := append(append([]string{}, base...), "--image-status-request-digest", digestCommunityBytes(raw))
	code, out, errout = runCNCFCLI(t, matching...)
	if code != ExitUnknown || errout != "" || !json.Valid([]byte(out)) || strings.Contains(out, "PRIVATE_CRIO") {
		t.Fatalf("matching code=%d stderr=%q output=%s", code, errout, out)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	code, out, errout = runCNCFCLI(t, append(base, "--image-status-request-digest", badDigest)...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, out, errout)
	}
	for _, extra := range [][]string{{"--input", path}, {"--service", path}, {"--metanode-config", path}, {"--knowledge-db", dir}, {"--replay-report", path}} {
		args := append(append([]string{}, base...), extra...)
		code, out, errout = runCNCFCLI(t, args...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
			t.Fatalf("extra=%v code=%d out=%q err=%q", extra, code, out, errout)
		}
	}
}

func assertCRIORedacted(t *testing.T, output, path string) {
	t.Helper()
	for _, value := range []string{path, "PRIVATE_CRIO", "private-repository", "registry.example", "repository/widget", "auth", "password", "secret"} {
		if strings.Contains(output, value) {
			t.Fatalf("private request leaked: %q in %s", value, output)
		}
	}
}
