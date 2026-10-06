// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func openFGAPreparationArgs(path string, complete bool) []string {
	args := []string{"prepare", "cncf", "--project", "openfga", "--input", path, "--from", "1.17.1", "--to", "1.18.0", "--format", "input"}
	if complete {
		args = append(args, "--effective-config-complete")
	}
	return args
}

func TestOpenFGAEffectiveConfigPreparationFeedsScopedCheck(t *testing.T) {
	t.Parallel()
	const canary = "openfga-private-canary-91d2"
	missing := []byte(`{"authn":{"method":"oidc","oidc":{"audience":"aud"}},"unrelated":{"private":"` + canary + `"}}`)
	missingPath := writeCNCFFile(t, "openfga-missing.json", missing, 0o600)
	code, prepared, stderr := runCNCFCLI(t, openFGAPreparationArgs(missingPath, true)...)
	if code != ExitOK || stderr != "" || !strings.Contains(prepared, `"boolValue":true`) || strings.Contains(prepared, canary) || strings.Contains(prepared, missingPath) {
		t.Fatalf("missing preparation code=%d stderr=%q input=%q", code, stderr, prepared)
	}
	preparedPath := writeCNCFFile(t, "openfga-missing-prepared.json", []byte(prepared), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "openfga", "--input", preparedPath, "--now", "2026-09-11T16:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, canary) || strings.Contains(report, missingPath) {
		t.Fatalf("missing check code=%d stderr=%q report=%q", code, stderr, report)
	}

	complete := []byte(`{"authn":{"method":"oidc","oidc":{"issuer":"https://issuer.example.invalid","audience":"aud"}}}`)
	completePath := writeCNCFFile(t, "openfga-complete.json", complete, 0o600)
	code, prepared, stderr = runCNCFCLI(t, openFGAPreparationArgs(completePath, true)...)
	if code != ExitOK || stderr != "" || !strings.Contains(prepared, `"boolValue":false`) {
		t.Fatalf("complete preparation code=%d stderr=%q input=%q", code, stderr, prepared)
	}
	preparedPath = writeCNCFFile(t, "openfga-complete-prepared.json", []byte(prepared), 0o600)
	code, report, stderr = runCNCFCLI(t, "check", "cncf", "--project", "openfga", "--input", preparedPath, "--now", "2026-09-11T16:00:00Z", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(report, `"status":"PASS"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) {
		t.Fatalf("complete check code=%d stderr=%q report=%q", code, stderr, report)
	}
}

func TestOpenFGAIncompleteAndCrossProjectFlagStayUnknownOrRejected(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`)
	path := writeCNCFFile(t, "openfga-incomplete.json", raw, 0o600)
	code, input, stderr := runCNCFCLI(t, openFGAPreparationArgs(path, false)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(input, `"state":"unsupported"`) {
		t.Fatalf("incomplete code=%d stderr=%q input=%q", code, stderr, input)
	}
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "metallb", "--input", path, "--from", "0.12.1", "--to", "0.13.2", "--effective-config-complete")
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "only valid for OpenFGA") {
		t.Fatalf("cross-project flag code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
