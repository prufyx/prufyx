// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const syntheticHelmInput = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/helm/helm","version":"3.14.4","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/helm/helm","version":"4.0.0","facts":[{"id":"component.helm.post_renderer_mode","state":"declared","enumValue":"plugin_name"}]}]}}`

// runCNCFCLI runs the command and returns its exit status, standard output
// and standard error without the knowledge age note: the note depends on the
// wall clock when the test knowledge is a synthetic database whose rules end
// within a day, and the age tests read it with runCNCFCLIRaw.
//
// New assertions that standard error is empty must use runCNCFCLIRaw: this
// helper would hide a stray knowledge age note from them.
func runCNCFCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	code, stdout, stderr := runCNCFCLIRaw(t, args...)
	return code, stdout, ageNoteLine.ReplaceAllString(stderr, "")
}

// runCNCFCLIRaw is runCNCFCLI with standard error exactly as printed.
func runCNCFCLIRaw(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

// ageNoteLine matches the knowledge age note line on standard error.
var ageNoteLine = regexp.MustCompile(`(?m)^prufyx: note: \d+ knowledge rules? (?:expires?|has|have) [^\n]*\n`)

func writeCNCFFile(t *testing.T, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func cncfDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cncfArgs(input string) []string {
	return []string{"check", "cncf", "--project", "helm", "--input", input, "--now", "2026-09-08T12:10:00Z"}
}

func TestCNCFCLIValidationRejectsMissingAndDuplicateFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "missing project", args: []string{"check", "cncf", "--input", "unused", "--now", "2026-09-08T12:10:00Z"}},
		{name: "missing input", args: []string{"check", "cncf", "--project", "helm", "--now", "2026-09-08T12:10:00Z"}},
		// A missing --now is no longer a usage error: the knowledge source is then
		// chosen automatically (see cncf_autoknowledge_test.go).
		{name: "duplicate project", args: []string{"check", "cncf", "--project", "helm", "--project", "helm", "--input", "unused", "--now", "2026-09-08T12:10:00Z"}},
		{name: "duplicate digest", args: []string{"check", "cncf", "--project", "helm", "--input", "unused", "--input-digest", "sha256:" + strings.Repeat("a", 64), "--input-digest", "sha256:" + strings.Repeat("b", 64), "--now", "2026-09-08T12:10:00Z"}},
		{name: "invalid digest syntax", args: []string{"check", "cncf", "--project", "helm", "--input", "unused", "--input-digest", "not-a-digest", "--now", "2026-09-08T12:10:00Z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, tc.args...)
			if code != ExitUsage {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if stdout != "" || !strings.Contains(stderr, "invalid CNCF check arguments") {
				t.Fatalf("unsafe validation output stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestCNCFCLIRequiresCanonicalWholeSecondUTC(t *testing.T) {
	cases := []string{
		"2026-09-08T12:10:00+00:00",
		"2026-09-08T14:10:00+02:00",
		"2026-09-08T12:10:00.000Z",
	}
	for _, now := range cases {
		t.Run(now, func(t *testing.T) {
			args := []string{"check", "cncf", "--project", "helm", "--input", "unused", "--now", now}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "explicit canonical UTC with whole seconds") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCNCFCLIRejectsWrongDigestBeforeParsing(t *testing.T) {
	path := writeCNCFFile(t, "input.json", []byte(syntheticHelmInput), 0o600)
	args := cncfArgs(path)
	args = append(args, "--input-digest", "sha256:"+strings.Repeat("0", 64), "--format", "json")
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF input digest does not match\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFCLIPrivateInputAdmissionRejectsPermissiveSymlinkAndHardlink(t *testing.T) {
	raw := []byte(syntheticHelmInput)
	private := writeCNCFFile(t, "private-input.json", raw, 0o600)
	permissive := writeCNCFFile(t, "permissive-input.json", raw, 0o644)
	symlink := filepath.Join(t.TempDir(), "symlink-input.json")
	if err := os.Symlink(private, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(t.TempDir(), "hardlink-input.json")
	hardlinkSource := writeCNCFFile(t, "hardlink-source.json", raw, 0o600)
	if err := os.Link(hardlinkSource, hardlink); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		path     string
		wantCode int
		want     string
	}{
		{name: "permissive mode", path: permissive, wantCode: ExitUsage, want: "CNCF input failed local admission"},
		{name: "symlink", path: symlink, wantCode: ExitUsage, want: "CNCF input failed local admission"},
		{name: "hardlink", path: hardlink, wantCode: ExitUsage, want: "CNCF input failed local admission"},
		{name: "private regular reaches parser", path: private, wantCode: ExitOK, want: `"status":"PASS"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := cncfArgs(tc.path)
			args = append(args, "--format", "json")
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.wantCode {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if tc.wantCode == ExitOK {
				if stderr != "" || !strings.Contains(stdout, tc.want) {
					t.Fatalf("successful admission output stdout=%q stderr=%q", stdout, stderr)
				}
			} else if stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Fatalf("rejected admission output stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestCNCFCLIRejectsMalformedSecretCanaryWithoutEcho(t *testing.T) {
	const canary = "cncf-private-secret-canary-7f7c1d"
	raw := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","secret":"` + canary + `"}`)
	path := writeCNCFFile(t, "malformed-private-input.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, cncfArgs(path)...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "CNCF source-constraint check failed") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, canary) || strings.Contains(stderr, canary) {
		t.Fatalf("secret canary echoed: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestCNCFCLIHelmReviewedVectors(t *testing.T) {
	cases := []struct {
		name       string
		raw        []byte
		wantCode   int
		wantStatus string
	}{
		{name: "plugin name pass", raw: []byte(syntheticHelmInput), wantCode: ExitOK, wantStatus: `"status":"PASS"`},
		{name: "executable path blocked", raw: []byte(strings.Replace(syntheticHelmInput, `"plugin_name"`, `"executable_path"`, 1)), wantCode: ExitBlocked, wantStatus: `"status":"BLOCKED"`},
		{name: "missing fact unknown", raw: []byte(strings.Replace(syntheticHelmInput, `[{"id":"component.helm.post_renderer_mode","state":"declared","enumValue":"plugin_name"}]`, `[]`, 1)), wantCode: ExitUnknown, wantStatus: `"status":"UNKNOWN"`},
		{name: "outside transition unknown", raw: []byte(strings.Replace(syntheticHelmInput, `"version":"4.0.0"`, `"version":"3.14.4"`, 1)), wantCode: ExitUnknown, wantStatus: `"status":"UNKNOWN"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "vector.json", tc.raw, 0o600)
			args := cncfArgs(path)
			args = append(args, "--format", "json")
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.wantCode || stderr != "" || !strings.Contains(stdout, tc.wantStatus) {
				t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, tc.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"networkUsed":false`) {
				t.Fatalf("unsafe or broad report: %q", stdout)
			}
		})
	}
}

func TestCNCFCLIReplayRequiresExactCanonicalJSONAndPrivateReport(t *testing.T) {
	raw := []byte(syntheticHelmInput)
	input := writeCNCFFile(t, "replay-input.json", raw, 0o600)
	args := cncfArgs(input)
	args = append(args, "--format", "json", "--input-digest", cncfDigest(raw))
	code, original, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.HasSuffix(original, "\n") || !strings.Contains(original, `"status":"PASS"`) {
		t.Fatalf("initial code=%d stdout=%q stderr=%q", code, original, stderr)
	}

	replay := writeCNCFFile(t, "replay-report.json", []byte(original), 0o600)
	replayArgs := cncfArgs(input)
	replayArgs = append(replayArgs, "--format", "json", "--input-digest", cncfDigest(raw), "--replay-report", replay)
	code, matched, stderr := runCNCFCLI(t, replayArgs...)
	if code != ExitOK || stderr != "" || matched != original {
		t.Fatalf("exact replay code=%d matched=%q original=%q stderr=%q", code, matched, original, stderr)
	}

	trimmed := writeCNCFFile(t, "trimmed-report.json", []byte(strings.TrimSuffix(original, "\n")), 0o600)
	trimmedArgs := cncfArgs(input)
	trimmedArgs = append(trimmedArgs, "--format", "json", "--input-digest", cncfDigest(raw), "--replay-report", trimmed)
	code, stdout, stderr := runCNCFCLI(t, trimmedArgs...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF source-constraint check failed\n" {
		t.Fatalf("newline tamper code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	tamperedRaw := []byte(original)
	tamperedRaw[len(tamperedRaw)-2] ^= 1
	tampered := writeCNCFFile(t, "tampered-report.json", tamperedRaw, 0o600)
	tamperedArgs := cncfArgs(input)
	tamperedArgs = append(tamperedArgs, "--format", "json", "--input-digest", cncfDigest(raw), "--replay-report", tampered)
	code, stdout, stderr = runCNCFCLI(t, tamperedArgs...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF source-constraint check failed\n" {
		t.Fatalf("content tamper code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	permissive := writeCNCFFile(t, "permissive-report.json", []byte(original), 0o644)
	permissiveArgs := cncfArgs(input)
	permissiveArgs = append(permissiveArgs, "--format", "json", "--input-digest", cncfDigest(raw), "--replay-report", permissive)
	code, stdout, stderr = runCNCFCLI(t, permissiveArgs...)
	if code != ExitUsage || stdout != "" || !strings.HasPrefix(stderr, "prufyx: CNCF replay report failed local admission: ") || !strings.Contains(stderr, "chmod 600") {
		t.Fatalf("permissive replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
