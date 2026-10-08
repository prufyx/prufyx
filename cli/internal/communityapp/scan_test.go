// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const scanCronJob = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\n"

func runScan(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), append([]string{"scan"}, args...), &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

// TestScanCommand: the command maps the scan outcome to output and exit
// codes: 10 for a blocker, 11 for gaps, 2 for input it does not accept.
func TestScanCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	declared := []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", "2026-11-20T00:00:00Z"}
	code, stdout, stderr := runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3"}, declared...)...)
	if code != ExitBlocked || !strings.HasPrefix(stdout, "BLOCKED: 1 problem must be fixed before this upgrade\n") || !strings.Contains(stdout, "CronJob default/nightly-report") || !quietOrAgeNote(stderr) {
		t.Fatalf("blocked: %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, _ = runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--format", "json"}, declared...)...)
	report, err := scanreport.DecodeJSON([]byte(stdout))
	if code != ExitBlocked || err != nil || report.Verdict != scanreport.VerdictBlocked || report.Provenance.NetworkUsed {
		t.Fatalf("json: %d %v", code, err)
	}
	// An upgrade that skips release lines still blocks on the reviewed
	// removal of a line it enters (it used to answer "NO BLOCKERS FOUND").
	code, stdout, _ = runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, declared...)...)
	if code != ExitBlocked || !strings.HasPrefix(stdout, "BLOCKED: 1 problem must be fixed before this upgrade\n") || !strings.Contains(stdout, "Decided on the step 1.24.17 -> 1.25") {
		t.Fatalf("skipped lines: %d\n%s", code, stdout)
	}
	// Removed at or before the current line: no rule decides it, and the
	// answer names it instead of "no blockers".
	code, stdout, _ = runScan(t, append([]string{path, "--from", "kubernetes=1.25.2", "--to", "kubernetes=1.30.4"}, declared...)...)
	if code != ExitUnknown || !strings.HasPrefix(stdout, "UNKNOWN: manifests use API versions the target does not serve") || strings.Contains(stdout, "NO BLOCKERS FOUND") {
		t.Fatalf("unknown: %d\n%s", code, stdout)
	}
	code, _, stderr = runScan(t, path, "--to", "kubernets=1.30.4")
	if code != ExitUsage || !strings.HasPrefix(stderr, "prufyx: unknown component") || !strings.Contains(stderr, "kubernetes") {
		t.Fatalf("usage: %d %s", code, stderr)
	}
	code, stdout, _ = runScan(t, "--help")
	if code != ExitOK || !strings.HasPrefix(stdout, "Usage: prufyx scan") {
		t.Fatalf("help: %d %s", code, stdout)
	}
	previous := scanStdin
	scanStdin = strings.NewReader(scanCronJob)
	defer func() { scanStdin = previous }()
	code, stdout, _ = runScan(t, append([]string{"-", "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--redact"}, declared...)...)
	if code != ExitBlocked || strings.Contains(stdout, "nightly-report") {
		t.Fatalf("stdin: %d\n%s", code, stdout)
	}
	var help bytes.Buffer
	Run(context.Background(), nil, &help, &bytes.Buffer{}, "test")
	if !strings.Contains(help.String(), "prufyx scan [PATH ...]") {
		t.Fatal("root help does not list scan")
	}
}

func scanFormatsFixture(t *testing.T) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", "2026-11-20T00:00:00Z"}
}

// TestScanFormatsExitCodes: human, json, sarif and markdown exit the same
// for a blocked scan (10), also over skipped lines, and a scan with
// unchecked areas (11); the passing
// case needs line reviews the embedded knowledge does not carry, so it is
// covered at the scan level with test knowledge.
func TestScanFormatsExitCodes(t *testing.T) {
	t.Parallel()
	path, declared := scanFormatsFixture(t)
	for name, tc := range map[string]struct {
		from, to string
		exit     int
	}{
		"blocked":               {"kubernetes=1.24.17", "kubernetes=1.25.3", ExitBlocked},
		"blocked skipped lines": {"kubernetes=1.24.17", "kubernetes=1.30.4", ExitBlocked},
		"unknown":               {"kubernetes=1.25.2", "kubernetes=1.30.4", ExitUnknown},
	} {
		for _, format := range []string{"human", "json", "sarif", "markdown"} {
			code, stdout, stderr := runScan(t, append([]string{path, "--from", tc.from, "--to", tc.to, "--format", format}, declared...)...)
			if code != tc.exit || stdout == "" || !quietOrAgeNote(stderr) {
				t.Errorf("%s/%s: exit %d, stdout %d bytes, stderr %q", name, format, code, len(stdout), stderr)
			}
		}
	}
}

// TestScanFormatsDeterministic: two runs print the same bytes.
func TestScanFormatsDeterministic(t *testing.T) {
	t.Parallel()
	path, declared := scanFormatsFixture(t)
	for _, format := range []string{"human", "json", "sarif", "markdown"} {
		command := append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--format", format}, declared...)
		_, first, _ := runScan(t, command...)
		_, second, _ := runScan(t, command...)
		if first != second || !strings.HasSuffix(first, "\n") {
			t.Errorf("%s differs between runs", format)
		}
	}
}

// TestScanRedactFormats: --redact removes the file, namespace and name from
// every format, SARIF and Markdown included, and keeps the exit code.
func TestScanRedactFormats(t *testing.T) {
	t.Parallel()
	path, declared := scanFormatsFixture(t)
	for _, format := range []string{"human", "json", "sarif", "markdown"} {
		code, stdout, _ := runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--format", format, "--redact", "--verbose"}, declared...)...)
		if code != ExitBlocked {
			t.Errorf("%s: exit %d", format, code)
		}
		for _, secret := range []string{"applyset", "nightly-report", filepath.Dir(path), "default/"} {
			if strings.Contains(stdout, secret) {
				t.Errorf("%s leaks %q:\n%s", format, secret, stdout)
			}
		}
	}
	_, stdout, _ := runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--format", "sarif"}, declared...)...)
	if !strings.Contains(stdout, `"uri": "`+filepath.Base(path)+`"`) && !strings.Contains(stdout, filepath.Base(path)) {
		t.Fatalf("unredacted sarif lacks the path:\n%s", stdout)
	}
}

// TestScanFormatRejected: an unknown format is a usage error with nothing
// on standard output.
func TestScanFormatRejected(t *testing.T) {
	t.Parallel()
	path, declared := scanFormatsFixture(t)
	for _, format := range []string{"xml", "SARIF", "sarif2", ""} {
		code, stdout, stderr := runScan(t, append([]string{path, "--to", "kubernetes=1.25.3", "--format", format}, declared...)...)
		if code != ExitUsage || stdout != "" || !strings.HasPrefix(stderr, "prufyx: ") {
			t.Errorf("%q: exit %d stdout %q stderr %q", format, code, stdout, stderr)
		}
	}
}

// quietOrAgeNote reports whether stderr is empty or only the one-line note
// that embedded knowledge expires soon. The mechanical Kubernetes rules are
// reviewed after the 30-day window of the older rules begins, so a clock at
// which they are current is inside it.
func quietOrAgeNote(stderr string) bool {
	return stderr == "" || (strings.HasPrefix(stderr, "prufyx: note: ") && strings.Count(strings.TrimRight(stderr, "\n"), "\n") == 0)
}
