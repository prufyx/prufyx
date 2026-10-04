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
	declared := []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", "2026-10-04T00:00:00Z"}
	code, stdout, stderr := runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3"}, declared...)...)
	if code != ExitBlocked || !strings.HasPrefix(stdout, "BLOCKED: 1 problem must be fixed before this upgrade\n") || !strings.Contains(stdout, "CronJob default/nightly-report") || stderr != "" {
		t.Fatalf("blocked: %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, _ = runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--format", "json"}, declared...)...)
	report, err := scanreport.DecodeJSON([]byte(stdout))
	if code != ExitBlocked || err != nil || report.Verdict != scanreport.VerdictBlocked || report.Provenance.NetworkUsed {
		t.Fatalf("json: %d %v", code, err)
	}
	code, stdout, _ = runScan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, declared...)...)
	if code != ExitUnknown || !strings.HasPrefix(stdout, "NO BLOCKERS FOUND IN COVERED CHECKS") {
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
