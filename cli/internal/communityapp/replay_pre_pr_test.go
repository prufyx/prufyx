// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"strings"
	"testing"
)

// A report saved by a build that predates the rewritten next-action text
// still holds the same decisions. Replay needs exact bytes, so it is refused,
// but with a message that says why, not as an integrity failure.
func TestReplayOfPreRewriteReportNamesTheOlderContract(t *testing.T) {
	t.Parallel()
	input, err := os.ReadFile("testdata/replay-pre-pr/containerd-input.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile("testdata/replay-pre-pr/containerd-report.json")
	if err != nil {
		t.Fatal(err)
	}
	inputPath := writeCNCFFile(t, "input.json", input, 0o600)
	args := func(report []byte) []string {
		return []string{"check", "cncf", "--project", "containerd", "--input", inputPath, "--now", "2026-10-08T00:00:00Z", "--format", "json",
			"--replay-report", writeCNCFFile(t, "report.json", report, 0o600)}
	}

	code, stdout, stderr := runCNCFCLI(t, args(report)...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "older engine contract") || !strings.Contains(stderr, "Generate a new report") {
		t.Fatalf("pre-rewrite report: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// A change to a decision is never explained away as an older contract.
	tampered := []byte(strings.Replace(string(report), `"status":"UNKNOWN"`, `"status":"PASS"`, 1))
	if string(tampered) == string(report) {
		t.Fatal("fixture has no UNKNOWN status to tamper with")
	}
	code, stdout, stderr = runCNCFCLI(t, args(tampered)...)
	if code != ExitIntegrity || stdout != "" || strings.Contains(stderr, "older engine contract") {
		t.Fatalf("tampered report: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
