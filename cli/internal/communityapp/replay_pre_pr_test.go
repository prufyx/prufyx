// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/testclock"
)

// A report saved by a build that predates the rewritten next-action text
// still holds the same decisions. Replay needs exact bytes, so it is refused,
// but with a message that says why, not as an integrity failure.
// nextActionField is a claim's next-action text in a JSON check report.
var nextActionField = regexp.MustCompile(`"nextAction":"(?:[^"\\]|\\.)*"`)

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
	// The stored report is what a build that predates the rewritten next-action
	// text printed. Its rule digests, sources and dates move with every renewal
	// of the containerd rules, so the report replayed here is a fresh check of
	// the same input, at the earliest instant every containerd rule is in
	// force, whose next-action text is put back to the stored older one: it
	// differs from a current report in that text only.
	now := testclock.ProjectNewest("containerd").Format(time.RFC3339)
	_, fresh, _ := runCNCFCLI(t, "check", "cncf", "--project", "containerd", "--input", inputPath, "--now", now, "--format", "json")
	stored, current := nextActionField.FindAll(report, -1), nextActionField.FindAll([]byte(fresh), -1)
	if len(stored) == 0 || len(stored) != len(current) {
		t.Fatalf("stored report holds %d next actions, fresh check %d: %q", len(stored), len(current), fresh)
	}
	older, i := 0, 0
	report = nextActionField.ReplaceAllFunc([]byte(fresh), func(now []byte) []byte {
		i++
		if !bytes.Equal(stored[i-1], now) {
			older++
		}
		return stored[i-1]
	})
	if older != 1 {
		t.Fatalf("%d next actions differ from the older report's, want exactly 1", older)
	}
	args := func(report []byte) []string {
		return []string{"check", "cncf", "--project", "containerd", "--input", inputPath, "--now", now, "--format", "json",
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
