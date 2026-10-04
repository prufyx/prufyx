// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

// embeddedEnd is the earliest end date of the embedded pack's active rules.
func embeddedEnd(t *testing.T) time.Time {
	t.Helper()
	sources, err := cncfcheck.EmbeddedKnowledgeAge()
	if err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for _, end := range sources[0].Expiries {
		if first.IsZero() || end.Before(first) {
			first = end
		}
	}
	return first
}

// embeddedNote is the note the embedded knowledge gives at now.
func embeddedNote(t *testing.T, now string) string {
	t.Helper()
	at, err := time.Parse(time.RFC3339, now)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := cncfcheck.EmbeddedKnowledgeAge()
	if err != nil {
		t.Fatal(err)
	}
	line := knowledgeage.Line(knowledgeage.Summarize(sources, at), at, true)
	if line == "" {
		return ""
	}
	return "prufyx: " + line + "\n"
}

// TestKnowledgeAgeCheckCNCFEmbedded: check cncf prints exactly the note on
// standard error, after its output, only inside the window or after it, and
// the exit code is the verdict's either way.
func TestKnowledgeAgeCheckCNCFEmbedded(t *testing.T) {
	input := writeCNCFFile(t, "input.json", []byte(kyvernoInputTrue), 0o600)
	end := embeddedEnd(t)
	instants := []string{
		"2026-10-04T00:00:00Z",
		end.Add(-knowledgeage.Window - time.Second).Format(time.RFC3339),
		end.Add(-knowledgeage.Window).Format(time.RFC3339),
		"2026-11-20T00:00:00Z",
		end.Add(-time.Second).Format(time.RFC3339),
		end.Format(time.RFC3339),
		"2026-12-10T00:00:00Z",
	}
	for _, now := range instants {
		for _, format := range []string{"human", "json"} {
			code, stdout, stderr := runCNCFCLIRaw(t, "check", "cncf", "--project", "kyverno", "--input", input, "--now", now, "--format", format)
			if want := embeddedNote(t, now); stderr != want {
				t.Errorf("%s %s: stderr %q, want %q", now, format, stderr, want)
			}
			if code != ExitOK && code != ExitBlocked && code != ExitUnknown {
				t.Errorf("%s %s: exit %d", now, format, code)
			}
			if strings.Contains(stdout, "knowledge rules") || strings.Contains(stdout, "db update") {
				t.Errorf("%s %s: the note reached standard output", now, format)
			}
		}
	}
	// The note is the same wording on every run.
	_, _, first := runCNCFCLIRaw(t, "check", "cncf", "--project", "kyverno", "--input", input, "--now", "2026-11-20T00:00:00Z")
	_, _, second := runCNCFCLIRaw(t, "check", "cncf", "--project", "kyverno", "--input", input, "--now", "2026-11-20T00:00:00Z")
	if first != second || !ageNoteLine.MatchString(first) || strings.Count(first, "\n") != 1 || len(first) > 256 {
		t.Fatalf("%q %q", first, second)
	}
	if strings.Contains(first, input) || strings.Contains(first, "/") {
		t.Fatalf("the note names a path: %q", first)
	}
}

// TestKnowledgeAgeCheckCNCFNoNoteWithoutEvaluation: input the command does
// not accept, a missing time and help print no note, and the exit codes are
// the usual ones.
func TestKnowledgeAgeCheckCNCFNoNoteWithoutEvaluation(t *testing.T) {
	input := writeCNCFFile(t, "input.json", []byte(kyvernoInputTrue), 0o600)
	cases := [][]string{
		{"check", "cncf", "--project", "kyverno", "--input", input, "--now", "2026-11-20T00:00:00"},
		{"check", "cncf", "--project", "kyverno", "--input", input},
		{"check", "cncf", "--project", "no-such-project", "--input", input, "--now", "2026-11-20T00:00:00Z"},
		{"check", "cncf", "--help"},
		{"check", "cncf", "--project", "kyverno", "--input", input, "--now", "2026-11-20T00:00:00Z", "--help"},
	}
	for _, args := range cases {
		_, _, stderr := runCNCFCLIRaw(t, args...)
		if ageNoteLine.MatchString(stderr) {
			t.Errorf("%v: %q", args, stderr)
		}
	}
	if code, _, _ := runCNCFCLIRaw(t, cases[0]...); code != ExitUsage {
		t.Errorf("exit %d", code)
	}
}

// TestKnowledgeAgeCheckCNCFStore: for a knowledge database the note
// describes the database's rules at its verifier clock, in the same words,
// without the hint to use a database. The synthetic database's rule ends the
// next day.
func TestKnowledgeAgeCheckCNCFStore(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	importExternalCLIRevision2(t, &fixture)
	input := writeCNCFFile(t, "active-input.json", []byte(kyvernoInputTrue), 0o600)
	args := externalCLIArgs(fixture, input, "2", fixture.manifest.Revisions[1].BundleDigest, fixture.receipt2.TrustReceiptDigest)
	code, stdout, stderr := runCNCFCLIRaw(t, append(args, "--format", "json")...)
	pattern := regexp.MustCompile(`^prufyx: note: 1 knowledge rule expires within 30 days, the earliest on \d{4}-\d\d-\d\d \(in (less than a day|1 day)\); update with ` + "`prufyx db update`" + `\n$`)
	if code != ExitBlocked || !pattern.MatchString(stderr) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, "--knowledge-db") || strings.Contains(stderr, fixture.store) || strings.Contains(stdout, "knowledge rule expires") {
		t.Fatalf("stderr %q", stderr)
	}
	// The verdict is what it is without the note (the report records the
	// verifier's clock, so the bytes themselves move with the second).
	if code2, _, _ := runCNCFCLI(t, append(args, "--format", "json")...); code2 != code {
		t.Fatalf("exit %d then %d", code, code2)
	}
	// Replaying a report evaluates nothing against current knowledge.
	report := writeCNCFFile(t, "report.json", []byte(stdout), 0o600)
	_, _, replayErr := runCNCFCLIRaw(t, append(args, "--format", "json", "--replay-report", report)...)
	if ageNoteLine.MatchString(replayErr) {
		t.Fatalf("replay printed a note: %q", replayErr)
	}
}

// TestKnowledgeAgeScan: scan prints the note after its report, the same
// stdout and exit code as the scan itself gives, --redact included.
func TestKnowledgeAgeScan(t *testing.T) {
	path, base := scanFormatsFixture(t)
	for _, clock := range []string{"2026-10-04T00:00:00Z", "2026-11-20T00:00:00Z", "2026-12-10T00:00:00Z"} {
		for _, redact := range []bool{false, true} {
			for _, format := range scanreport.Formats() {
				args := []string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", clock, "--format", format}
				if redact {
					args = append(args, "--redact")
				}
				code, stdout, stderr := runScan(t, args...)
				request, err := scanrun.ParseArgs(args)
				if err != nil {
					t.Fatal(err)
				}
				result, err := scanrun.Run(request, scanrun.Options{})
				if err != nil {
					t.Fatal(err)
				}
				want, err := scanreport.Render(result.Report, request.Format, scanreport.RenderOptions{ShowPasses: request.ShowPasses, Verbose: request.Verbose})
				if err != nil {
					t.Fatal(err)
				}
				if code != result.Exit || stdout != string(want) {
					t.Errorf("%s %s redact=%v: exit %d (want %d) or stdout differs", clock, format, redact, code, result.Exit)
				}
				if expected := embeddedNote(t, clock); stderr != expected {
					t.Errorf("%s %s redact=%v: stderr %q, want %q", clock, format, redact, stderr, expected)
				}
			}
		}
	}
	_ = base
}

// TestKnowledgeAgeScanNoNoteOnFailure: a scan that stops (usage error,
// output failure) prints no note.
func TestKnowledgeAgeScanNoNoteOnFailure(t *testing.T) {
	path, _ := scanFormatsFixture(t)
	code, _, stderr := runScan(t, path, "--to", "kubernets=1.25.3", "--now", "2026-11-20T00:00:00Z")
	if code != ExitUsage || ageNoteLine.MatchString(stderr) {
		t.Fatalf("%d %q", code, stderr)
	}
	var out bytes.Buffer
	code = Run(context.Background(), []string{"scan", path, "--to", "kubernetes=1.25.3", "--now", "2026-11-20T00:00:00Z"}, failedBatchWriter{}, &out, "test")
	if code != ExitIntegrity || ageNoteLine.MatchString(out.String()) {
		t.Fatalf("%d %q", code, out.String())
	}
}

// TestKnowledgeAgeBatchEmbedded: check batch prints the note for embedded
// CNCF knowledge in both formats; the output is unchanged.
func TestKnowledgeAgeBatchEmbedded(t *testing.T) {
	root, plan := writeEmbeddedCLIBatch(t)
	for _, now := range []string{"2026-10-04T00:00:00Z", "2026-11-20T00:00:00Z", "2026-12-10T00:00:00Z"} {
		for _, format := range []string{"human", "json"} {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"check", "batch", "--plan", plan, "--root", root, "--now", now, "--format", format}, &stdout, &stderr, "test")
			if want := embeddedNote(t, now); stderr.String() != want {
				t.Errorf("%s %s: stderr %q, want %q", now, format, stderr.String(), want)
			}
			if code != ExitOK && code != ExitUnknown {
				t.Errorf("%s %s: exit %d", now, format, code)
			}
			if strings.Contains(stdout.String(), "knowledge rules") {
				t.Errorf("%s %s: the note reached standard output", now, format)
			}
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"check", "batch", "--plan", plan, "--root", root, "--now", "2026-11-20T00:00:00Z", "--format", "json"}, failedBatchWriter{}, &stderr, "test"); code != ExitIntegrity || ageNoteLine.MatchString(stderr.String()) {
		t.Fatalf("write failure: %d %q", code, stderr.String())
	}
	_ = stdout
}

// TestKnowledgeAgeBatchStore: a batch over a knowledge database describes
// the database's rules, in the same words and without the hint to use one.
func TestKnowledgeAgeBatchStore(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	importExternalCLIRevision2(t, &fixture)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.json"), []byte(kyvernoInputTrue), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := `{"schema":"prufyx.io/batch-check-plan/v1alpha1","authority":"OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS","knowledge":{"mode":"external_cncf_embedded_community","cncf":"external_signed_local","communityProject":"embedded"},"items":[{"id":"a","kind":"cncf","project":"kyverno","from":"1.12.5","to":"1.13.0","inputPath":"input.json"}]}`
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"human", "json"} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"check", "batch", "--plan", planPath, "--root", root, "--knowledge-db", fixture.store, "--format", format}, &stdout, &stderr, "test")
		pattern := regexp.MustCompile(`^prufyx: note: 1 knowledge rule expires within 30 days, the earliest on \d{4}-\d\d-\d\d \(in (less than a day|1 day)\); update with ` + "`prufyx db update`" + `\n$`)
		if code != ExitBlocked || !pattern.MatchString(stderr.String()) || strings.Contains(stdout.String(), "knowledge rule expires") || strings.Contains(stderr.String(), fixture.store) {
			t.Fatalf("%s: code=%d stderr=%q stdout=%s", format, code, stderr.String(), stdout.String())
		}
	}
}
