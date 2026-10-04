// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// formatRun is one scan of a scenario, with the request that produced it.
type formatRun struct {
	name   string
	exit   int
	result func(format string, extra ...string) Result
}

func formatRuns(t *testing.T) []formatRun {
	full := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	partial := newKnowledge(t, knowledgeOptions{lines: without(allLines, "1.28", "1.30"), policy: "current"})
	blockedDir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	passDir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	in := func(dir string, knowledge Knowledge) func(format string, extra ...string) Result {
		return func(format string, extra ...string) Result {
			var result Result
			inDir(t, dir, func() {
				result = mustScan(t, knowledge, args([]string{"applyset.yaml"}, append([]string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--format", format}, extra...)...)...)
			})
			return result
		}
	}
	return []formatRun{
		{"blocked", scanreport.ExitBlocked, in(blockedDir, full)},
		{"unknown", scanreport.ExitUnknown, in(passDir, partial)},
		{"pass", scanreport.ExitPass, in(passDir, full)},
	}
}

// TestScanFormatsExitCodes: the format changes only the bytes. The verdict
// and the exit code are the same for human, json, sarif and markdown, for a
// blocked, an unknown and a passing scan, and SARIF carries them.
func TestScanFormatsExitCodes(t *testing.T) {
	for _, run := range formatRuns(t) {
		var reference []byte
		for _, format := range scanreport.Formats() {
			result := run.result(format)
			if result.Exit != run.exit {
				t.Errorf("%s/%s: exit %d, want %d", run.name, format, result.Exit, run.exit)
			}
			request, _ := ParseArgs([]string{"--to", "kubernetes=1.30.4", "--format", format})
			if request.Format != format {
				t.Fatalf("format %q parsed as %q", format, request.Format)
			}
			out, err := scanreport.Render(result.Report, request.Format, scanreport.RenderOptions{})
			if err != nil || len(out) == 0 {
				t.Fatalf("%s/%s: %v", run.name, format, err)
			}
			if format == "json" {
				reference = out
			}
			if format == "sarif" {
				var log struct {
					Runs []struct {
						Invocations []struct {
							ExitCode int `json:"exitCode"`
						} `json:"invocations"`
						Properties struct {
							Verdict string `json:"verdict"`
						} `json:"properties"`
					} `json:"runs"`
				}
				if err := json.Unmarshal(out, &log); err != nil || log.Runs[0].Invocations[0].ExitCode != run.exit || log.Runs[0].Properties.Verdict != result.Report.Verdict {
					t.Errorf("%s: sarif says %+v (%v)", run.name, log, err)
				}
			}
		}
		again, _ := scanreport.Render(run.result("json").Report, "json", scanreport.RenderOptions{})
		if !bytes.Equal(reference, again) {
			t.Errorf("%s: the report differs between runs", run.name)
		}
	}
}

// TestScanFormatsDeterministic: two runs are byte-identical in every format.
func TestScanFormatsDeterministic(t *testing.T) {
	for _, run := range formatRuns(t) {
		for _, format := range scanreport.Formats() {
			a, _ := scanreport.Render(run.result(format).Report, format, scanreport.RenderOptions{ShowPasses: true, Verbose: true})
			b, _ := scanreport.Render(run.result(format).Report, format, scanreport.RenderOptions{ShowPasses: true, Verbose: true})
			if !bytes.Equal(a, b) {
				t.Errorf("%s/%s differs between runs", run.name, format)
			}
		}
	}
}

// TestScanFormatGoldens: SARIF and Markdown of the real scans, end to end.
func TestScanFormatGoldens(t *testing.T) {
	for _, run := range formatRuns(t) {
		report := run.result("sarif").Report
		sarif, err := scanreport.SARIF(report)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "scan-"+run.name+".sarif.json", sarif)
		golden(t, "scan-"+run.name+".md", scanreport.Markdown(report, scanreport.MarkdownOptions{}))
	}
}

// TestScanRedactFormats: --redact removes paths, names and namespaces from
// SARIF and Markdown exactly as from the human and JSON formats.
func TestScanRedactFormats(t *testing.T) {
	run := formatRuns(t)[0]
	for _, format := range scanreport.Formats() {
		result := run.result(format, "--redact")
		out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{Verbose: true, ShowPasses: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"applyset.yaml", "nightly-report", "report-settings", "\"default\"", "default/"} {
			if strings.Contains(string(out), secret) {
				t.Errorf("%s leaks %q", format, secret)
			}
		}
		if result.Exit != scanreport.ExitBlocked {
			t.Errorf("%s: exit %d", format, result.Exit)
		}
	}
}
