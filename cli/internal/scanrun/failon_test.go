// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestFailOnExitMatrix: --fail-on changes only the exit code mapping.
func TestFailOnExitMatrix(t *testing.T) {
	const (
		pass, blocked, unknown = scanreport.ExitPass, scanreport.ExitBlocked, scanreport.ExitUnknown
	)
	cases := []struct {
		flags                  []string
		onPass, onBlock, onUnk int
	}{
		{nil, pass, blocked, unknown},
		{[]string{"--fail-on", "unknown"}, pass, blocked, unknown},
		{[]string{"--fail-on=blocked"}, pass, blocked, pass},
		{[]string{"--fail-on", "none"}, pass, pass, pass},
	}
	for _, c := range cases {
		request, err := ParseArgs(append([]string{"--to", "kubernetes=1.30.4"}, c.flags...))
		if err != nil {
			t.Fatalf("%v: %v", c.flags, err)
		}
		for verdict, want := range map[int]int{pass: c.onPass, blocked: c.onBlock, unknown: c.onUnk} {
			if got := request.ExitCode(scanreport.Report{Verdict: "UNKNOWN"}, verdict); got != want {
				t.Errorf("%v: verdict exit %d mapped to %d, want %d", c.flags, verdict, got, want)
			}
		}
	}
}

// TestFailOnUsageErrors: bad values and repeats are usage errors (exit 2),
// which no policy suppresses.
func TestFailOnUsageErrors(t *testing.T) {
	for _, bad := range [][]string{
		{"--fail-on", "warn"}, {"--fail-on"}, {"--fail-on", ""}, {"--fail-on=none", "--fail-on=none"},
		{"--only-blocked=maybe"}, {"--only-blocked", "--only-blocked"},
	} {
		if _, err := ParseArgs(append([]string{"--to", "kubernetes=1.30.4"}, bad...)); !isUsage(err) {
			t.Errorf("%v: err %v, want usage error", bad, err)
		}
	}
	request, err := ParseArgs([]string{"--to", "kubernetes=1.30.4", "--only-blocked=false"})
	if err != nil || request.OnlyBlocked || request.FailOn != FailOnUnknown {
		t.Errorf("defaults: %+v %v", request, err)
	}
}

// TestOnlyBlocked: human and markdown list only findings and count what is
// hidden; the default output has no such line; json and sarif are identical
// with and without the flag; the report and verdict are unchanged.
func TestOnlyBlocked(t *testing.T) {
	for _, run := range formatRuns(t) {
		base := run.result("human")
		keptGaps := 0
		for _, gap := range base.Report.Gaps {
			if gap.Reason == scanreport.ReasonAPIVersionNotServed {
				keptGaps++
			}
		}
		hiddenGaps := len(base.Report.Gaps) - keptGaps
		hiddenOther := len(base.Report.Notices) + len(base.Report.Unsupported) + len(base.Report.Leads)
		want := fmt.Sprintf("Hidden by --only-blocked: %d not-checked gap(s), %d other item(s)", hiddenGaps, hiddenOther)
		for _, format := range scanreport.Formats() {
			plain := run.result(format)
			only := run.result(format, "--only-blocked")
			if only.Exit != plain.Exit || only.Report.Verdict != plain.Report.Verdict {
				t.Errorf("%s/%s: verdict or exit changed", run.name, format)
			}
			render := func(r Result, only bool) []byte {
				out, err := scanreport.Render(r.Report, format, scanreport.RenderOptions{OnlyBlocked: only})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			plainOut, onlyOut := render(plain, false), render(only, true)
			switch format {
			case "json", "sarif":
				if !bytes.Equal(plainOut, onlyOut) {
					t.Errorf("%s/%s: output changed by --only-blocked", run.name, format)
				}
			default:
				if bytes.Contains(plainOut, []byte("Hidden by --only-blocked")) {
					t.Errorf("%s/%s: default output has the hidden line", run.name, format)
				}
				if n := strings.Count(string(onlyOut), "Hidden by --only-blocked"); n != 1 || !strings.Contains(string(onlyOut), want) {
					t.Errorf("%s/%s: hidden-count line missing or repeated (want %q):\n%s", run.name, format, want, onlyOut)
				}
				if keptGaps == 0 && hiddenGaps > 0 && strings.Contains(string(onlyOut), "NOT CHECKED (") {
					t.Errorf("%s/%s: gaps still listed", run.name, format)
				}
				if keptGaps > 0 && !strings.Contains(string(onlyOut), "NOT CHECKED (") {
					t.Errorf("%s/%s: the not-served gap is hidden", run.name, format)
				}
				if len(plain.Report.Findings) > 0 && !strings.Contains(string(onlyOut), plain.Report.Findings[0].Title) {
					t.Errorf("%s/%s: finding missing", run.name, format)
				}
			}
		}
	}
}

// TestFailOnKeepsNotServedExit: manifests that use an API version the target
// does not serve (CronJob batch/v1beta1, 1.25 to 1.26) give UNKNOWN with an
// API_VERSION_NOT_SERVED gap. No --fail-on value turns that into exit 0, the
// same as the GitHub Action; an UNKNOWN without that gap is still suppressed.
func TestFailOnKeepsNotServedExit(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.25.3", "--to", "kubernetes=1.26.15")...)
	if result.Exit != scanreport.ExitUnknown || !ReportHasNotServedGap(result.Report) {
		t.Fatalf("fixture: exit %d, not-served gap %v", result.Exit, ReportHasNotServedGap(result.Report))
	}
	for _, failOn := range []string{FailOnUnknown, FailOnBlocked, FailOnNone} {
		request, err := ParseArgs([]string{"--to", "kubernetes=1.26.15", "--fail-on", failOn})
		if err != nil {
			t.Fatal(err)
		}
		if got := request.ExitCode(result.Report, result.Exit); got != scanreport.ExitUnknown {
			t.Errorf("--fail-on %s: exit %d, want 11", failOn, got)
		}
		if note := request.ExitNote(result.Report, result.Exit); note != "" {
			t.Errorf("--fail-on %s: exit not changed but note %q", failOn, note)
		}
	}
	// The same report without the gap is suppressed, with a note.
	result.Report.Gaps = nil
	request, _ := ParseArgs([]string{"--to", "kubernetes=1.26.15", "--fail-on", "blocked"})
	if got := request.ExitCode(result.Report, result.Exit); got != scanreport.ExitPass {
		t.Errorf("without the gap: exit %d, want 0", got)
	}
	want := "prufyx: note: verdict UNKNOWN (exit 11) reported as exit 0 by --fail-on blocked; this is not a PASS"
	if note := request.ExitNote(result.Report, result.Exit); note != want {
		t.Errorf("note %q, want %q", note, want)
	}
}

// TestFailOnNoteOnlyWhenChanged: a pass, a default run and an unchanged
// blocked exit print no note; every changed non-zero code does.
func TestFailOnNoteOnlyWhenChanged(t *testing.T) {
	report := scanreport.Report{Verdict: "BLOCKED"}
	for _, c := range []struct {
		failOn  string
		verdict int
		note    bool
	}{
		{FailOnUnknown, scanreport.ExitBlocked, false},
		{FailOnUnknown, scanreport.ExitUnknown, false},
		{FailOnBlocked, scanreport.ExitBlocked, false},
		{FailOnBlocked, scanreport.ExitUnknown, true},
		{FailOnNone, scanreport.ExitBlocked, true},
		{FailOnNone, scanreport.ExitPass, false},
	} {
		request := Request{FailOn: c.failOn}
		if got := request.ExitNote(report, c.verdict) != ""; got != c.note {
			t.Errorf("--fail-on %s verdict %d: note %v, want %v", c.failOn, c.verdict, got, c.note)
		}
	}
}

// TestOnlyBlockedShowsNotServedGap: for the CronJob batch/v1beta1 1.25 to 1.26
// scan the only finding-like item is the not-served gap; --only-blocked must
// still print it, and hide the other gaps.
func TestOnlyBlockedShowsNotServedGap(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n"})
	for _, format := range []string{"human", "markdown"} {
		result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.25.3", "--to", "kubernetes=1.26.15", "--format", format, "--only-blocked")...)
		out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{OnlyBlocked: true})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "does not serve") || !strings.Contains(string(out), "NOT CHECKED (1)") {
			t.Errorf("%s: not-served gap hidden by --only-blocked:\n%s", format, out)
		}
		if strings.Contains(string(out), "DECLARATION_MISSING") {
			t.Errorf("%s: other gaps not hidden:\n%s", format, out)
		}
	}
}
