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
			if got := request.ExitCode(verdict); got != want {
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
		hiddenGaps := len(base.Report.Gaps)
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
				if hiddenGaps > 0 && strings.Contains(string(onlyOut), fmt.Sprintf("NOT CHECKED (%d)", hiddenGaps)) {
					t.Errorf("%s/%s: gaps still listed", run.name, format)
				}
				if len(plain.Report.Findings) > 0 && !strings.Contains(string(onlyOut), plain.Report.Findings[0].Title) {
					t.Errorf("%s/%s: finding missing", run.name, format)
				}
			}
		}
	}
}
