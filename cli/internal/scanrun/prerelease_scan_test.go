// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A scan that names a Kubernetes pre-release never passes: it is UNKNOWN,
// or BLOCKED when a reviewed rule blocks it, and the report says so.
func TestScanPreReleaseNeverPasses(t *testing.T) {
	t.Parallel()
	_, clean := files(t, map[string]string{"applyset.yaml": cronjobV1})
	_, removed := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	cases := []struct {
		name, from, to string
		paths          []string
		verdict        string
		pre            []string // versions the report labels
	}{
		{"release baseline passes", "1.24.17", "1.30.4", clean, scanreport.VerdictPass, nil},
		{"pre-release target", "1.24.17", "1.30.0-rc.1", clean, scanreport.VerdictUnknown, []string{"1.30.0-rc.1"}},
		{"pre-release origin", "1.24.0-alpha.1", "1.30.4", clean, scanreport.VerdictUnknown, []string{"1.24.0-alpha.1"}},
		{"both ends pre-release", "1.28.0-beta.0", "1.30.0-alpha.2", clean, scanreport.VerdictUnknown, []string{"1.28.0-beta.0", "1.30.0-alpha.2"}},
		{"same-line hop alpha to release", "1.30.0-alpha.2", "1.30.0", clean, scanreport.VerdictUnknown, []string{"1.30.0-alpha.2"}},
		{"same-line hop release to rc", "1.30.0-rc.0", "1.30.0-rc.1", clean, scanreport.VerdictUnknown, []string{"1.30.0-rc.0", "1.30.0-rc.1"}},
		{"one line step to a pre-release", "1.29.4", "1.30.0-alpha.1", clean, scanreport.VerdictUnknown, []string{"1.30.0-alpha.1"}},
		{"blocker with a pre-release target", "1.24.17", "1.30.0-rc.1", removed, scanreport.VerdictBlocked, []string{"1.30.0-rc.1"}},
		{"blocker with a pre-release origin", "1.24.0-alpha.1", "1.30.4", removed, scanreport.VerdictBlocked, []string{"1.24.0-alpha.1"}},
		{"blocker on the entered pre-release line", "1.24.17", "1.25.0-alpha.1", removed, scanreport.VerdictBlocked, []string{"1.25.0-alpha.1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			knowledge := crossingKnowledge(t, crossingRule(crossingRuleID, true), "current")
			result := mustScan(t, knowledge, args(c.paths, "--from", "kubernetes="+c.from, "--to", "kubernetes="+c.to)...)
			report := result.Report
			if report.Verdict != c.verdict {
				t.Fatalf("verdict %s, want %s (gaps %v)", report.Verdict, c.verdict, gapReasons(report))
			}
			wantExit := map[string]int{scanreport.VerdictPass: scanreport.ExitPass, scanreport.VerdictBlocked: scanreport.ExitBlocked, scanreport.VerdictUnknown: scanreport.ExitUnknown}[c.verdict]
			if result.Exit != wantExit {
				t.Fatalf("exit %d, want %d", result.Exit, wantExit)
			}
			for _, path := range report.Paths {
				for _, hop := range path.Hops {
					if hop.Status == scanreport.HopCovered && (constraintengine.PreRelease(hop.From.Version) || constraintengine.PreRelease(hop.To.Version)) {
						t.Fatalf("hop %d with a pre-release end is COVERED: %+v", hop.Index, hop)
					}
				}
			}
			encoded := string(jsonOf(t, report))
			if len(c.pre) == 0 {
				if strings.Contains(encoded, "versionStage") || strings.Contains(strings.Join(report.Notes, "\n"), "pre-release") {
					t.Fatal("a release scan carries the pre-release label")
				}
				return
			}
			if !strings.Contains(encoded, `"versionStage":"prerelease"`) {
				t.Fatal("JSON report lacks versionStage")
			}
			// The human and Markdown outputs carry the same statement.
			for _, out := range [][]byte{scanreport.Human(report, scanreport.HumanOptions{}), scanreport.Markdown(report, scanreport.MarkdownOptions{})} {
				if !strings.Contains(string(out), "is a pre-release; findings are provisional until the GA release") {
					t.Fatalf("output lacks the pre-release line:\n%s", out)
				}
			}
			for _, version := range c.pre {
				line := scanreport.Text(scanreport.NotePreRelease, version)
				if !strings.Contains(strings.Join(report.Notes, "\n"), line) {
					t.Fatalf("no note %q in %v", line, report.Notes)
				}
			}
			if c.verdict == scanreport.VerdictUnknown && !containsReason(report, "LINE_NOT_ATTESTED") {
				t.Fatalf("no pre-release gap in %v", gapReasons(report))
			}
		})
	}
}

func containsReason(report scanreport.Report, reason string) bool {
	for _, gap := range report.Gaps {
		if gap.Reason == reason {
			return true
		}
	}
	return false
}

// Other components keep strict X.Y.Z: a pre-release is refused at intake.
func TestScanPreReleaseRefusedForOtherComponents(t *testing.T) {
	t.Parallel()
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	knowledge := crossingKnowledge(t, crossingRule(crossingRuleID, true), "current")
	for _, component := range []string{"argo-cd", "cilium"} {
		for _, flag := range []string{"--from", "--to"} {
			_, err := scan(t, knowledge, args(paths, flag, component+"=1.30.0-rc.1")...)
			if !isUsage(err) {
				t.Fatalf("%s %s=1.30.0-rc.1: %v, want a usage error", flag, component, err)
			}
		}
	}
	for _, malformed := range []string{"1.30.0-alpha", "1.30.0-alpha.01", "1.30.1-alpha.1", "1.30-alpha.1", "1.30.0-rc.1+x", "v1.30.0-rc.1"} {
		_, err := scan(t, knowledge, args(paths, "--to", "kubernetes="+malformed)...)
		if !isUsage(err) {
			t.Fatalf("kubernetes=%s: %v, want a usage error", malformed, err)
		}
	}
}

// The line helpers read a pre-release as its own line and plain versions as
// before.
func TestLineHelpersPreRelease(t *testing.T) {
	for _, c := range []struct {
		from, to string
		entered  []string
		skips    bool
	}{
		{"1.37.5", "1.38.0-alpha.2", []string{"1.38"}, false},
		{"1.38.0-alpha.2", "1.39.0", []string{"1.39"}, false},
		{"1.37.5", "1.39.0-rc.1", []string{"1.38", "1.39"}, true},
		{"1.38.0-alpha.2", "1.38.0", nil, false},
		{"1.38.0-rc.0", "1.38.0-rc.1", nil, false},
		{"1.37.5", "1.37.9", nil, false},
		{"1.37.5", "1.38.2", []string{"1.38"}, false},
		{"1.36.0", "1.38.2", []string{"1.37", "1.38"}, true},
		{"1.38.4", "1.37.5", nil, false},
	} {
		if got := enteredLines(c.from, c.to); strings.Join(got, ",") != strings.Join(c.entered, ",") {
			t.Errorf("enteredLines(%s, %s) = %v, want %v", c.from, c.to, got, c.entered)
		}
		if got := skipsLines(c.from, c.to); got != c.skips {
			t.Errorf("skipsLines(%s, %s) = %v, want %v", c.from, c.to, got, c.skips)
		}
	}
	if major, minor, ok := majorMinor("1.38.0-alpha.2"); !ok || major != 1 || minor != 38 {
		t.Errorf("majorMinor of a pre-release: %d.%d %v", major, minor, ok)
	}
}
