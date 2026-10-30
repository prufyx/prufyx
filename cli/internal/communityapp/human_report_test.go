// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"flag"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/goldenfile"
)

var updateHumanReportGoldens = flag.Bool("update-human-report", false, "rewrite the human report JSON golden files")

const humanReportNow = "2026-11-20T00:00:00Z"

var humanReportDeclarations = []string{"--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete"}

type humanReportCase struct {
	name string
	args func(t *testing.T) []string
}

func humanReportCases() []humanReportCase {
	kube := func(from, to string, extra ...string) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			path := writeCNCFFile(t, "kubernetes.json", []byte(quietCronJobJSON), 0o600)
			args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", from, "--to", to, "--now", humanReportNow}
			return append(args, extra...)
		}
	}
	return []humanReportCase{
		{"kubernetes-undeclared", kube("1.24.0", "1.25.0")},
		{"kubernetes-declared", kube("1.24.0", "1.25.0", humanReportDeclarations...)},
		{"kubernetes-unreviewed-hop", kube("1.21.0", "1.25.0", humanReportDeclarations...)},
		{"generic-helm", func(t *testing.T) []string {
			return cncfArgs(writeCNCFFile(t, "vector.json", []byte(syntheticHelmInput), 0o600))
		}},
		{"project-kibana", func(t *testing.T) []string {
			path := writePrivateProjectFixture(t, "xpack.reporting.roles.allow: [private-role]\n")
			return []string{"check", "project", "--project", "kibana", "--effective-config", path, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}
		}},
	}
}

// The JSON report is the stable interface: the human report redesign must not
// move one byte of it. The golden files were captured from the build before
// the redesign.
func TestHumanReportLeavesJSONByteIdentical(t *testing.T) {
	t.Parallel()
	for _, c := range humanReportCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			args := append(c.args(t), "--format", "json")
			_, stdout, _ := runCNCFCLI(t, args...)
			// Object locations are additive (WI-4): without them the bytes are
			// exactly the ones captured before the redesign.
			goldenfile.Check(t, filepath.Join("testdata", "human-report", c.name+".json"), maskPack(t, withoutLocations([]byte(stdout))), *updateHumanReportGoldens, "")
		})
	}
}

type jsonReport struct {
	Check struct {
		Claims []struct {
			RuleID     string `json:"ruleId"`
			Status     string `json:"status"`
			ReasonCode string `json:"reasonCode"`
			Sources    []struct {
				URL string `json:"url"`
			} `json:"sources"`
		} `json:"claims"`
	} `json:"check"`
}

var checkedPasses = regexp.MustCompile(`(?m)^checked: (\d+) rules? passed;`)

var headlineCounts = regexp.MustCompile(`^\S.*?  (\d+) must fix · (\d+) undecided(?: · (\d+) passed)? `)

// The headline word follows the exit code, the three counts add up to the
// claims, and -v (with --show-passes where the route has it) shows every rule
// and every source the JSON report holds, except the rules of other
// transitions, which are counted and never listed.
func TestHumanReportInvariantsOverRouteFixtures(t *testing.T) {
	t.Parallel()
	for _, c := range humanReportCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			args := c.args(t)
			verboseArgs := []string{"-v"}
			if c.name != "project-kibana" {
				verboseArgs = append(verboseArgs, "--show-passes")
			}
			code, jsonOut, _ := runCNCFCLI(t, append(append([]string(nil), args...), "--format", "json")...)
			humanCode, human, _ := runCNCFCLI(t, args...)
			verboseCode, verbose, _ := runCNCFCLI(t, append(append([]string(nil), args...), verboseArgs...)...)
			if humanCode != code || verboseCode != code {
				t.Fatalf("exit codes differ: json %d human %d verbose %d", code, humanCode, verboseCode)
			}
			var report jsonReport
			if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
				t.Fatal(err)
			}
			first := strings.SplitN(human, "\n", 2)[0]
			switch code {
			case ExitBlocked:
				if !strings.HasPrefix(first, "BLOCKED  ") {
					t.Fatalf("headline %q for exit %d", first, code)
				}
			case ExitOK:
				if !strings.HasPrefix(first, "PASS (scoped)  ") {
					t.Fatalf("headline %q for exit %d", first, code)
				}
			default:
				if !strings.HasPrefix(first, "UNKNOWN  ") || strings.Contains(first, "PASS (") {
					t.Fatalf("headline %q for exit %d", first, code)
				}
			}
			match := headlineCounts.FindStringSubmatch(first)
			if match == nil {
				t.Fatalf("no counts in headline %q", first)
			}
			total := 0
			for _, field := range match[1:] {
				n, _ := strconv.Atoi(field)
				total += n
			}
			if code != ExitOK && !strings.Contains(first, "passed") {
				// Non-PASS headline carries no pass count; it follows as "checked: N rule(s) passed".
				if m := checkedPasses.FindStringSubmatch(human); m != nil {
					n, _ := strconv.Atoi(m[1])
					total += n
				}
			}
			if total != len(report.Check.Claims) {
				t.Fatalf("counts add up to %d, the report holds %d claims: %q", total, len(report.Check.Claims), first)
			}
			for _, text := range []string{human, verbose} {
				if !strings.Contains(text, "Whole upgrade: not proven") {
					t.Fatalf("whole-upgrade line missing:\n%s", text)
				}
			}
			for _, claim := range report.Check.Claims {
				if claim.ReasonCode == reasonTransitionNotReviewed || claim.ReasonCode == "RULE_RELEASE_BOUNDARY_NOT_REVIEWED" {
					continue
				}
				if !strings.Contains(verbose, claim.RuleID) {
					t.Fatalf("-v lost rule %s:\n%s", claim.RuleID, verbose)
				}
				for _, source := range claim.Sources {
					if !strings.Contains(verbose, source.URL) {
						t.Fatalf("-v lost source %s of %s:\n%s", source.URL, claim.RuleID, verbose)
					}
				}
			}
		})
	}
}
