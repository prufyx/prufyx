// SPDX-License-Identifier: AGPL-3.0-only

package humanreport

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func claim(id, status, reason, action string) constraintengine.Claim {
	return constraintengine.Claim{RuleID: id, Status: status, ReasonCode: reason, NextAction: action}
}

func render(t *testing.T, in Input) string {
	t.Helper()
	var out strings.Builder
	if err := Render(&out, in); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestHeadlineWordNeverNamesAPassForAnythingButExitZero(t *testing.T) {
	t.Parallel()
	for exit, want := range map[int]string{10: "BLOCKED", 0: "PASS (scoped)", 11: "UNKNOWN", 2: "UNKNOWN", 3: "UNKNOWN", 12: "UNKNOWN", 13: "UNKNOWN", 14: "UNKNOWN", -1: "UNKNOWN"} {
		if got := HeadlineWord(exit); got != want {
			t.Errorf("exit %d: %q, want %q", exit, got, want)
		}
	}
}

// An UNKNOWN or UNSUPPORTED claim is counted as undecided, never as passed,
// and the headline follows the exit code even when every other claim passed.
func TestUndecidedClaimsAreNeverCountedAsPassed(t *testing.T) {
	t.Parallel()
	out := render(t, Input{Exit: 11, Project: "p", Claims: []constraintengine.Claim{
		claim("a", "PASS", "R", "x"),
		claim("b", "UNKNOWN", "RULE_FACT_UNAVAILABLE", "y"),
		claim("c", constraintengine.StatusUnsupported, "S", "z"),
	}})
	if !strings.HasPrefix(out, "UNKNOWN  0 must fix · 2 undecided · 1 passed ") {
		t.Fatalf("headline:\n%s", out)
	}
	if strings.Contains(strings.SplitN(out, "\n", 2)[0], "PASS (") {
		t.Fatalf("UNKNOWN read as PASS:\n%s", out)
	}
}

func TestIdenticalActionsAreGroupedAndVerboseListsEveryRule(t *testing.T) {
	t.Parallel()
	claims := []constraintengine.Claim{
		claim("r1", "UNKNOWN", "RULE_FACT_UNAVAILABLE", "declare things"),
		claim("r2", "UNKNOWN", "RULE_FACT_UNAVAILABLE", "declare things"),
		claim("r3", "UNKNOWN", "RULE_FACT_UNAVAILABLE", "declare things"),
	}
	short := render(t, Input{Exit: 11, Project: "p", Claims: claims})
	if strings.Count(short, "declare things") != 1 || strings.Contains(short, "r1") || !strings.Contains(short, "3 rules with the same action") {
		t.Fatalf("default report:\n%s", short)
	}
	verbose := render(t, Input{Exit: 11, Project: "p", Claims: claims, Verbose: true})
	for _, id := range []string{"r1", "r2", "r3"} {
		if !strings.Contains(verbose, "rule: "+id+" (UNKNOWN, RULE_FACT_UNAVAILABLE)") {
			t.Fatalf("-v lost %s:\n%s", id, verbose)
		}
	}
}

// A common final sentence is printed once, byte for byte, only when every
// listed action ends with it; -v never splits an action.
func TestCommonTrailingSentenceIsFactoredOnlyWhenEveryActionShares(t *testing.T) {
	t.Parallel()
	tail := "Validate admission separately."
	both := []constraintengine.Claim{
		claim("a", "BLOCKED", "R", "Fix A. "+tail),
		claim("b", "BLOCKED", "R", "Fix B. "+tail),
	}
	out := render(t, Input{Exit: 10, Project: "p", Claims: both})
	if strings.Count(out, tail) != 1 || !strings.Contains(out, "fix: Fix A.\n") {
		t.Fatalf("factored report:\n%s", out)
	}
	if v := render(t, Input{Exit: 10, Project: "p", Claims: both, Verbose: true}); strings.Count(v, tail) != 2 {
		t.Fatalf("-v must keep full actions:\n%s", v)
	}
	mixed := append(append([]constraintengine.Claim(nil), both...), claim("c", "BLOCKED", "R", "Fix C. Other ending."))
	if m := render(t, Input{Exit: 10, Project: "p", Claims: mixed}); strings.Count(m, tail) != 2 {
		t.Fatalf("a sentence not shared by every action must stay in place:\n%s", m)
	}
}

func TestPassedRulesAreListedOnlyOnRequestAndSourcesAreCounted(t *testing.T) {
	t.Parallel()
	pass := claim("ok", "PASS", "R", "recheck")
	pass.Sources = []constraintengine.SourceEvidence{{URL: "https://example.test/a", StartLine: 1, EndLine: 2, Revision: "r", ContentDigest: "sha256:d"}}
	hidden := render(t, Input{Exit: 0, Project: "p", Claims: []constraintengine.Claim{pass}})
	if strings.Contains(hidden, "PASSED (") || !strings.Contains(hidden, "1 passed rule (--show-passes)") || !strings.HasPrefix(hidden, "PASS (scoped)  0 must fix · 0 undecided · 1 passed") {
		t.Fatalf("default:\n%s", hidden)
	}
	shown := render(t, Input{Exit: 0, Project: "p", Claims: []constraintengine.Claim{pass}, ShowPasses: true, Verbose: true})
	if !strings.Contains(shown, "PASSED (1)") || !strings.Contains(shown, "if this changes: recheck") || !strings.Contains(shown, "https://example.test/a lines 1-2; revision r; digest sha256:d") {
		t.Fatalf("shown:\n%s", shown)
	}
}
