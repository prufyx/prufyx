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
	if !strings.HasPrefix(out, "UNKNOWN  0 must fix · 2 undecided     ") {
		t.Fatalf("headline:\n%s", out)
	}
	if strings.Contains(strings.SplitN(out, "\n", 2)[0], "PASS (") {
		t.Fatalf("UNKNOWN read as PASS:\n%s", out)
	}
}

// The headline leads with the verdict. A pass count never sits in the
// headline of an UNKNOWN or BLOCKED report; it follows as a "checked:" line.
func TestHeadlineStatesVerdictFirst(t *testing.T) {
	t.Parallel()
	pass := claim("a", "PASS", "R", "x")
	unknown := claim("b", "UNKNOWN", "RULE_FACT_UNAVAILABLE", "y")
	blocked := claim("c", "BLOCKED", "B", "z")
	for _, tc := range []struct {
		name       string
		exit       int
		claims     []constraintengine.Claim
		wantPrefix string
		wantSecond string
	}{
		{"unknown with passes", 11, []constraintengine.Claim{pass, pass, unknown}, "UNKNOWN  0 must fix · 1 undecided     ", "checked: 2 rules passed; this is not a pass"},
		{"unknown one pass", 11, []constraintengine.Claim{pass, unknown}, "UNKNOWN  0 must fix · 1 undecided     ", "checked: 1 rule passed; this is not a pass"},
		{"unknown no passes", 11, []constraintengine.Claim{unknown}, "UNKNOWN  0 must fix · 1 undecided     ", ""},
		{"blocked with passes", 10, []constraintengine.Claim{pass, blocked}, "BLOCKED  1 must fix · 0 undecided     ", "checked: 1 rule passed; this is not a pass"},
		{"pass unchanged", 0, []constraintengine.Claim{pass, pass}, "PASS (scoped)  0 must fix · 0 undecided · 2 passed     ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(render(t, Input{Exit: tc.exit, Project: "p", Claims: tc.claims}), "\n")
			if !strings.HasPrefix(lines[0], tc.wantPrefix) {
				t.Fatalf("headline %q, want prefix %q", lines[0], tc.wantPrefix)
			}
			if tc.exit != 0 && strings.Contains(lines[0], "passed") {
				t.Fatalf("pass count in non-PASS headline %q", lines[0])
			}
			second := ""
			if strings.HasPrefix(lines[1], "checked:") {
				second = lines[1]
			}
			if second != tc.wantSecond {
				t.Fatalf("second line %q, want %q", lines[1], tc.wantSecond)
			}
		})
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

func sourced(status string, sources ...constraintengine.SourceEvidence) constraintengine.Claim {
	c := claim("r1", status, "R", "Fix it.")
	c.Sources = sources
	return c
}

func TestListedClaimShowsExactSourceCitation(t *testing.T) {
	t.Parallel()
	src := constraintengine.SourceEvidence{
		URL:           "https://github.com/argoproj/argo-cd/blob/7cedae735ca5c68fc24520b42da339aa388b9d25/VERSION",
		Revision:      "7cedae735ca5c68fc24520b42da339aa388b9d25",
		ContentDigest: "sha256:4be81e8be837feae319a9f87e070bc2cb4758612bdf878fdb2c05797a816e06d",
		StartLine:     3, EndLine: 9,
	}
	for _, status := range []string{"BLOCKED", "UNKNOWN"} {
		out := render(t, Input{Exit: 10, Project: "p", Claims: []constraintengine.Claim{sourced(status, src)}})
		want := "    source: argoproj/argo-cd/VERSION @ 7cedae735ca5, lines 3-9, sha256:4be81e8be837\n"
		if !strings.Contains(out, want) {
			t.Fatalf("%s: missing %q in:\n%s", status, want, out)
		}
	}
}

func TestSourceCitationCannotForgeReportLines(t *testing.T) {
	t.Parallel()
	src := constraintengine.SourceEvidence{
		URL:           "https://example.test/a\nBLOCKED  0 must fix\x1b[31m\u2028PASS (scoped)\u202e\u2066",
		Revision:      "abc\r\nPASS (scoped)",
		ContentDigest: "sha256:ab\ncd",
		StartLine:     1, EndLine: 2,
	}
	out := render(t, Input{Exit: 11, Project: "p", Claims: []constraintengine.Claim{sourced("UNKNOWN", src)}})
	if strings.ContainsAny(out, "\r\x1b") {
		t.Fatalf("control characters reached the report:\n%q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "BLOCKED") || strings.HasPrefix(line, "PASS") {
			t.Fatalf("forged line %q in:\n%s", line, out)
		}
	}
}

func TestSourceListIsBounded(t *testing.T) {
	t.Parallel()
	var sources []constraintengine.SourceEvidence
	for i := 0; i < 5; i++ {
		sources = append(sources, constraintengine.SourceEvidence{URL: "https://example.test/x", Revision: "r", ContentDigest: "sha256:d", StartLine: i + 1, EndLine: i + 2})
	}
	c := []constraintengine.Claim{sourced("BLOCKED", sources...)}
	out := render(t, Input{Exit: 10, Project: "p", Claims: c})
	if strings.Count(out, "    source: ") != 3 || !strings.Contains(out, "    +2 more sources, see --format json\n") {
		t.Fatalf("default:\n%s", out)
	}
	if v := render(t, Input{Exit: 10, Project: "p", Claims: c, Verbose: true}); strings.Count(v, "    source: ") != 5 {
		t.Fatalf("verbose:\n%s", v)
	}
}

func TestSourceLineOmitsMissingFieldsAndStripsURLSecrets(t *testing.T) {
	t.Parallel()
	got := render(t, Input{Exit: 10, Project: "p", Claims: []constraintengine.Claim{
		sourced("BLOCKED", constraintengine.SourceEvidence{URL: "https://example.test/a"}),
	}})
	if !strings.Contains(got, "    source: https://example.test/a\n") {
		t.Fatalf("missing fields must be omitted:\n%s", got)
	}
	for _, bad := range []string{" @ ", "lines 0-0", ", \n"} {
		if strings.Contains(got, bad) {
			t.Fatalf("empty field printed (%q):\n%s", bad, got)
		}
	}
	none := render(t, Input{Exit: 10, Project: "p", Claims: []constraintengine.Claim{
		sourced("BLOCKED", constraintengine.SourceEvidence{Revision: "r", StartLine: 1, EndLine: 2}),
	}})
	if strings.Contains(none, "source:") {
		t.Fatalf("a source without URL must print no line:\n%s", none)
	}
	line, ok := SourceLine(constraintengine.SourceEvidence{URL: "https://user:tok@example.test/a?token=x#frag", Revision: "r", ContentDigest: "sha256:d", StartLine: 1, EndLine: 2})
	if !ok || line != "https://example.test/a @ r, lines 1-2, sha256:d" {
		t.Fatalf("url not stripped: %q", line)
	}
}
