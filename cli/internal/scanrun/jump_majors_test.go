// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Lines 0.50, 0.51 of the test-only Strimzi reviews plus the line 1.1 of the
// next major (never published). A first line X.0 has no previous line, so no
// review of it can exist.
func majorKnowledge(t *testing.T, lines ...string) attestedCRD {
	t.Helper()
	all := map[string]lineattest.LineAttestation{
		"0.50": jumpAtt("0.50", jumpReleases("0.49.0", "0.49.1"), jumpReleases("0.50.0", "0.50.1"), ""),
		"0.51": jumpAtt("0.51", jumpReleases("0.50.0", "0.50.1"), jumpReleases("0.51.0"), ""),
		"1.1":  jumpAtt("1.1", jumpReleases("1.0.0"), jumpReleases("1.1.0"), ""),
	}
	var atts []lineattest.LineAttestation
	for _, line := range lines {
		atts = append(atts, all[line])
	}
	k := attestedCRD{crdKnowledge: newCRDKnowledge(t)}
	k.attestations = lineattest.NewIndex(atts)
	return k
}

func majorScan(t *testing.T, k Knowledge, from, to string) Result {
	t.Helper()
	return crdScan(t, k, []string{settingsDoc, kafkaV1Doc}, "--from", "strimzi="+from, "--to", "strimzi="+to, "--resource-scope-complete")
}

// A jump across a major line is split into the minor hops of both majors and
// ONE explicit hop that changes the major. The minor hops that every review
// decides pass; the major hop is undecided with its own gap, so the jump is
// never STEPWISE_PASS and never a bare UNKNOWN.
func TestJumpAcrossMajorListsMinorHopsAndTheMajorHop(t *testing.T) {
	t.Parallel()
	result := majorScan(t, majorKnowledge(t, "0.50", "0.51", "1.1"), "0.49.0", "1.1.0")
	path, jump := strimziJump(t, result.Report)
	if len(path.Hops) != 4 {
		t.Fatalf("hops %+v", path.Hops)
	}
	var steps []string
	for _, h := range path.Hops {
		steps = append(steps, h.From.String()+">"+h.To.String())
	}
	want := []string{"0.49.0>0.50.1", "0.50.1>0.51", "0.51>1.0", "1.0>1.1.0"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("steps %v want %v", steps, want)
	}
	requireNeverBare(t, "major jump", jump, 4)
	if jump.Status == scanreport.JumpStepwisePass || jump.Status != scanreport.JumpUnknown {
		t.Fatalf("jump status %s", jump.Status)
	}
	major := jump.Hops[2]
	if major.Status != scanreport.JumpHopUndecided || !hasReason(major.Reasons, scanreport.ReasonMajorHopNotCovered) {
		t.Fatalf("major hop %+v", major)
	}
	for _, i := range []int{0, 1, 3} {
		if jump.Hops[i].Status == scanreport.JumpHopBlocked || hasReason(jump.Hops[i].Reasons, scanreport.ReasonMajorHopNotCovered) {
			t.Fatalf("hop %d %+v", i+1, jump.Hops[i])
		}
	}
	text := jumpText(result.Report)
	if !strings.Contains(text, "hop 3 0.51 -> 1.0: UNDECIDED") || !strings.Contains(text, "major upgrade: no reviewed rule for 0.51 -> 1.0") {
		t.Fatalf("text:\n%s", text)
	}
	if result.Exit != 11 || result.Report.Verdict != scanreport.VerdictUnknown {
		t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
	}
}

// Even when every review says the minor hops pass, a hop across the major
// line is not a pass by the absence of rules: negative acceptance path.
func TestJumpAcrossMajorNeverPassesWithoutRules(t *testing.T) {
	t.Parallel()
	for name, lines := range map[string][]string{
		"all lines reviewed":   {"0.50", "0.51", "1.1"},
		"no review of 1.x":     {"0.50", "0.51"},
		"no review at all":     {},
		"only the major line":  {"1.1"},
		"only old major lines": {"0.50"},
	} {
		result := majorScan(t, majorKnowledge(t, lines...), "0.49.0", "1.1.0")
		path, jump := strimziJump(t, result.Report)
		if result.Report.Verdict == scanreport.VerdictPass || result.Exit == 0 || jump == nil || jump.Status == scanreport.JumpStepwisePass {
			t.Fatalf("%s: verdict %s exit %d jump %+v", name, result.Report.Verdict, result.Exit, jump)
		}
		requireNeverBare(t, name, jump, len(path.Hops))
		majors := 0
		for _, h := range jump.Hops {
			if hasReason(h.Reasons, scanreport.ReasonMajorHopNotCovered) {
				majors++
				if h.Status != scanreport.JumpHopUndecided {
					t.Fatalf("%s: major hop %+v", name, h)
				}
			}
		}
		if majors != 1 {
			t.Fatalf("%s: %d major hops in %+v", name, majors, jump.Hops)
		}
	}
}

// The jump across the major starts at the first line of the new major and
// every minor line of it up to the target is a hop of its own.
func TestJumpAcrossMajorStartsTheNewMajorAtItsFirstLine(t *testing.T) {
	t.Parallel()
	result := majorScan(t, majorKnowledge(t), "0.51.0", "1.1.0")
	path, jump := strimziJump(t, result.Report)
	if len(path.Hops) != 2 || path.Hops[0].To.String() != "1.0" || path.Hops[1].From.String() != "1.0" || path.Hops[1].To.String() != "1.1.0" {
		t.Fatalf("hops %+v", path.Hops)
	}
	requireNeverBare(t, "no reviews", jump, 2)
	// An upgrade to the first release of the next major is one major hop.
	result = majorScan(t, majorKnowledge(t, "1.1"), "0.51.0", "1.0.0")
	path, _ = strimziJump(t, result.Report)
	if len(path.Hops) != 1 {
		t.Fatalf("hops %+v", path.Hops)
	}
}

// A component the scan does not cover still lists the requested path: every
// hop undecided with COMPONENT_NOT_COVERED and its next action. No hop and no
// jump is a pass, and the verdict and exit code are the ones without it.
func TestUncoveredComponentListsItsHops(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		from, to string
		hops     int
	}{
		"minor lines":                   {"2.14.1", "2.19.0", 5},
		"across a major (no line data)": {"2.14.1", "3.0.0", 1},
		"one line":                      {"2.14.1", "2.15.0", 1},
	} {
		result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1Doc}, "--from", "jaeger="+tc.from, "--to", "jaeger="+tc.to, "--resource-scope-complete")
		var found *scanreport.Path
		for i := range result.Report.Paths {
			if result.Report.Paths[i].Component == "jaeger" {
				found = &result.Report.Paths[i]
			}
		}
		if found == nil || len(found.Hops) != tc.hops || found.Jump == nil || len(found.Jump.Hops) != tc.hops {
			t.Fatalf("%s: path %+v", name, found)
		}
		if found.Jump.Status != scanreport.JumpUnknown || result.Report.Verdict != scanreport.VerdictUnknown || result.Exit != 11 {
			t.Fatalf("%s: jump %s verdict %s exit %d", name, found.Jump.Status, result.Report.Verdict, result.Exit)
		}
		if tc.hops > 1 {
			requireNeverBare(t, name, found.Jump, tc.hops)
		}
		for i, h := range found.Hops {
			if h.Status != scanreport.HopNoData || !reflect.DeepEqual(h.Reasons, []string{scanreport.ReasonComponentNotCovered}) {
				t.Fatalf("%s: hop %d %+v", name, i+1, h)
			}
			if found.Jump.Hops[i].Status != scanreport.JumpHopUndecided || !strings.Contains(found.Jump.Missing[i].Evidence, scanreport.ReasonComponentNotCovered) {
				t.Fatalf("%s: jump hop %d %+v missing %+v", name, i+1, found.Jump.Hops[i], found.Jump.Missing[i])
			}
		}
		if !hasComponentGap(result.Report, "jaeger", scanreport.ReasonComponentNotCovered, "") {
			t.Fatalf("%s: the component gap is missing", name)
		}
	}
}

// An unusable pair of versions plans nothing, as before.
func TestUncoveredComponentWithBadVersionsHasNoPath(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{{"2.19.0", "2.14.1"}, {"2.14.1", "2.14.1"}} {
		result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1Doc}, "--from", "jaeger="+pair[0], "--to", "jaeger="+pair[1], "--resource-scope-complete")
		for _, path := range result.Report.Paths {
			if path.Component == "jaeger" {
				t.Fatalf("%v: path %+v", pair, path)
			}
		}
		if result.Report.Verdict != scanreport.VerdictUnknown {
			t.Fatalf("%v: verdict %s", pair, result.Report.Verdict)
		}
	}
}

func hasReason(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
