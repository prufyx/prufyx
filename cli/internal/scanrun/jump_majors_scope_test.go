// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Only a rule scoped to exactly the transition of the major hop decides it. A
// removal crossing, a rule anchored on other lines, a rule the run does not
// know and a notice of such a rule leave the hop undecided with
// MAJOR_HOP_NOT_COVERED; they never make it BLOCKED, ATTENTION or PASS.
func TestMajorHopDecidedOnlyByRulesScopedToItsTransition(t *testing.T) {
	t.Parallel()
	scoped := func(id string, notice bool, from, to string, crossing *constraintengine.CrossingSpec) cncfcheck.ScanRule {
		return cncfcheck.ScanRule{Notice: notice, Scope: lineattest.RuleScope{ID: id, Component: crdComponent, Transition: constraintengine.RuleTransition{From: from, To: to, Crossing: crossing}}}
	}
	rules := map[string]cncfcheck.ScanRule{
		"exact":        scoped("exact", false, "0.51.0", "1.0.0", nil),
		"exact-notice": scoped("exact-notice", true, "0.51.3", "1.0.2", nil),
		"crossing":     scoped("crossing", false, "0.51.0", "1.0.0", &constraintengine.CrossingSpec{}),
		"other-lines":  scoped("other-lines", false, "0.50.0", "1.0.0", nil),
		"wide-notice":  scoped("wide-notice", true, "0.51.0", "1.0.0", &constraintengine.CrossingSpec{}),
		"other-notice": scoped("other-notice", true, "0.49.0", "1.1.0", nil),
	}
	pass := &scanreport.FamilyResult{Family: lineattest.FamilyCustomResourceVersions, Status: scanreport.FamilyPass}
	compose := func(decision hopDecision) scanreport.Jump {
		run := &customResourceRun{knowledge: jumpKnowledge(t, nil), report: &scanreport.Report{}, slug: "strimzi", component: crdComponent, now: parseNow(t), byID: rules,
			rootGaps: map[scanreport.GapKey]scanreport.Gap{}}
		path := scanreport.Path{Component: "strimzi", Hops: []scanreport.Hop{
			{Index: 1, From: scanreport.Endpoint{Version: "0.50.1"}, To: scanreport.Endpoint{Line: "0.51"}},
			{Index: 2, From: scanreport.Endpoint{Line: "0.51"}, To: scanreport.Endpoint{Line: "1.0"}},
		}}
		decision.setDigest = "sha256:1"
		run.composeJump(&path, upgradepath.Plan{}, []hopDecision{{family: pass, setDigest: "sha256:1"}, decision})
		return *path.Jump
	}
	// The hop itself stays undecided, never PASS; a wider rule that blocks
	// makes the jump BLOCKED and a notice of one ATTENTION, both labelled.
	undecided := func(name, want string, decision hopDecision) {
		j := compose(decision)
		h := j.Hops[1]
		if h.Status != scanreport.JumpHopUndecided || !hasReason(h.Reasons, scanreport.ReasonMajorHopNotCovered) || !hasReason(h.Reasons, scanreport.ReasonLinesNotListed) || len(h.RuleIDs) != 0 || len(h.Entries) != 0 ||
			j.Status != want || j.Status == scanreport.JumpStepwisePass {
			t.Fatalf("%s: %+v", name, j)
		}
		if want != scanreport.JumpUnknown {
			if len(j.DecidedBy) != 1 || j.DecidedBy[0] != 2 || len(h.WiderRuleIDs)+len(h.WiderNoticeIDs) == 0 || len(j.Missing) != 2 || j.Missing[1].Hop != 2 {
				t.Fatalf("%s: decidedBy %v hop %+v missing %+v", name, j.DecidedBy, h, j.Missing)
			}
			text := strings.Join(scanreport.JumpLines("strimzi", "0.50.1", "1.0", j), "\n")
			if !strings.Contains(text, "wider-range rule, not scoped to this hop") {
				t.Fatalf("%s: text\n%s", name, text)
			}
		}
	}
	undecided("crossing block", scanreport.JumpBlocked, hopDecision{blocks: []string{"crossing"}})
	undecided("anchor on other lines", scanreport.JumpBlocked, hopDecision{blocks: []string{"other-lines"}})
	undecided("unknown rule", scanreport.JumpBlocked, hopDecision{blocks: []string{"missing"}})
	undecided("crossing notice", scanreport.JumpAttention, hopDecision{neutral: []neutralRule{{id: "wide-notice", text: "read", noticed: true}}})
	undecided("notice of other lines", scanreport.JumpAttention, hopDecision{neutral: []neutralRule{{id: "other-notice", text: "read", noticed: true}}})
	undecided("family pass alone", scanreport.JumpUnknown, hopDecision{family: pass})
	// A notice the engine did not give is no citation.
	undecided("unnoticed wide notice", scanreport.JumpUnknown, hopDecision{neutral: []neutralRule{{id: "wide-notice", text: "read"}}})
	// A wide rule beside an exact one: only the exact one decides.
	j := compose(hopDecision{blocks: []string{"crossing", "exact"}})
	if j.Status != scanreport.JumpBlocked || j.Hops[1].Status != scanreport.JumpHopBlocked || len(j.Hops[1].RuleIDs) != 1 || j.Hops[1].RuleIDs[0] != "exact" {
		t.Fatalf("exact beside wide: %+v", j)
	}
	// An exact notice still makes the hop ATTENTION (never a pass).
	j = compose(hopDecision{neutral: []neutralRule{{id: "exact-notice", text: "read", noticed: true}}})
	if j.Status != scanreport.JumpAttention || j.Hops[1].Status != scanreport.JumpHopAttention {
		t.Fatalf("exact notice: %+v", j)
	}
}

// The hop that leaves the last reviewed line of the old major names the lines
// the client does not know, and no hop is invented for them.
func TestMajorHopCarriesLinesNotListed(t *testing.T) {
	t.Parallel()
	result := majorScan(t, majorKnowledge(t, "0.50", "0.51", "1.1"), "0.49.0", "1.1.0")
	path, jump := strimziJump(t, result.Report)
	if len(path.Hops) != 4 || !hasReason(jump.Hops[2].Reasons, scanreport.ReasonLinesNotListed) {
		t.Fatalf("hops %d major hop %+v", len(path.Hops), jump.Hops[2])
	}
	for i, h := range jump.Hops {
		if i != 2 && hasReason(h.Reasons, scanreport.ReasonLinesNotListed) {
			t.Fatalf("hop %d %+v", i+1, h)
		}
	}
	found := false
	for _, gap := range result.Report.Gaps {
		if gap.Reason == scanreport.ReasonLinesNotListed && gap.Hop != nil && gap.Hop.Index == 3 && strings.Contains(gap.Detail, "release lines after 0.51 and before 1.0 are not known to this client; each needs its own review") && gap.Action != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
}
