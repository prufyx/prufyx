// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
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
	undecided := func(name string, decision hopDecision) {
		j := compose(decision)
		h := j.Hops[1]
		if h.Status != scanreport.JumpHopUndecided || !hasReason(h.Reasons, scanreport.ReasonMajorHopNotCovered) || len(h.RuleIDs) != 0 || len(h.Entries) != 0 ||
			j.Status == scanreport.JumpStepwisePass || j.Status == scanreport.JumpBlocked || j.Status == scanreport.JumpAttention {
			t.Fatalf("%s: %+v", name, j)
		}
	}
	undecided("crossing block", hopDecision{blocks: []string{"crossing"}})
	undecided("anchor on other lines", hopDecision{blocks: []string{"other-lines"}})
	undecided("unknown rule", hopDecision{blocks: []string{"missing"}})
	undecided("crossing notice", hopDecision{neutral: []neutralRule{{id: "wide-notice", text: "read", noticed: true}}})
	undecided("notice of other lines", hopDecision{neutral: []neutralRule{{id: "other-notice", text: "read", noticed: true}}})
	undecided("family pass alone", hopDecision{family: pass})
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
