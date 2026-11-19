// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// jumpPlan returns the stepwise plan of an upgrade through several minor
// lines of a component of the custom-resource family, or false.
//
// The stepwise path (one hop per minor line) is always a path upstream
// permits, so it is decomposed when the component has no reviewed path policy
// or the policy is sequential_minor. A policy that allows a direct hop, a
// policy by major line, an upgrade across a major line, a component whose
// lines are not consecutive minors and an upgrade of one line or of adjacent
// lines are never decomposed: the plan is the one the run always had.
//
// Each intermediate end is the highest final release that both the review of
// its line and the review of the next line read (and pin to one commit), so
// the hop's family can be decided; an intermediate line without one stays a
// whole line, which still finds a blocker (a rule covers the whole previous
// line) but never decides a family.
func (r *customResourceRun) jumpPlan(plan upgradepath.Plan, policy *upgradepath.PathPolicy, from, to string) (upgradepath.Plan, bool) {
	family, ok := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions)
	if !ok || !family.Admits(r.component) {
		return upgradepath.Plan{}, false
	}
	stepwise := plan
	switch {
	case policy == nil:
		stepwise = upgradepath.PlanPath(r.component, from, to, &upgradepath.PathPolicy{Component: r.component, Policy: upgradepath.PolicySequentialMinor})
	case policy.Policy != upgradepath.PolicySequentialMinor:
		return upgradepath.Plan{}, false
	}
	if stepwise.Gap != upgradepath.GapNone || len(stepwise.Hops) < 2 {
		return upgradepath.Plan{}, false
	}
	// Every hop must enter its line from the previous line of the
	// component's own scheme.
	previous, ok := endpointLine(stepwise.Hops[0].From)
	if !ok {
		return upgradepath.Plan{}, false
	}
	var lines []string
	for _, hop := range stepwise.Hops {
		line, ok := endpointLine(hop.To)
		if !ok || !lineattest.LineHop(r.component, previous, line) {
			return upgradepath.Plan{}, false
		}
		lines = append(lines, line)
		previous = line
	}
	out := stepwise
	out.Hops = append([]upgradepath.Hop(nil), stepwise.Hops...)
	for i := 0; i < len(out.Hops)-1; i++ {
		release, found := r.commonRelease(family, lines[i], lines[i+1])
		if !found {
			continue
		}
		out.Hops[i].To = upgradepath.Endpoint{Version: release.Version}
		out.Hops[i+1].From = upgradepath.Endpoint{Version: release.Version}
	}
	return out, true
}

func endpointLine(e upgradepath.Endpoint) (string, bool) {
	if e.MinorLine() {
		return e.Line, true
	}
	if e.Exact() {
		return lineattest.LineOf(e.Version)
	}
	return "", false
}

// currentReview is the one attestation of the family for the line when it is
// current, of the line, family and component asked, and on a basis the trust
// policy admits.
func (r *customResourceRun) currentReview(family lineattest.Family, line string) (lineattest.LineAttestation, bool) {
	statuses := r.knowledge.AttestationsFor(r.component, line, family.ID, r.now)
	if len(statuses) != 1 || !statuses[0].Current() {
		return lineattest.LineAttestation{}, false
	}
	a := statuses[0].Attestation
	if a.Line != line || a.FactFamily != family.ID || a.Component != r.component || a.Releases == nil || !r.policy.Admits(a.Evidence.Basis) {
		return lineattest.LineAttestation{}, false
	}
	return a, true
}

// commonRelease is the highest final release of line that the review of line
// read as a release of its own line and the review of next read as a release
// of the line before it, with the same commit in both. A pre-release, a
// release of another line and a version that does not compare never qualify.
func (r *customResourceRun) commonRelease(family lineattest.Family, line, next string) (lineattest.Release, bool) {
	own, ok := r.currentReview(family, line)
	if !ok {
		return lineattest.Release{}, false
	}
	following, ok := r.currentReview(family, next)
	if !ok {
		return lineattest.Release{}, false
	}
	var best lineattest.Release
	found := false
	for _, candidate := range own.Releases.To {
		if constraintengine.PreRelease(candidate.Version) {
			continue
		}
		if l, ok := lineattest.LineOf(candidate.Version); !ok || l != line {
			continue
		}
		matched := false
		for _, other := range following.Releases.From {
			if other.Version == candidate.Version && other.Commit == candidate.Commit {
				matched = true
			}
		}
		if !matched {
			continue
		}
		if found {
			if order, ok := constraintengine.CompareVersions(best.Version, candidate.Version); !ok || order >= 0 {
				continue
			}
		}
		best, found = candidate, true
	}
	return best, found
}

// composeJump records the jump of a planned path: every hop with its own
// status, from the hop's decision alone. A hop is BLOCKED only by a rule that
// blocked it, PASS only by the PASS result of its line review, and anything
// else is UNDECIDED with a named gap. The jump never changes a finding, a
// gap's meaning, the verdict or the exit code.
func (r *customResourceRun) composeJump(path *scanreport.Path, plan upgradepath.Plan, decisions []hopDecision) {
	if len(path.Hops) != len(decisions) || len(decisions) < 2 {
		return
	}
	digest := decisions[0].setDigest
	family, _ := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions)
	hops := make([]scanreport.JumpHop, 0, len(path.Hops))
	var releases []scanreport.JumpRelease
	for i := range path.Hops {
		hop, decision := &path.Hops[i], decisions[i]
		ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String()}
		jump := scanreport.JumpHop{Index: hop.Index, From: hop.From.String(), To: hop.To.String(), ObjectSetDigest: decision.setDigest, Attestation: hop.Attestation}
		switch {
		case len(decision.blocks) > 0:
			jump.Status, jump.RuleIDs = scanreport.JumpHopBlocked, decision.blocks
		case len(decision.neutral) > 0:
			// A notice or lead rule overlaps the hop. It decides nothing, so
			// the hop is never a pass: ATTENTION citing the notice when the
			// engine gave it one, UNDECIDED otherwise.
			all := true
			for _, n := range decision.neutral {
				all = all && n.noticed
			}
			if all {
				jump.Status = scanreport.JumpHopAttention
				for _, n := range decision.neutral {
					jump.Entries = append(jump.Entries, n.id+": "+n.text)
				}
				break
			}
			jump.Status = scanreport.JumpHopUndecided
			for _, n := range decision.neutral {
				if !n.noticed {
					hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapRuleNotDecided, n.id, "NOTICE_OR_LEAD_RULE_OVERLAPS_HOP"))
				}
			}
		case decision.family != nil && decision.family.Status == scanreport.FamilyPass && hop.From.Version != "" && hop.To.Version != "":
			jump.Status = scanreport.JumpHopPass
		default:
			jump.Status = scanreport.JumpHopUndecided
			toLine, _ := endpointLine(upgradepath.Endpoint{Version: hop.To.Version, Line: hop.To.Line})
			switch {
			case len(r.knowledge.AttestationsFor(r.component, toLine, family.ID, r.now)) != 1:
				hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapCustomResourceJumpNoReview, toLine))
			case hop.From.Version == "" || hop.To.Version == "":
				line := hop.From.Line
				if hop.From.Version != "" {
					line = hop.To.Line
				}
				hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapCustomResourceJumpRelease, line))
			case !hopHasSpecificGap(*hop):
				hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapCustomResourceJumpOpen, hop.To.Version))
			}
		}
		for _, reason := range hop.Reasons {
			if reason != r.rootGaps[scanreport.GapCustomResourcesOnly].Reason {
				jump.Reasons = append(jump.Reasons, reason)
			}
		}
		jump.Reasons = uniqueStrings(jump.Reasons)
		hops = append(hops, jump)
		if i < len(path.Hops)-1 && hop.To.Version != "" {
			if line, ok := lineattest.LineOf(hop.To.Version); ok {
				releases = append(releases, scanreport.JumpRelease{Line: line, Version: hop.To.Version, Commit: r.releaseCommit(family, line, hop.To.Version)})
			}
		}
	}
	actions := map[int]string{}
	for _, gap := range r.report.Gaps {
		if gap.Hop != nil && !gap.Hop.WholeUpgrade && gap.Component == r.slug && actions[gap.Hop.Index] == "" {
			actions[gap.Hop.Index] = gap.Action
		}
	}
	jump := scanreport.NewJump(hops, digest, releases, actions)
	path.Jump = &jump
}

// hopHasSpecificGap reports whether the hop already names a reason beyond
// the component-level one.
func hopHasSpecificGap(hop scanreport.Hop) bool {
	for _, reason := range hop.Reasons {
		if reason != scanreport.ReasonComponentNotCovered {
			return true
		}
	}
	return false
}

// releaseCommit is the commit the review of line pins release to.
func (r *customResourceRun) releaseCommit(family lineattest.Family, line, version string) string {
	if a, ok := r.currentReview(family, line); ok {
		for _, release := range a.Releases.To {
			if release.Version == version {
				return release.Commit
			}
		}
	}
	return ""
}

// kubernetesJumpScope is the sentence a Kubernetes jump carries: what it
// covers and what it does not. It replaces the custom-resource scope.
const kubernetesJumpScope = "composed from the hops of the planned path through the named releases, from the reviewed removed-API rules, " +
	"line reviews and one-way notices that apply to each hop, for the objects of the manifests as they are today; " +
	"a direct skip of a release line, other patch releases of an intermediate line, behaviour changes without a removed API, " +
	"and gaps the report lists outside any hop are not part of a pass"

// objectSetDigest is the digest of the object content a hop was evaluated on
// and of the install profile: the workspace content digest and every
// declaration that selects the facts. It does not depend on the versions of
// the hop. An empty content digest gives no digest, so no hop composes.
func (r *kubernetesRun) objectSetDigest(contentDigest string) string {
	if contentDigest == "" {
		return ""
	}
	d := r.declarations
	h := sha256.New()
	for _, part := range []string{"prufyx/k8s-object-set/v1", contentDigest, d.distribution, fmt.Sprint(d.distributionSet), fmt.Sprint(d.scopeComplete), fmt.Sprint(d.applyRequired), d.kubelet.Minimum, d.kubelet.Maximum} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// neutralOf describes a notice or lead rule that overlaps a hop: noticed means
// the trust policy admits the rule, the rule is a notice, it covers the hop
// and the engine gave it a NOTICE claim. Anything else (a lead, a rule the
// policy left out, a rule that does not cover the hop or that the engine did
// not decide) is not noticed, so its hop is never a pass.
func (r *kubernetesRun) neutralOf(rule cncfcheck.ScanRule, eval evaluation, covers bool) neutralRule {
	claim, found := eval.claims[rule.Scope.ID]
	noticed := rule.Notice && covers && found && claim.Status == constraintengine.StatusNotice && r.policy.Admits(rule.Basis)
	return neutralRule{id: rule.Scope.ID, text: rule.NextAction, noticed: noticed}
}

// composeJump records the jump of a Kubernetes route of several hops with the
// shared composition (scanreport.NewJump): a hop is BLOCKED only by a finding
// that names a rule at that hop, ATTENTION by a one-way notice at it, PASS
// only when the hop is COVERED, and anything else is UNDECIDED with its
// reasons. A gap outside every hop (or one of the whole upgrade) keeps every
// otherwise passing hop from PASS, and a blocker of the whole upgrade, which
// no hop owns, is cited on the last hop. The jump never changes a finding, a
// gap, the verdict or the exit code.
func (r *kubernetesRun) composeJump(path *scanreport.Path) {
	if len(path.Hops) < 2 {
		return
	}
	digest := r.hopDigests[path.Hops[0].Index]
	var open []string
	if len(r.wholeNeutral) > 0 {
		// A notice or lead of the whole upgrade belongs to no hop.
		open = append(open, scanreport.ReasonRuleNotDecided)
	}
	var wholeBlocks []string
	for _, gap := range r.report.Gaps {
		if gap.Component == kubernetesSlug && (gap.Hop == nil || gap.Hop.WholeUpgrade) {
			open = append(open, gap.Reason)
		}
	}
	for _, f := range r.report.Findings {
		if f.Component == kubernetesSlug && f.Hop.WholeUpgrade {
			wholeBlocks = append(wholeBlocks, f.RuleID)
		}
	}
	at := func(ref scanreport.HopRef, own scanreport.HopRef, also []scanreport.HopRef) bool {
		if own == ref {
			return true
		}
		for _, other := range also {
			if other == ref {
				return true
			}
		}
		return false
	}
	hops := make([]scanreport.JumpHop, 0, len(path.Hops))
	for i := range path.Hops {
		hop := path.Hops[i]
		ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String()}
		jump := scanreport.JumpHop{Index: hop.Index, From: ref.From, To: ref.To, ObjectSetDigest: r.hopDigests[hop.Index], Attestation: hop.Attestation}
		var blocks []string
		for _, f := range r.report.Findings {
			if f.Component == kubernetesSlug && at(ref, f.Hop, f.AlsoAt) {
				blocks = append(blocks, f.RuleID)
			}
		}
		if i == len(path.Hops)-1 {
			blocks = append(blocks, wholeBlocks...)
		}
		var entries []string
		noticedAll := len(r.hopNeutral[hop.Index]) > 0
		for _, n := range r.hopNeutral[hop.Index] {
			noticedAll = noticedAll && n.noticed
			if n.noticed {
				entries = append(entries, n.id+": "+n.text)
			}
		}
		switch {
		case (hop.Status == scanreport.HopBlocked && len(blocks) > 0) || (i == len(path.Hops)-1 && len(wholeBlocks) > 0):
			jump.Status, jump.RuleIDs = scanreport.JumpHopBlocked, uniqueStrings(blocks)
		case noticedAll && hop.Status != scanreport.HopBlocked:
			// A notice rule overlaps the hop and decides nothing: ATTENTION
			// citing it, never a pass.
			jump.Status, jump.Entries = scanreport.JumpHopAttention, uniqueStrings(entries)
		case hop.Status == scanreport.HopCovered && len(open) == 0 && len(r.hopNeutral[hop.Index]) == 0:
			jump.Status = scanreport.JumpHopPass
		default:
			jump.Status = scanreport.JumpHopUndecided
			reasons := append(append([]string{}, hop.Reasons...), open...)
			if len(r.hopNeutral[hop.Index]) > 0 {
				reasons = append(reasons, scanreport.ReasonRuleNotDecided)
			}
			jump.Reasons = uniqueStrings(reasons)
		}
		hops = append(hops, jump)
	}
	// The next action of an undecided hop is that of the first gap that
	// explains it, so no hop falls back to the generic custom-resource text.
	actions := map[int]string{}
	for _, hop := range hops {
		if hop.Status != scanreport.JumpHopUndecided {
			continue
		}
		for _, gap := range r.report.Gaps {
			if gap.Component != kubernetesSlug || gap.Action == "" || actions[hop.Index] != "" {
				continue
			}
			if (gap.Hop != nil && !gap.Hop.WholeUpgrade && gap.Hop.Index == hop.Index) || (gap.Hop == nil && slices.Contains(hop.Reasons, gap.Reason)) {
				actions[hop.Index] = gap.Action
			}
		}
		if actions[hop.Index] == "" {
			actions[hop.Index] = "check this hop's upgrade notes and the removed APIs of its release lines by hand"
		}
	}
	jump := scanreport.NewJump(hops, digest, nil, actions)
	jump.Scope = kubernetesJumpScope
	path.Jump = &jump
}
