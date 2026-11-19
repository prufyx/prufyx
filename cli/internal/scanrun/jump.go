// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
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
