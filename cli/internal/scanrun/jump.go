// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
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
	if policy != nil && policy.Policy != upgradepath.PolicySequentialMinor {
		return upgradepath.Plan{}, false
	}
	if crossesMajor(from, to) {
		return r.majorPlan(family, policy, from, to)
	}
	stepwise := plan
	if policy == nil {
		stepwise = upgradepath.PlanPath(r.component, from, to, &upgradepath.PathPolicy{Component: r.component, Policy: upgradepath.PolicySequentialMinor})
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

// majorOf is the major number of a version or of a line "M.m".
func majorOf(value string) (uint64, bool) {
	line := value
	if !lineattest.ValidLine(value) {
		var ok bool
		if line, ok = lineattest.LineOf(value); !ok {
			return 0, false
		}
	}
	major, _, ok := splitLine(line)
	return major, ok
}

func splitLine(line string) (major, minor uint64, ok bool) {
	parts := strings.Split(line, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, err1 := strconv.ParseUint(parts[0], 10, 32)
	minor, err2 := strconv.ParseUint(parts[1], 10, 32)
	return major, minor, err1 == nil && err2 == nil
}

// crossesMajor reports whether both versions are valid and the target is on a
// higher major line.
func crossesMajor(from, to string) bool {
	fm, ok1 := majorOf(from)
	tm, ok2 := majorOf(to)
	return ok1 && ok2 && tm > fm
}

// isMajorHop reports whether the hop changes the major line.
func isMajorHop(hop scanreport.Hop) bool {
	oldMajor, ok1 := majorOf(firstNonEmpty(hop.From.Version, hop.From.Line))
	newMajor, ok2 := majorOf(firstNonEmpty(hop.To.Version, hop.To.Line))
	return ok1 && ok2 && oldMajor != newMajor
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// majorPlan is the path of an upgrade across one or more major lines, for a
// component with ordinary minor lines: the minor lines of the old major that
// the knowledge reviews (every line from the actual line up to the last
// line it reviews, a line it does not review stays its own hop), then ONE hop that enters the first line of the
// next major (X.0), then the minor lines of that major up to the target. A
// major in between enters its own X.0 the same way and has the lines it
// reviews. The hop that changes the major is its own hop, never merged into a
// neighbour. The path never replaces a rule or a review: the hops are only
// what the run evaluates.
func (r *customResourceRun) majorPlan(family lineattest.Family, policy *upgradepath.PathPolicy, from, to string) (upgradepath.Plan, bool) {
	if lineattest.CalverComponent(r.component) || lineattest.PublishedLineComponent(r.component) {
		return upgradepath.Plan{}, false
	}
	// The same refusals as every plan: versions, pre-release, order.
	if check := upgradepath.PlanPath(r.component, from, to, nil); check.Gap != upgradepath.GapNone {
		return upgradepath.Plan{}, false
	}
	fromLine, _ := lineattest.LineOf(from)
	toLine, _ := lineattest.LineOf(to)
	fm, fmin, ok1 := splitLine(fromLine)
	tm, tmin, ok2 := splitLine(toLine)
	if !ok1 || !ok2 || tm <= fm {
		return upgradepath.Plan{}, false
	}
	reviewed := func(line string) bool {
		return len(r.knowledge.AttestationsFor(r.component, line, family.ID, r.now)) == 1
	}
	var lines []string
	line := func(major, minor uint64) string {
		return strconv.FormatUint(major, 10) + "." + strconv.FormatUint(minor, 10)
	}
	// An unreviewed line between reviewed ones stays its own hop (undecided);
	// the tail ends at the last reviewed line within MaxHops lines.
	tail := func(major, first uint64) {
		last := uint64(0)
		for minor := first; minor < first+upgradepath.MaxHops; minor++ {
			if reviewed(line(major, minor)) {
				last = minor
			}
		}
		for minor := first; last >= first && minor <= last; minor++ {
			lines = append(lines, line(major, minor))
		}
	}
	tail(fm, fmin+1)
	for major := fm + 1; major <= tm; major++ {
		lines = append(lines, line(major, 0))
		if major == tm {
			for minor := uint64(1); minor <= tmin && len(lines) <= upgradepath.MaxHops; minor++ {
				lines = append(lines, line(major, minor))
			}
			continue
		}
		tail(major, 1)
	}
	if len(lines) > upgradepath.MaxHops || len(lines) < 1 || lines[len(lines)-1] != toLine {
		return upgradepath.Plan{}, false
	}
	out := upgradepath.Plan{Component: r.component, Hops: make([]upgradepath.Hop, 0, len(lines))}
	if policy != nil {
		out.Policy = policy.Policy
	}
	for i, entered := range lines {
		hop := upgradepath.Hop{Index: i + 1, From: upgradepath.Endpoint{Version: from}, To: upgradepath.Endpoint{Line: entered}}
		if i > 0 {
			hop.From = upgradepath.Endpoint{Line: lines[i-1]}
		}
		if i == len(lines)-1 {
			hop.To = upgradepath.Endpoint{Version: to}
		}
		out.Hops = append(out.Hops, hop)
	}
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
	if len(path.Hops) != len(decisions) || len(decisions) < 1 {
		return
	}
	// One hop is a jump only when it is the hop that changes the major line;
	// a direct one-hop upgrade has no jump object.
	if len(decisions) == 1 && !isMajorHop(path.Hops[0]) {
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
		major := isMajorHop(*hop)
		if major {
			// Only a rule scoped to exactly this transition decides the
			// change of major line. A wider rule (a removal crossing, an
			// anchor on other lines) or a notice over it stays a finding or
			// notice of the whole upgrade and decides nothing here.
			exact := r.exactMajorIDs(decision.blocks, *hop)
			for _, id := range decision.blocks {
				if !slices.Contains(exact, id) {
					jump.WiderRuleIDs = append(jump.WiderRuleIDs, id)
				}
			}
			decision.blocks = exact
			var neutral []neutralRule
			for _, n := range decision.neutral {
				switch {
				case len(r.exactMajorIDs([]string{n.id}, *hop)) == 1:
					neutral = append(neutral, n)
				case n.noticed:
					jump.WiderNoticeIDs = append(jump.WiderNoticeIDs, n.id)
				}
			}
			decision.neutral = neutral
		}
		if major && len(decision.blocks) == 0 && !allNoticed(decision.neutral) {
			// The change of major line is decided only by a rule scoped to
			// that transition; the absence of one is never a pass.
			fromLine, _ := endpointLine(upgradepath.Endpoint{Version: hop.From.Version, Line: hop.From.Line})
			toLine, _ := endpointLine(upgradepath.Endpoint{Version: hop.To.Version, Line: hop.To.Line})
			hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapMajorHopNotCovered, fromLine, toLine))
		}
		if major {
			// The client holds no list of the release lines between the
			// last reviewed line of the old major and the first of the next.
			fromLine, _ := endpointLine(upgradepath.Endpoint{Version: hop.From.Version, Line: hop.From.Line})
			next, _ := majorOf(firstNonEmpty(hop.To.Version, hop.To.Line))
			hop.Reasons = append(hop.Reasons, r.gap(&ref, scanreport.GapLinesNotListed, fromLine, next))
		}
		switch {
		case len(decision.blocks) > 0:
			jump.Status, jump.RuleIDs = scanreport.JumpHopBlocked, decision.blocks
		case len(decision.neutral) > 0:
			// A notice or lead rule overlaps the hop. It decides nothing, so
			// the hop is never a pass: ATTENTION citing the notice when the
			// engine gave it one, UNDECIDED otherwise.
			if allNoticed(decision.neutral) {
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
		case decision.family != nil && !major && decision.family.Status == scanreport.FamilyPass && hop.From.Version != "" && hop.To.Version != "":
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

// exactMajorIDs keeps the rules that are scoped to exactly the transition of
// the major hop: no removal crossing, and an anchor pair on the hop's own
// two lines. A rule the run does not know is not kept.
func (r *customResourceRun) exactMajorIDs(ids []string, hop scanreport.Hop) []string {
	fromLine, ok1 := endpointLine(upgradepath.Endpoint{Version: hop.From.Version, Line: hop.From.Line})
	toLine, ok2 := endpointLine(upgradepath.Endpoint{Version: hop.To.Version, Line: hop.To.Line})
	var out []string
	for _, id := range ids {
		rule, known := r.byID[id]
		if !known || !ok1 || !ok2 || rule.Scope.Transition.Crossing != nil {
			continue
		}
		anchorFrom, f := lineattest.LineOf(rule.Scope.Transition.From)
		anchorTo, t := lineattest.LineOf(rule.Scope.Transition.To)
		if f && t && anchorFrom == fromLine && anchorTo == toLine {
			out = append(out, id)
		}
	}
	return out
}

// allNoticed reports whether there is a neutral rule and every one of them
// was given a notice by the engine.
func allNoticed(neutral []neutralRule) bool {
	for _, n := range neutral {
		if !n.noticed {
			return false
		}
	}
	return len(neutral) > 0
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

// Kubelet skew is read only from a declared kubelet version, so the scope of
// a jump says which of the two holds.
const (
	kubeletSkewNotChecked = "; kubelet skew not checked: no kubelet version is declared (--kubelet-version-min, --kubelet-version-max)"
	kubeletSkewChecked    = "; kubelet skew was checked against the declared kubelet version %s"
)

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
	var wholeBlocks, wholeSkew []string
	for _, gap := range r.report.Gaps {
		if gap.Component == kubernetesSlug && (gap.Hop == nil || gap.Hop.WholeUpgrade) {
			open = append(open, gap.Reason)
		}
	}
	for _, f := range r.report.Findings {
		if f.Component == kubernetesSlug && f.Hop.WholeUpgrade {
			if r.skewRule(f.RuleID) {
				wholeSkew = append(wholeSkew, f.RuleID)
			} else {
				wholeBlocks = append(wholeBlocks, f.RuleID)
			}
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
	skews := r.hopSkews(path.Hops)
	summary := kubeletSummary(skews)
	hops := make([]scanreport.JumpHop, 0, len(path.Hops))
	for i := range path.Hops {
		hop := path.Hops[i]
		skewState := skews[i]
		ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String()}
		jump := scanreport.JumpHop{Index: hop.Index, From: ref.From, To: ref.To, ObjectSetDigest: r.hopDigests[hop.Index], Attestation: hop.Attestation}
		var blocks, skew []string
		for _, f := range r.report.Findings {
			if f.Component == kubernetesSlug && at(ref, f.Hop, f.AlsoAt) {
				if r.skewRule(f.RuleID) {
					skew = append(skew, f.RuleID)
				} else {
					blocks = append(blocks, f.RuleID)
				}
			}
		}
		if i == len(path.Hops)-1 {
			blocks = append(blocks, wholeBlocks...)
			skew = append(skew, wholeSkew...)
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
		case len(skew) > 0 && (hop.Status == scanreport.HopBlocked || (i == len(path.Hops)-1 && len(wholeSkew) > 0)):
			// The hop enters a line the declared kubelet versions are too old
			// for. The stepwise path rolls the nodes between its hops, so the
			// hop is a step to take (ATTENTION with the minimum kubelet), not
			// a block of the path; the direct upgrade keeps its finding.
			jump.Status = scanreport.JumpHopAttention
			action := skewState.action()
			if skewState.tooNew {
				action = "a declared kubelet is newer than the target of this hop; check the declared kubelet versions"
			}
			for _, id := range uniqueStrings(skew) {
				jump.Entries = append(jump.Entries, id+": "+action)
			}
			jump.Entries = append(jump.Entries, summary[i]...)
		case skewState.outside && hop.Status != scanreport.HopBlocked:
			// The declared kubelet versions are outside the supported skew
			// for this hop and no signed rule says so: computed by scan from
			// the declaration for every hop, never a pass.
			jump.Status = scanreport.JumpHopAttention
			jump.Entries = append([]string{skewState.text()}, summary[i]...)
		case skewState.unresolved:
			jump.Status = scanreport.JumpHopUndecided
			jump.Reasons = uniqueStrings(append(append([]string{}, hop.Reasons...), reasonKubeletSkewNotResolved))
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
	jump.Scope = kubernetesJumpScope + kubeletSkewNotChecked
	if k := r.declarations.kubelet; k.Minimum != "" {
		declared := k.Minimum
		if k.Maximum != "" && k.Maximum != k.Minimum {
			declared = k.Minimum + " to " + k.Maximum
		}
		jump.Scope = kubernetesJumpScope + fmt.Sprintf(kubeletSkewChecked, declared)
	}
	path.Jump = &jump
}

// skewRule reports whether the rule is a kubelet version-skew rule: one that
// reads only the declared kubelet versions.
func (r *kubernetesRun) skewRule(id string) bool {
	rule, found := r.byID[id]
	return found && declarationOnly(rule)
}

// minKubeletMinor is the lowest kubelet minor version the version-skew policy
// allows against a control plane of minor line: three minors older (two for a
// kubelet below 1.25).
func minKubeletMinor(line uint64) uint64 {
	if line >= 3 && line-3 >= 25 {
		return line - 3
	}
	if line >= 2 {
		return line - 2
	}
	return 0
}

// minKubelet is the minimum kubelet version for a control plane of the line
// "1.N", or "" when the line is not a minor line.
func minKubelet(line string) string {
	major, minor, found := strings.Cut(line, ".")
	if !found {
		return ""
	}
	n, err := strconv.ParseUint(minor, 10, 64)
	if err != nil {
		return ""
	}
	return major + "." + strconv.FormatUint(minKubeletMinor(n), 10) + ".0"
}

// reasonKubeletSkewNotResolved keeps a hop from PASS when a kubelet version is
// declared but the skew window cannot be computed for the hop (another major
// line, or a version scan cannot read).
const reasonKubeletSkewNotResolved = "KUBELET_SKEW_NOT_RESOLVED"

// hopSkew is the skew window of the declared kubelet versions against the
// target of one hop, computed by scan from the declaration alone.
type hopSkew struct {
	declared, line string
	from, to       string // the hop's ends, as shown
	minimum        string // the minimum kubelet for the hop's target line
	outside        bool   // outside the supported skew window
	tooNew         bool   // a declared kubelet is newer than the hop's target
	unresolved     bool   // a kubelet version is declared but the window cannot be computed
}

// text is the line shown for a hop outside the window, labelled as computed.
func (h hopSkew) text() string {
	if h.tooNew {
		return "computed: declared kubelet " + h.declared + " is newer than Kubernetes " + h.line + ", outside the supported skew; check the declared kubelet versions"
	}
	return "computed: declared kubelet " + h.declared + " is outside the supported skew for " + h.line + "; " + h.action()
}

// action is what to do before this hop: roll the kubelets to a version inside
// the window of the hop's target and never newer than the hop's start, since a
// kubelet must never be newer than the control plane.
func (h hopSkew) action() string {
	if h.minimum == "" || h.from == "" {
		return "upgrade kubelets into the skew window of the hop's target, never newer than the control plane, before this hop"
	}
	return "before this hop (" + h.from + " -> " + h.to + "), upgrade kubelets to a version between " + h.minimum + " and " + h.from
}

// versionParts reads "1.30", "1.30.2" or "1.30.2-rc.1" as major, minor, patch.
func versionParts(v string) ([3]uint64, bool) {
	var out [3]uint64
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for n, part := range parts {
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return out, false
		}
		out[n] = value
	}
	return out, true
}

// hopSkews computes the window for every hop from the declared kubelet
// versions; without a declaration nothing is computed.
func (r *kubernetesRun) hopSkews(hops []scanreport.Hop) []hopSkew {
	out := make([]hopSkew, len(hops))
	k := r.declarations.kubelet
	if k.Minimum == "" {
		return out
	}
	maximum := k.Maximum
	if maximum == "" {
		maximum = k.Minimum
	}
	declared := k.Minimum
	if maximum != k.Minimum {
		declared += " to " + maximum
	}
	low, lowOK := versionParts(k.Minimum)
	high, highOK := versionParts(maximum)
	for i, hop := range hops {
		line, lineOK := endpointLine(upgradepath.Endpoint{Version: hop.To.Version, Line: hop.To.Line})
		state := hopSkew{declared: declared, line: line, from: hop.From.String(), to: hop.To.String(), minimum: minKubelet(line)}
		target, targetOK := versionParts(hop.To.Version)
		if !targetOK {
			target, targetOK = versionParts(hop.To.Line)
		}
		if !lowOK || !highOK || !lineOK || !targetOK {
			state.unresolved = true
			out[i] = state
			continue
		}
		present, resolved := cncfprepare.KubeletSkewUnsupported(low, high, target)
		switch {
		case !resolved:
			state.unresolved = true
		case present:
			state.outside = true
			state.tooNew = high[1] > target[1]
		}
		out[i] = state
	}
	return out
}

// kubeletSummary names, on the last hop that needs the highest minimum, the
// kubelet version the whole path needs by its end. It is per hop index: nil
// everywhere else.
func kubeletSummary(skews []hopSkew) [][]string {
	out := make([][]string, len(skews))
	var best uint64
	index := -1
	for i, state := range skews {
		if !state.outside || state.tooNew || state.minimum == "" {
			continue
		}
		_, minor, _ := strings.Cut(state.minimum, ".")
		minor, _, _ = strings.Cut(minor, ".")
		if n, err := strconv.ParseUint(minor, 10, 64); err == nil && (index < 0 || n >= best) {
			best, index = n, i
		}
	}
	if index >= 0 {
		out[index] = []string{"summary: kubelets must reach >= " + skews[index].minimum + " by the hop to " + skews[index].to + ", rolled stepwise, never newer than the control plane"}
	}
	return out
}

// skewComputed is the line scan computes for a kubelet-skew finding: the
// declared kubelet versions and the minimum for the target. It is labelled as
// computed and never replaces the rule's own wording.
func skewComputed(line, target, declaredMin, declaredMax string) string {
	declared := declaredMin
	if declaredMax != "" && declaredMax != declaredMin {
		declared += " to " + declaredMax
	}
	return "computed: declared kubelet " + declared + "; minimum for " + target + " is " + minKubelet(line)
}

// notCoveredPath lists the requested path of a component the scan does not
// evaluate, so that the report never says "0 hops" for an upgrade that was
// asked for. The hops are the consecutive minor lines between the two
// versions when both are on one major line and their lines follow each other
// in the component's own scheme, otherwise the one hop from -> to (no line
// data exists for the component). Every hop is UNDECIDED with the reason
// COMPONENT_NOT_COVERED and its next action; no rule or review is consulted,
// so no hop can be blocked or pass and the path adds no verdict: the
// component's own gap already holds.
func notCoveredPath(slug, component, from, to string) (scanreport.Path, bool) {
	if from == "" || to == "" {
		return scanreport.Path{}, false
	}
	direct := upgradepath.PlanPath(component, from, to, nil)
	if direct.Gap != upgradepath.GapNone || len(direct.Hops) != 1 {
		return scanreport.Path{}, false
	}
	plan := direct
	if !crossesMajor(from, to) {
		if stepwise := upgradepath.PlanPath(component, from, to, &upgradepath.PathPolicy{Component: component, Policy: upgradepath.PolicySequentialMinor}); stepwise.Gap == upgradepath.GapNone && len(stepwise.Hops) > 1 && consecutiveLines(component, stepwise) {
			plan = stepwise
		}
	}
	path := scanreport.Path{Component: slug, From: from, To: to, Hops: []scanreport.Hop{}}
	var hops []scanreport.JumpHop
	actions := map[int]string{}
	gap := scanreport.NewGap(slug, nil, scanreport.GapComponentNotCovered, slug)
	for _, planned := range plan.Hops {
		hop := scanreport.Hop{
			Index:   planned.Index,
			From:    scanreport.Endpoint{Version: planned.From.Version, Line: planned.From.Line},
			To:      scanreport.Endpoint{Version: planned.To.Version, Line: planned.To.Line},
			Status:  scanreport.HopNoData,
			Reasons: []string{gap.Reason},
		}
		path.Hops = append(path.Hops, hop)
		hops = append(hops, scanreport.JumpHop{Index: hop.Index, From: hop.From.String(), To: hop.To.String(), Status: scanreport.JumpHopUndecided, Reasons: []string{gap.Reason}})
		actions[hop.Index] = gap.Action
	}
	jump := scanreport.NewJump(hops, "", nil, actions)
	path.Jump = &jump
	return path, true
}

// consecutiveLines reports whether every hop of the plan enters a line that
// follows the line it leaves in the component's own scheme.
func consecutiveLines(component string, plan upgradepath.Plan) bool {
	previous, ok := endpointLine(plan.Hops[0].From)
	if !ok {
		return false
	}
	for _, hop := range plan.Hops {
		line, ok := endpointLine(hop.To)
		if !ok || !lineattest.LineHop(component, previous, line) {
			return false
		}
		previous = line
	}
	return true
}
