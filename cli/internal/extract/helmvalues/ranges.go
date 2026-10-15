// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"fmt"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

// A rule of a pair is derived at the two anchors: the first release of the
// earlier line and the first release of the later one. It is widened to
// every release of both lines (a ranged chart rule) only when "the same rule
// holds for an upgrade from any tagged final release of the earlier line to
// any tagged final release of the later one" is checked release by release.
// The range then also covers versions of both lines the proof never read
// (an untagged release, a later patch); the docs disclose that:
//
//   - every final release of both lines reads completely, each line has
//     more than one final release and at most the per-line bound, no tag
//     outside the tag scheme names a version of either line, and each
//     anchor is the first release M.m.0 of its line;
//   - the anchor derivation, run on every earlier release against every
//     later release, gives the same rule as at the anchors (operator,
//     members, Kubernetes minimum, and "no rule" where the anchors have
//     none). A later release whose schema requires one more key, or an
//     earlier release already at the Kubernetes bound, keeps the rule
//     anchor-only.
//
// Anything else keeps the rule anchor-only, with the reason in the pair's
// proof. Set notices are always anchor-only.

// Rule kinds that may be ranged.
const (
	kindKube     = "kube-version"
	kindRequired = "required-values"
	kindRemoved  = "removed-values"
)

var rangedKinds = []string{kindKube, kindRequired, kindRemoved}

// Range outcomes.
const (
	rangeChecked       = "checked"
	rangeNoAnchorRule  = "no rule at the anchors"
	rangeConsecutive   = "range: consecutive lines"
	rangeWholeLines    = "range: whole lines"
	anchorOnlyPrefix   = "anchor-only: "
	noRuleSignature    = "no rule"
	rangeDescription   = " The same derivation, from Chart.yaml, values.yaml and values.schema.json, gives this rule for each of the %d x %d tagged final releases of lines %s and %s; the range also applies to other patches of those lines."
	lineLabelTemplate  = "%d.%d"
	toLineNameTemplate = "%d.%d.x"
)

// pairLines is the two release lines of a pair and their releases as read,
// one per tag, the anchor first.
type pairLines struct {
	from, to           *releaseLine
	fromSides, toSides []*side
}

// anchorOnly is why no rule of the pair can be ranged, "" when each kind
// is to be checked.
func (l *pairLines) anchorOnly() string {
	lines := []*releaseLine{l.from, l.to}
	for _, line := range lines {
		if line.Problem != "" {
			return fmt.Sprintf("%sline %s: %s", anchorOnlyPrefix, line.key(), line.Problem)
		}
	}
	for _, line := range lines {
		if n := len(line.Outside); n > 0 {
			return fmt.Sprintf("%sline %s has %d tag(s) outside the tag scheme naming one of its versions, first %s", anchorOnlyPrefix, line.key(), n, line.Outside[0])
		}
	}
	for i, sides := range [][]*side{l.fromSides, l.toSides} {
		if len(sides) != len(lines[i].Tags) {
			return fmt.Sprintf("%sline %s was not read", anchorOnlyPrefix, lines[i].key())
		}
		for j, s := range sides {
			if s == nil || s.problem != "" {
				return fmt.Sprintf("%srelease %s of line %s does not read completely", anchorOnlyPrefix, lines[i].Tags[j].Name, lines[i].key())
			}
		}
	}
	for _, line := range lines {
		if len(line.Tags) < 2 {
			return fmt.Sprintf("%sline %s has a single final release", anchorOnlyPrefix, line.key())
		}
		if start := fmt.Sprintf("%d.%d.0", line.Major, line.Minor); line.Versions[0] != start {
			return fmt.Sprintf("%sthe anchor %s is not the first release %s of line %s", anchorOnlyPrefix, line.Versions[0], start, line.key())
		}
	}
	return ""
}

// ranges checks each rule kind of the pair and widens a kind's anchor
// candidate in place when its proof holds. It returns the pair's range
// outcome and the proof of each kind.
func (x *Extractor) ranges(pair extract.VersionPair, lines *pairLines, anchor map[string]*chartrun.Candidate) (string, []RangeProof) {
	reason := lines.anchorOnly()
	proofs := make([]RangeProof, 0, len(rangedKinds))
	for _, kind := range rangedKinds {
		p := RangeProof{Kind: kind}
		switch c := anchor[kind]; {
		case c == nil:
			p.Outcome = rangeNoAnchorRule
		case reason != "":
			p.Outcome = reason
		default:
			x.proveKind(pair, lines, kind, c, &p)
		}
		proofs = append(proofs, p)
	}
	if reason == "" {
		reason = rangeChecked
	}
	return reason, proofs
}

// proveKind runs the derivation of one kind on every release pair of the
// two lines, and widens c when every pair gives the anchors' rule.
func (x *Extractor) proveKind(pair extract.VersionPair, lines *pairLines, kind string, c *chartrun.Candidate, p *RangeProof) {
	want := x.signature(kind, pair, lines.fromSides[0], lines.toSides[0])
	for _, f := range lines.fromSides {
		for _, t := range lines.toSides {
			p.PairsChecked++
			if got := x.signature(kind, pair, f, t); got != want {
				p.Outcome = fmt.Sprintf("%s%s differs at %s -> %s", anchorOnlyPrefix, kind, f.version, t.version)
				p.Divergence = &Divergence{From: f.tag, To: t.tag, What: fmt.Sprintf("%s at the anchors, %s here", want, got)}
				return
			}
		}
	}
	from, to := lines.from, lines.to
	toName := fmt.Sprintf(toLineNameTemplate, to.Major, to.Minor)
	var widened *chartrun.Candidate
	switch kind {
	case kindKube:
		_, widened = x.kubeVersionFor(pair, lines.fromSides[0], lines.toSides[0], toName)
	case kindRequired:
		_, widened = x.requiredFor(pair, lines.fromSides[0], lines.toSides[0], toName)
	case kindRemoved:
		_, widened = x.removedFor(pair, lines.fromSides[0], lines.toSides[0], toName)
	}
	if widened == nil {
		p.Outcome = anchorOnlyPrefix + "the anchors no longer derive the rule"
		return
	}
	release := constraintengine.BasisChangedInRelease
	if kind == kindRemoved {
		release = constraintengine.BasisRemovedInRelease
	}
	fromSource, toSource := rangeSources(pair, widened.Sources)
	rng, outcome := lineRange(from, to, release, fromSource, toSource)
	if widened.Rule.ID != c.Rule.ID || toSource == "" || !constraintengine.ValidChartRangeShape(widened.Rule.Operator, *rng) {
		p.Outcome = anchorOnlyPrefix + "the range does not have a chart line shape"
		return
	}
	widened.Rule.Range = rng
	widened.Description += fmt.Sprintf(rangeDescription, len(lines.fromSides), len(lines.toSides), fmt.Sprintf(lineLabelTemplate, from.Major, from.Minor), fmt.Sprintf(lineLabelTemplate, to.Major, to.Minor))
	*c = *widened
	p.Outcome = outcome
}

// signature is the content of the rule one kind derives for one release
// pair, with every version and text removed: what must be equal at every
// release pair for a range to hold.
func (x *Extractor) signature(kind string, pair extract.VersionPair, from, to *side) string {
	var c *chartrun.Candidate
	switch kind {
	case kindKube:
		_, c = x.kubeVersion(pair, from, to)
	case kindRequired:
		_, c = x.required(pair, from, to)
	case kindRemoved:
		_, c = x.removed(pair, from, to)
	}
	if c == nil {
		return noRuleSignature
	}
	if d := c.Rule.Dependency; d != nil {
		return fmt.Sprintf("rule %s on %s %s %s %s", c.Rule.Operator, d.Side, d.Component, d.Comparison, d.Version)
	}
	sc := c.Rule.SetCondition
	return fmt.Sprintf("rule %s on %s %s members %s", c.Rule.Operator, sc.Side, sc.FactID, strings.Join(sc.Members, ", "))
}

// rangeSources picks the source ids the range bounds cite: the earlier
// bounds cite the rule's first source at the earlier anchor, the later
// bounds its first source at the later anchor. A rule that cites nothing
// at the earlier anchor (a required key is read at the later chart only;
// an earlier chart without kubeVersion) cites the later source for all
// four bounds.
func rangeSources(pair extract.VersionPair, sources []extract.SourceRef) (from, to string) {
	for _, s := range sources {
		if from == "" && s.Commit == pair.FromCommit {
			from = s.ID
		}
		if to == "" && s.Commit == pair.ToCommit {
			to = s.ID
		}
	}
	if from == "" {
		from = to
	}
	return from, to
}

// lineRange is the range of a line-wide chart rule. Consecutive minor
// lines of one major take the release-boundary shape (the later line's
// first release is the boundary, licensed by release); any other pair of
// lines (a new major, skipped minor numbers) ranges over each whole line
// without a boundary. It is the chart counterpart of the CRD extractor's
// line range.
func lineRange(from, to *releaseLine, release, fromSource, toSource string) (*constraintengine.VersionRange, string) {
	at := func(major, minor int) string { return fmt.Sprintf("%d.%d.0", major, minor) }
	r := &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: at(from.Major, from.Minor), Lt: at(from.Major, from.Minor+1)},
		To:   constraintengine.VersionBound{Gte: at(to.Major, to.Minor), Lt: at(to.Major, to.Minor+1)},
	}
	if from.Major == to.Major && from.Minor+1 == to.Minor {
		r.Bounds = []constraintengine.RangeBound{
			{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: fromSource},
			{Bound: "from.lt", Basis: release, SourceID: fromSource},
			{Bound: "to.gte", Basis: release, SourceID: toSource},
			{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
		}
		return r, rangeConsecutive
	}
	r.Bounds = []constraintengine.RangeBound{
		{Bound: "from.gte", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromSource},
		{Bound: "from.lt", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromSource},
		{Bound: "to.gte", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
		{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
	}
	return r, rangeWholeLines
}
