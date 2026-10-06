// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
)

// This file is the only place that decides whether a declared from/to
// transition falls under a rule's reviewed subject. Every caller that selects,
// filters, or evaluates rules by transition goes through RuleTransition. A
// source test bans direct from/to equality comparisons elsewhere.
//
// A rule without a range matches exactly its reviewed anchor pair, by string
// equality, as it always has. A rule with a range additionally matches every
// transition whose from and to lie inside the range's half-open bounds. The
// matcher is a pure function of declared versions and the rule's own declared
// subject: it never reads a clock, so applicability stays independent of
// evidence freshness.

// MatchMode names how a transition matched a rule's reviewed subject.
type MatchMode string

const (
	// MatchNone means the transition is outside the anchor and any range.
	MatchNone MatchMode = ""
	// MatchAnchor means the transition equals the reviewed anchor pair.
	MatchAnchor MatchMode = "anchor"
	// MatchRange means the transition is inside the reviewed range but is
	// not the anchor pair.
	MatchRange MatchMode = "range"
)

// VersionBound is a half-open interval [Gte, Lt).
type VersionBound struct {
	Gte string `json:"gte"`
	Lt  string `json:"lt"`
}

// RangeBound licenses one of the four bounds with a basis from the closed
// vocabulary and a cited source that the rule's own evidence carries.
type RangeBound struct {
	Bound    string `json:"bound"`
	Basis    string `json:"basis"`
	SourceID string `json:"sourceId"`
}

// VersionRange widens a reviewed anchor pair. All four bounds are finite.
type VersionRange struct {
	From   VersionBound `json:"from"`
	To     VersionBound `json:"to"`
	Bounds []RangeBound `json:"bounds"`
}

// RuleTransition is a rule's reviewed subject: the anchor pair and, when
// present, the reviewed range around it.
type RuleTransition struct {
	Component string
	From      string
	To        string
	Range     *VersionRange
}

// Match reports how the declared transition matches this subject. A version
// that is not a valid release version never matches a range.
func (t RuleTransition) Match(from, to string) MatchMode {
	if from == t.From && to == t.To {
		return MatchAnchor
	}
	if t.Range != nil && inBound(from, t.Range.From) && inBound(to, t.Range.To) {
		return MatchRange
	}
	return MatchNone
}

// MatchesFrom reports whether a declared current version alone falls under
// this subject. It serves partial catalogue filters; rule selection and
// evaluation always use Match.
func (t RuleTransition) MatchesFrom(from string) bool {
	return from == t.From || t.Range != nil && inBound(from, t.Range.From)
}

// MatchesTo is the proposed-version counterpart of MatchesFrom.
func (t RuleTransition) MatchesTo(to string) bool {
	return to == t.To || t.Range != nil && inBound(to, t.Range.To)
}

// IsAnchorFrom reports whether the declared current version is exactly the
// reviewed anchor origin, as opposed to merely falling inside a range. Only
// the anchor origin licenses handing back the exact-pair native command with
// its literal --from/--to flags: a range widens which origins are covered by
// the rule's verdict, but the command text stays pinned to what was reviewed.
func (t RuleTransition) IsAnchorFrom(from string) bool { return from == t.From }

// IsAnchor reports whether the pair is exactly the reviewed anchor. Review
// records bind the anchor, never the range.
func (t RuleTransition) IsAnchor(from, to string) bool { return from == t.From && to == t.To }

// Contains reports gte <= version < lt. An invalid version is never inside.
func (b VersionBound) Contains(version string) bool { return inBound(version, b) }

// SameVersion reports that two valid release versions are equal.
func SameVersion(left, right string) bool {
	c, ok := compareVersions(left, right)
	return ok && c == 0
}

// VersionLess reports left < right for two valid release versions.
func VersionLess(left, right string) bool {
	c, ok := compareVersions(left, right)
	return ok && c < 0
}

func inBound(version string, bound VersionBound) bool {
	low, lowOK := compareVersions(bound.Gte, version)
	high, highOK := compareVersions(version, bound.Lt)
	return lowOK && highOK && low <= 0 && high < 0
}

// RuleTransitionOf reads the subject and optional range of one raw rule for
// selection. It does not validate the rule: selection only narrows a document
// that ParseRuleSet then validates in full.
func RuleTransitionOf(raw []byte) (RuleTransition, error) {
	var shape struct {
		Subject struct {
			Component string `json:"component"`
			From      string `json:"from"`
			To        string `json:"to"`
		} `json:"subject"`
		Range *VersionRange `json:"range"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return RuleTransition{}, fmt.Errorf("rule subject: %w", ErrInvalid)
	}
	return RuleTransition{Component: shape.Subject.Component, From: shape.Subject.From, To: shape.Subject.To, Range: shape.Range}, nil
}

// RulesSchemaFor returns the rules schema a document holding exactly these
// rules must carry: the severity schema when at least one rule declares a
// severity, else the basis schema when at least one rule has a consensus
// or lead basis, else the notice schema when at least one rule uses
// notice_one_way, else the set schema when at least one rule uses
// forbid_set_member, else the ranged schema when at least one rule has a
// range, the original exact-only schema otherwise.
func RulesSchemaFor(rules []json.RawMessage) (string, error) {
	severity, err := AnySeverityRule(rules)
	if err != nil {
		return "", err
	}
	if severity {
		return RulesSchemaSeverity, nil
	}
	basis, err := AnyBasisRule(rules)
	if err != nil {
		return "", err
	}
	if basis {
		return RulesSchemaBasis, nil
	}
	notice, err := AnyNoticeRule(rules)
	if err != nil {
		return "", err
	}
	if notice {
		return RulesSchemaNotice, nil
	}
	set, err := AnySetRule(rules)
	if err != nil {
		return "", err
	}
	if set {
		return RulesSchemaSet, nil
	}
	ranged, err := AnyRanged(rules)
	if err != nil {
		return "", err
	}
	if ranged {
		return RulesSchemaRanged, nil
	}
	return RulesSchema, nil
}

// AnyRanged reports whether any raw rule declares a range.
func AnyRanged(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape["range"]; ok {
			return true, nil
		}
	}
	return false, nil
}

// requiredRulesSchema is the schema of the highest-level feature a parsed
// document uses; RulesSchemaFor is its raw-rule counterpart.
func requiredRulesSchema(ranged, setOperator, notice, basis, severity bool) string {
	switch {
	case severity:
		return RulesSchemaSeverity
	case basis:
		return RulesSchemaBasis
	case notice:
		return RulesSchemaNotice
	case setOperator:
		return RulesSchemaSet
	case ranged:
		return RulesSchemaRanged
	}
	return RulesSchema
}

func (r rule) transition() RuleTransition {
	return RuleTransition{Component: r.Subject.Component, From: r.Subject.From, To: r.Subject.To, Range: r.Range}
}

// sameVersion is the one exact version equality used by structural guards.
func sameVersion(left, right string) bool { return left == right }

// Bound names and the closed basis vocabulary. Changing either is an engine
// contract change: both are bound into the ranged engine contract digest.
const (
	boundFromGte = "from.gte"
	boundFromLt  = "from.lt"
	boundToGte   = "to.gte"
	boundToLt    = "to.lt"

	BasisRemovedInRelease         = "REMOVED_IN_RELEASE"
	BasisChangedInRelease         = "CHANGED_IN_RELEASE"
	BasisRestoredInRelease        = "RESTORED_IN_RELEASE"
	BasisUpgradeFromSeries        = "UPGRADE_FROM_SERIES"
	BasisTargetSeries             = "TARGET_SERIES"
	BasisPreviousMinorLine        = "PREVIOUS_MINOR_LINE"
	BasisReviewedThroughMinorLine = "REVIEWED_THROUGH_MINOR_LINE"
	BasisAnchorOnly               = "ANCHOR_ONLY"
	rangeWidthPolicy              = "range-width:one-minor-line-per-side"
	unresolvedTransitionNotAnchor = "TRANSITION_NOT_ANCHOR_REVIEWED"
	subjectMatchModeRange         = "range"
	rangeNextActionSuffixTemplate = "; matched by reviewed range; anchor pair %s -> %s"
	rangeNextActionSuffixShort    = "; matched by reviewed range"
	rangeSubjectActionTemplate    = "no rule for declared pair; reviewed range %s from [%s,%s) to [%s,%s); retain actual versions and request coverage"
)

var boundOrder = []string{boundFromGte, boundFromLt, boundToGte, boundToLt}

// basisAllowed lists, per basis, the bounds it may license.
var basisAllowed = map[string]map[string]bool{
	BasisRemovedInRelease:         {boundFromLt: true, boundToGte: true},
	BasisChangedInRelease:         {boundFromLt: true, boundToGte: true},
	BasisRestoredInRelease:        {boundToLt: true},
	BasisUpgradeFromSeries:        {boundFromGte: true, boundFromLt: true},
	BasisTargetSeries:             {boundToGte: true, boundToLt: true},
	BasisPreviousMinorLine:        {boundFromGte: true},
	BasisReviewedThroughMinorLine: {boundToLt: true},
	BasisAnchorOnly:               {boundFromGte: true, boundFromLt: true, boundToGte: true, boundToLt: true},
}

func basisVocabulary() string {
	return BasisAnchorOnly + "\n" + BasisChangedInRelease + "\n" + BasisPreviousMinorLine + "\n" + BasisRemovedInRelease + "\n" + BasisRestoredInRelease + "\n" + BasisReviewedThroughMinorLine + "\n" + BasisTargetSeries + "\n" + BasisUpgradeFromSeries
}

// validateRange enforces the structural range guards. Every failure is
// ErrInvalid: a range the engine cannot fully check is never admitted.
func validateRange(r rule) error {
	rng := r.Range
	if rng == nil {
		return nil
	}
	values := map[string]string{boundFromGte: rng.From.Gte, boundFromLt: rng.From.Lt, boundToGte: rng.To.Gte, boundToLt: rng.To.Lt}
	parsed := map[string]numericVersion{}
	for name, value := range values {
		version, ok := parseVersion(value)
		if !ok {
			return fmt.Errorf("range bound %s version: %w", name, ErrInvalid)
		}
		parsed[name] = version
	}
	less := func(a, b string) bool { c, ok := compareVersions(a, b); return ok && c < 0 }
	lessEqual := func(a, b string) bool { c, ok := compareVersions(a, b); return ok && c <= 0 }
	// Non-empty half-open intervals.
	if !less(rng.From.Gte, rng.From.Lt) || !less(rng.To.Gte, rng.To.Lt) {
		return fmt.Errorf("range interval empty or inverted: %w", ErrInvalid)
	}
	// Every matched pair is a strict upgrade: the largest from is below the
	// smallest to, so equal versions and downgrades can never match.
	if !lessEqual(rng.From.Lt, rng.To.Gte) {
		return fmt.Errorf("range admits a non-upgrade pair: %w", ErrInvalid)
	}
	// A range only widens its reviewed anchor; it never moves away from it.
	if !inBound(r.Subject.From, rng.From) || !inBound(r.Subject.To, rng.To) {
		return fmt.Errorf("range excludes its anchor: %w", ErrInvalid)
	}
	// Width cap: each side spans at most one minor line.
	if !withinOneMinorLine(parsed[boundFromGte], parsed[boundFromLt]) || !withinOneMinorLine(parsed[boundToGte], parsed[boundToLt]) {
		return fmt.Errorf("range wider than one minor line: %w", ErrInvalid)
	}
	if len(rng.Bounds) != len(boundOrder) {
		return fmt.Errorf("range bound count: %w", ErrInvalid)
	}
	sources := make(map[string]bool, len(r.Evidence.Sources))
	for _, source := range r.Evidence.Sources {
		sources[source.ID] = true
	}
	basis := map[string]string{}
	for index, bound := range rng.Bounds {
		if bound.Bound != boundOrder[index] {
			return fmt.Errorf("range bound order: %w", ErrInvalid)
		}
		allowed, known := basisAllowed[bound.Basis]
		if !known || !allowed[bound.Bound] {
			return fmt.Errorf("range bound basis: %w", ErrInvalid)
		}
		if !idRE.MatchString(bound.SourceID) || !sources[bound.SourceID] {
			return fmt.Errorf("range bound source: %w", ErrInvalid)
		}
		basis[bound.Bound] = bound.Basis
	}
	return validateBasisStructure(r, basis, parsed)
}

// validateBasisStructure checks the version shape each basis implies. It
// cannot check what the cited span says; a reviewer reads the span next to
// the bound. It checks what the basis makes mechanically checkable.
func validateBasisStructure(r rule, basis map[string]string, parsed map[string]numericVersion) error {
	fail := func(what string) error { return fmt.Errorf("range basis %s: %w", what, ErrInvalid) }
	release := func(name string) bool {
		return basis[name] == BasisRemovedInRelease || basis[name] == BasisChangedInRelease
	}
	if release(boundFromLt) || release(boundToGte) {
		// One release boundary B licenses both sides: from < B <= to.
		if basis[boundFromLt] != basis[boundToGte] || !sameVersion(r.Range.From.Lt, r.Range.To.Gte) || !minorStart(parsed[boundToGte]) {
			return fail("release boundary")
		}
	}
	if basis[boundFromGte] == BasisPreviousMinorLine {
		// from.gte is the start of the minor line immediately before from.lt.
		gte, lt := parsed[boundFromGte], parsed[boundFromLt]
		if !minorStart(gte) || !minorStart(lt) || gte[0] != lt[0] || uint64(gte[1])+1 != uint64(lt[1]) {
			return fail("previous minor line")
		}
	}
	for _, side := range [][2]string{{boundFromGte, boundFromLt}, {boundToGte, boundToLt}} {
		gte, lt := parsed[side[0]], parsed[side[1]]
		series := BasisUpgradeFromSeries
		if side[0] == boundToGte {
			series = BasisTargetSeries
		}
		// A series basis names one whole minor line: [M.m.0, M.(m+1).0).
		if (basis[side[0]] == series || basis[side[1]] == series) && !wholeMinorLine(gte, lt) {
			return fail("series")
		}
	}
	if basis[boundToLt] == BasisReviewedThroughMinorLine && !minorStart(parsed[boundToLt]) {
		return fail("review horizon")
	}
	// ANCHOR_ONLY leaves a side at exactly the anchor version: gte equals the
	// anchor, lt is the anchor's next patch.
	anchors := map[string]string{boundFromGte: r.Subject.From, boundFromLt: r.Subject.From, boundToGte: r.Subject.To, boundToLt: r.Subject.To}
	for name, value := range map[string]string{boundFromGte: r.Range.From.Gte, boundFromLt: r.Range.From.Lt, boundToGte: r.Range.To.Gte, boundToLt: r.Range.To.Lt} {
		if basis[name] != BasisAnchorOnly {
			continue
		}
		anchor, _ := parseVersion(anchors[name])
		if name == boundFromGte || name == boundToGte {
			if !sameVersion(value, anchors[name]) {
				return fail("anchor only")
			}
			continue
		}
		bound := parsed[name]
		if bound[0] != anchor[0] || bound[1] != anchor[1] || uint64(anchor[2])+1 != uint64(bound[2]) {
			return fail("anchor only")
		}
	}
	return nil
}

func minorStart(version numericVersion) bool { return version[2] == 0 }

func wholeMinorLine(gte, lt numericVersion) bool {
	return minorStart(gte) && minorStart(lt) && gte[0] == lt[0] && uint64(gte[1])+1 == uint64(lt[1])
}

// withinOneMinorLine reports lt <= M.(m+1).0 where M.m is gte's minor line.
func withinOneMinorLine(gte, lt numericVersion) bool {
	if lt[0] != gte[0] {
		return false
	}
	next := uint64(gte[1]) + 1
	return uint64(lt[1]) < next || uint64(lt[1]) == next && lt[2] == 0
}

// validateRangeOverlaps is the pack-level lint. Two rules for the same
// component whose match regions overlap may not constrain the same thing: a
// duplicate double-counts one fact, and contradictory predicates on one fact
// would block every overlapping transition. A reviewed range must widen its
// rule in place instead of being added as a sibling. Pairs of exact-only rules
// are not examined here; their behaviour is unchanged.
func validateRangeOverlaps(rules []rule) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.Range == nil && b.Range == nil || a.Subject.Component != b.Subject.Component {
				continue
			}
			if constraintKey(a) != constraintKey(b) {
				continue
			}
			// Two set rules on one set fact constrain the same thing only
			// when they forbid a common member; one rule per removed member
			// is the expected shape.
			if a.SetCondition != nil && len(setMembersHit(a.SetCondition.Members, b.SetCondition.Members)) == 0 {
				continue
			}
			if regionsOverlap(a.transition(), b.transition()) {
				return fmt.Errorf("overlapping rules constrain the same fact: %w", ErrInvalid)
			}
		}
	}
	return nil
}

// ConstraintKey is the engine's constraint key of one rule object (the JSON
// under an entry's "rule"): the operator and the fact the rule constrains.
// Two rules for one component constrain the same thing exactly when their
// keys are equal, which is what the overlap lint compares. Everything that
// needs that notion (the knowledge gate's supersede class, extract
// supersede) calls this one function, so none can drift from the engine's.
func ConstraintKey(ruleJSON []byte) (string, error) {
	var r rule
	if err := json.Unmarshal(ruleJSON, &r); err != nil {
		return "", fmt.Errorf("constraint key: %w", ErrInvalid)
	}
	return constraintKey(r), nil
}

func constraintKey(r rule) string {
	switch {
	case r.SetCondition != nil:
		return r.Operator + "\x00" + r.SetCondition.Side + "\x00" + r.SetCondition.Component + "\x00" + r.SetCondition.FactID
	case r.Condition != nil:
		return r.Operator + "\x00" + r.Condition.Side + "\x00" + r.Condition.Component + "\x00" + r.Condition.FactID
	case r.Dependency != nil:
		return r.Operator + "\x00" + r.Dependency.Side + "\x00" + r.Dependency.Component
	default:
		return r.Operator
	}
}

func regionsOverlap(a, b RuleTransition) bool {
	fromA, toA := region(a)
	fromB, toB := region(b)
	return intervalsOverlap(fromA, fromB) && intervalsOverlap(toA, toB)
}

// region returns the half-open from and to intervals a subject matches. An
// exact anchor v is represented as [v, v] with an inclusive upper end, which
// intervalsOverlap handles through the closed flag.
type interval struct {
	low, high string
	closed    bool
}

func region(t RuleTransition) (interval, interval) {
	from, to := interval{t.From, t.From, true}, interval{t.To, t.To, true}
	if t.Range != nil {
		// The anchor lies inside the range, so the range covers it.
		from, to = interval{t.Range.From.Gte, t.Range.From.Lt, false}, interval{t.Range.To.Gte, t.Range.To.Lt, false}
	}
	return from, to
}

func intervalsOverlap(a, b interval) bool {
	below := func(low string, other interval) bool {
		c, ok := compareVersions(low, other.high)
		if !ok {
			return true
		}
		if other.closed {
			return c <= 0
		}
		return c < 0
	}
	return below(a.low, b) && below(b.low, a)
}

// Line coverage. A multi-hop upgrade path passes through intermediate minor
// lines without fixing a patch version: the operator may stop at M.m.0 or at
// any later patch of the line. A rule may decide such a hop only when its
// range contains every release of the line on that side.

// CoversLine reports whether the bound contains every release version of the
// minor line M.m: gte <= M.m.0 and lt >= M.(m+1).0. The line must be exactly
// "M.m" with the engine's version syntax (no leading zeros, each part fitting
// 32 bits); an invalid line, a line without a next minor line, or a bound
// whose versions do not parse never covers anything.
func (b VersionBound) CoversLine(line string) bool {
	start, next, ok := lineBounds(line)
	if !ok {
		return false
	}
	low, lowOK := compareVersions(b.Gte, start)
	high, highOK := compareVersions(b.Lt, next)
	return lowOK && highOK && low <= 0 && high >= 0
}

// CoversFromLine reports whether the rule matches a transition from every
// release of line on its from side: the rule has a range and the range's
// from bound covers the whole line. An anchor-only rule matches one exact
// pair and never covers a line.
func (t RuleTransition) CoversFromLine(line string) bool {
	return t.Range != nil && t.Range.From.CoversLine(line)
}

// CoversToLine is the target-side counterpart of CoversFromLine.
func (t RuleTransition) CoversToLine(line string) bool {
	return t.Range != nil && t.Range.To.CoversLine(line)
}

// lineBounds returns M.m.0 and M.(m+1).0 for a valid minor line M.m.
func lineBounds(line string) (start, next string, ok bool) {
	start = line + ".0"
	parsed, valid := parseVersion(start)
	if !valid || parsed[1] == ^uint32(0) {
		return "", "", false
	}
	next = fmt.Sprintf("%d.%d.0", parsed[0], uint64(parsed[1])+1)
	return start, next, true
}
