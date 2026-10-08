// SPDX-License-Identifier: AGPL-3.0-only

// Package upgradepath plans the hops of an upgrade from an actual version to
// a target version of one component, following that component's reviewed
// upgrade-path policy, and holds the path-policy knowledge record.
//
// The planner only orders hops. It never evaluates a rule, never decides that
// a hop is safe and never invents a version: the real ends of a path are the
// exact versions given, and every intermediate end is a whole release line
// ("1.25", or "2" for a major line), because the operator may stop at any
// release of it. A rule decides a hop only when it matches every transition
// the hop stands for (Hop.CoveredBy).
//
// Without a policy the planner returns one direct hop and leaves the decision
// to the caller: silence about a component's upgrade path is never read as
// "skipping lines is safe".
package upgradepath

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Policies, the closed vocabulary of how a path is formed.
const (
	// PolicySequentialMinor visits every minor line between the ends, within
	// one major line.
	PolicySequentialMinor = "sequential_minor"
	// PolicyDirect is one hop from the actual version to the target.
	PolicyDirect = "direct"
	// PolicySequentialMajor visits every major line between the ends and is
	// direct within a major line.
	PolicySequentialMajor = "sequential_major"
)

// ValidPolicy reports whether policy is one of the closed vocabulary.
func ValidPolicy(policy string) bool {
	return policy == PolicySequentialMinor || policy == PolicyDirect || policy == PolicySequentialMajor
}

// Reason is why no plan could be made. The planner's vocabulary is closed.
type Reason string

const (
	// GapNone means the plan has hops.
	GapNone Reason = ""
	// GapDowngradeNotReviewed: the target is below the actual version.
	// Downgrades are never planned.
	GapDowngradeNotReviewed Reason = "DOWNGRADE_NOT_REVIEWED"
	// GapPathNotPlannable: the versions are invalid or equal, the policy is
	// unknown or names another component, the path crosses a major line
	// under sequential_minor, or it would need more than MaxHops hops.
	GapPathNotPlannable Reason = "PATH_NOT_PLANNABLE"
)

// MaxHops bounds a plan.
const MaxHops = 64

// PathPolicy is a component's upgrade-path policy, in memory. A caller passes
// one only when it rests on a current reviewed record (see Status.Policy).
type PathPolicy struct {
	Component string `json:"component"`
	Policy    string `json:"policy"`
}

// Endpoint is one end of a hop: an exact release version for the real ends
// of the path, or a whole release line for an intermediate end. Exactly one
// of the two is set.
type Endpoint struct {
	Version string `json:"version,omitempty"`
	Line    string `json:"line,omitempty"`
}

// Hop is one transition of a plan. Index counts from 1.
type Hop struct {
	Index int      `json:"index"`
	From  Endpoint `json:"from"`
	To    Endpoint `json:"to"`
}

// Plan is the ordered hops from the actual version to the target. When Gap
// is set, Hops is empty.
type Plan struct {
	Component string `json:"component"`
	Policy    string `json:"policy"`
	Hops      []Hop  `json:"hops"`
	Gap       Reason `json:"gap,omitempty"`
}

var majorLineRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

// Exact reports whether the endpoint is an exact release version.
func (e Endpoint) Exact() bool { return e.Line == "" && validVersion(e.Version) }

// MinorLine reports whether the endpoint is a whole minor line "M.m".
func (e Endpoint) MinorLine() bool { return e.Version == "" && lineattest.ValidLine(e.Line) }

// MajorLine reports whether the endpoint is a whole major line "M".
func (e Endpoint) MajorLine() bool { return e.Version == "" && majorLineRE.MatchString(e.Line) }

// String is the exact version or the line.
func (e Endpoint) String() string {
	if e.Version != "" {
		return e.Version
	}
	return e.Line
}

// EngineVersion is the concrete version that stands for the endpoint in an
// engine input: the exact version, or M.m.0 for a minor line. A major line
// has none. Matching rules at M.m.0 does not select the rules that apply to
// the hop: a rule for another release of the line does not match there. Use
// Hop.Overlaps to select them and Hop.CoveredBy to decide.
func (e Endpoint) EngineVersion() (string, bool) {
	switch {
	case e.Exact():
		return e.Version, true
	case e.MinorLine():
		return e.Line + ".0", true
	}
	return "", false
}

// CoveredBy reports whether the bound contains every release the endpoint
// stands for: the exact version, or every release of the minor line. A major
// line is never covered: the engine limits a range to one minor line per
// side.
func (e Endpoint) CoveredBy(b constraintengine.VersionBound) bool {
	switch {
	case e.Exact():
		return b.Contains(e.Version)
	case e.MinorLine():
		return b.CoversLine(e.Line)
	}
	return false
}

// CoveredBy reports whether the rule subject matches every concrete
// transition the hop stands for, using the engine's matcher semantics. A hop
// between two exact versions is covered when the rule matches that pair (its
// anchor or its range). A hop with a line end is covered only by a range
// whose side covers the whole line; an anchor-only rule never covers it. The
// caller checks that the rule's component is the plan's component.
//
// Decision rule: a hop is decided only when every current rule of the
// component that overlaps it (Overlaps) also covers it (CoveredBy). A rule
// that overlaps without covering applies to some releases of a line end but
// not to others, so it leaves the hop undecided, never passed.
func (h Hop) CoveredBy(t constraintengine.RuleTransition) bool {
	if h.From.Exact() && h.To.Exact() {
		return t.Match(h.From.Version, h.To.Version) != constraintengine.MatchNone
	}
	return t.Range != nil && h.From.CoveredBy(t.Range.From) && h.To.CoveredBy(t.Range.To)
}

// Overlaps reports whether the rule subject matches at least one concrete
// transition the hop stands for: its anchor pair lies in the hop (the anchor
// equals an exact end, or lies in a line end), its range intersects the hop
// on both sides, or its removal crossing does (some release of the from end
// below the removal release, some release of the to end in [C, cap)). Every rule that overlaps a hop applies to some operator
// taking that hop, so it must be found when the hop is decided, even when it
// does not match at M.m.0. An endpoint that is neither an exact version nor a
// line overlaps nothing.
func (h Hop) Overlaps(t constraintengine.RuleTransition) bool {
	if h.From.holds(t.From) && h.To.holds(t.To) {
		return true
	}
	if t.Range != nil && h.From.intersects(t.Range.From) && h.To.intersects(t.Range.To) {
		return true
	}
	if from, to, ok := t.CrossingBounds(); ok {
		return h.From.intersects(from) && h.To.intersects(to)
	}
	return false
}

// CrossingCovers reports whether the rule's removal crossing matches every
// concrete transition the hop stands for: every release of the from end lies
// below the removal release C and every release of the to end in [C, cap). A
// crossing only blocks, so this licenses reporting a BLOCKED claim for the
// whole hop; it never licenses a pass (CoveredBy stays the only test for
// that). An end that is a major line is never covered.
func (h Hop) CrossingCovers(t constraintengine.RuleTransition) bool {
	from, to, ok := t.CrossingBounds()
	return ok && h.From.CoveredBy(from) && h.To.CoveredBy(to)
}

// span is the half-open release interval a line end stands for:
// [M.m.0, M.(m+1).0) for a minor line, [M.0.0, (M+1).0.0) for a major line.
func (e Endpoint) span() (low, high string, ok bool) {
	switch {
	case e.MinorLine():
		major, minor := numbers(e.Line + ".0")
		return e.Line + ".0", strconv.FormatUint(major, 10) + "." + strconv.FormatUint(minor+1, 10) + ".0", true
	case e.MajorLine():
		major, _ := strconv.ParseUint(e.Line, 10, 64)
		return e.Line + ".0.0", strconv.FormatUint(major+1, 10) + ".0.0", true
	}
	return "", "", false
}

// holds reports whether the endpoint stands for the release version: the
// exact version itself (compared as the engine compares an anchor), or a
// release inside the line.
func (e Endpoint) holds(version string) bool {
	if e.Exact() {
		return e.Version == version
	}
	low, high, ok := e.span()
	return ok && validVersion(version) && !constraintengine.VersionLess(version, low) && constraintengine.VersionLess(version, high)
}

// intersects reports whether some release the endpoint stands for lies in
// the bound.
func (e Endpoint) intersects(b constraintengine.VersionBound) bool {
	if e.Exact() {
		return b.Contains(e.Version)
	}
	low, high, ok := e.span()
	return ok && constraintengine.VersionLess(b.Gte, b.Lt) && constraintengine.VersionLess(low, b.Lt) && constraintengine.VersionLess(b.Gte, high)
}

// PlanPath plans the upgrade of component from the exact version from to the
// exact version to. policy is the component's current reviewed policy, or nil
// when it has none; with nil the plan is one direct hop and Policy is empty,
// and deciding whether that hop is enough is the caller's job.
func PlanPath(component, from, to string, policy *PathPolicy) Plan {
	plan := Plan{Component: component, Hops: []Hop{}}
	if policy != nil {
		plan.Policy = policy.Policy
	}
	gap := func(reason Reason) Plan {
		plan.Hops, plan.Gap = []Hop{}, reason
		return plan
	}
	if !validVersion(from) || !validVersion(to) {
		return gap(GapPathNotPlannable)
	}
	if constraintengine.SameVersion(from, to) {
		return gap(GapPathNotPlannable)
	}
	if !constraintengine.VersionLess(from, to) {
		return gap(GapDowngradeNotReviewed)
	}
	if policy != nil && (policy.Component != component || !ValidPolicy(policy.Policy)) {
		return gap(GapPathNotPlannable)
	}
	first, last := Endpoint{Version: from}, Endpoint{Version: to}
	if policy == nil || policy.Policy == PolicyDirect {
		plan.Hops = []Hop{{Index: 1, From: first, To: last}}
		return plan
	}
	fromMajor, fromMinor := numbers(from)
	toMajor, toMinor := numbers(to)
	var (
		start, count uint64
		line         func(uint64) string
	)
	switch policy.Policy {
	case PolicySequentialMinor:
		if fromMajor != toMajor {
			// The last minor line of the old major is unknown.
			return gap(GapPathNotPlannable)
		}
		start, count = fromMinor, toMinor-fromMinor
		line = func(minor uint64) string {
			return strconv.FormatUint(fromMajor, 10) + "." + strconv.FormatUint(minor, 10)
		}
	case PolicySequentialMajor:
		start, count = fromMajor, toMajor-fromMajor
		line = func(major uint64) string { return strconv.FormatUint(major, 10) }
	}
	if count == 0 {
		plan.Hops = []Hop{{Index: 1, From: first, To: last}}
		return plan
	}
	if count > MaxHops {
		return gap(GapPathNotPlannable)
	}
	hops := make([]Hop, 0, count)
	for i := uint64(1); i <= count; i++ {
		hopFrom, hopTo := Endpoint{Line: line(start + i - 1)}, Endpoint{Line: line(start + i)}
		if i == 1 {
			hopFrom = first
		}
		if i == count {
			hopTo = last
		}
		hops = append(hops, Hop{Index: int(i), From: hopFrom, To: hopTo})
	}
	plan.Hops = hops
	return plan
}

// validVersion accepts a release version that both the engine and the line
// helpers read: M.m.p without leading zeros.
func validVersion(version string) bool {
	if _, ok := lineattest.LineOf(version); !ok {
		return false
	}
	return constraintengine.SameVersion(version, version)
}

// numbers returns the major and minor of a valid version.
func numbers(version string) (major, minor uint64) {
	parts := strings.SplitN(version, ".", 3)
	major, _ = strconv.ParseUint(parts[0], 10, 64)
	minor, _ = strconv.ParseUint(parts[1], 10, 64)
	return major, minor
}
