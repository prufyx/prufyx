// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
)

// A crossing rule states that a reviewed removal at release C blocks every
// strict upgrade hop A -> B with A < C <= B, whatever the width of the hop.
// The blocking fact is observed at A: if the removed API is in use there, the
// hop to B breaks it however many minor lines it skips.
//
// The mode is block-only. A crossing match never produces PASS: a rule whose
// fact is false on a hop wider than any reviewed range is UNKNOWN with
// RULE_CROSSING_PASS_NOT_REVIEWED, the same "may block, never passes" pattern
// the consensus basis uses. PASS stays an anchor or reviewed-range match only.
//
// Only a removal qualifies (a changed or default-off behaviour can be reversed
// by flags). The claim stays finite: it holds only below a cited, reviewed
// horizon H, and below a restoration R when one is cited. Beyond that the
// result is UNKNOWN, never BLOCKED, because a wrong BLOCK is as unsupported
// as a wrong PASS. The match is also limited to versions that compare as
// upstream versions: the observed distribution must be one the rule lists, and
// every listed distribution has a reviewed version normaliser.
//
// Documents holding a crossing rule carry RulesSchemaCrossing and are
// evaluated under their own engine and scope contracts, so binaries that
// predate the field reject them, and every other document keeps its schema,
// digest and replay bytes.

const (
	// RulesSchemaCrossing is carried by, and only by, a rule document holding
	// at least one rule with a crossing object. It also admits every feature
	// of the lower schemas.
	RulesSchemaCrossing = "prufyx.io/deterministic-constraint-rules/v1alpha7"

	// MatchCrossing means the transition matched no anchor and no range but
	// crosses the rule's reviewed removal release inside its reviewed horizon.
	MatchCrossing MatchMode = "crossing"

	// ScopeContractVersionCrossing adds crossing rules to the severity scope
	// contract.
	ScopeContractVersionCrossing = "scope-completeness-contract-v6"

	// ReasonCrossingPassNotReviewed is the reason of a crossing-matched rule
	// whose fact did not block: nothing reviewed covers the whole hop.
	ReasonCrossingPassNotReviewed = "RULE_CROSSING_PASS_NOT_REVIEWED"

	// ReasonCrossingNotReviewed is the reason of a rule whose reviewed
	// removal (or release boundary) the declared hop crosses (from < C <= to)
	// but that the rule does not cover: the target is beyond the cited
	// horizon or at or above the restoration, or the observed distribution
	// is outside the rule's reviewed list. The engine knows the hop crosses
	// a cited removal, so the rule is UNDETERMINED in scope, never an
	// exclusion: absence of a match is not evidence that the hop is safe.
	ReasonCrossingNotReviewed = "RULE_CROSSING_NOT_REVIEWED"

	// ReasonReleaseBoundaryNotReviewed is the reason of a ranged rule whose
	// range pins a REMOVED_IN_RELEASE or CHANGED_IN_RELEASE boundary C when the
	// declared hop crosses C (from < C <= to) outside the reviewed range. It is
	// not an exclusion: the rule is UNDETERMINED in scope, so the engine never
	// reports a complete pass over a hop that crosses a cited boundary. It is
	// legal under every range-capable contract.
	ReasonReleaseBoundaryNotReviewed = "RULE_RELEASE_BOUNDARY_NOT_REVIEWED"

	// CrossingMaxHorizonLines bounds how far above the change version a
	// horizon may reach, in minor lines of the same major line. A horizon
	// asserts a review of every line below it, so it may not outrun the
	// lines a reviewer can plausibly have read.
	CrossingMaxHorizonLines = 12

	crossingModeName = "crossing"

	// DistributionUpstream is the distribution of a version declared as a
	// plain upstream X.Y.Z, and the default when none is declared.
	DistributionUpstream = "upstream"
	// DistributionGKE is a version normalised by the reviewed GKE
	// normaliser (internal/k8sversion) to its upstream X.Y.Z.
	DistributionGKE = "gke"

	crossingNextActionTemplate = "; matched by removal crossing %s; anchor pair %s -> %s"
	crossingNextActionShort    = "; matched by removal crossing %s"
	crossingPassAction         = "no reviewed rule covers this whole hop; a removal crossing never passes; retain actual versions and request reviewed coverage"

	crossingSemantics = "crossing:forbid-operators-only;basis:" + BasisRemovedInRelease + ";horizon:" + BasisReviewedThroughMinorLine + ":finite-cited;restored:" + BasisRestoredInRelease + ":caps-horizon;match:A<C<=B<min(horizon,restored);order:anchor,range,crossing;distributions:upstream,gke;never-pass;pass-becomes:" + ReasonCrossingPassNotReviewed + ";beyond-horizon:unknown;downgrade:unknown;unparseable:unknown;restored:minor-line-start-above-change-and-range;horizon:same-major-at-most-12-minor-lines-above-change;unreviewed-crossing:" + ReasonCrossingNotReviewed + ":undetermined-in-scope;range-release-boundary-unreviewed:" + ReasonReleaseBoundaryNotReviewed + ":undetermined-in-scope"
)

// reviewedDistributions is the closed list of distributions whose versions
// have a reviewed normaliser to an upstream X.Y.Z: upstream itself and GKE.
// It is ascending, the canonical order of a rule's distributions list. EKS
// and AKS are added explicitly when their normalisers are reviewed.
var reviewedDistributions = []string{DistributionGKE, DistributionUpstream}

// ReviewedDistributions returns the closed list a crossing rule may name.
func ReviewedDistributions() []string { return append([]string(nil), reviewedDistributions...) }

// ReviewedDistribution reports whether name is in the closed list.
func ReviewedDistribution(name string) bool { return contains(reviewedDistributions, name) }

// CrossingChange is the cited removal release C.
type CrossingChange struct {
	Version  string `json:"version"`
	Basis    string `json:"basis"`
	SourceID string `json:"sourceId"`
}

// CrossingHorizon is the cited, finite review horizon H: crossing applies
// only to targets below H.
type CrossingHorizon struct {
	Lt       string `json:"lt"`
	Basis    string `json:"basis"`
	SourceID string `json:"sourceId"`
}

// CrossingRestored is an optional cited restoration release R. It caps the
// horizon: from R on the result is UNKNOWN.
type CrossingRestored struct {
	Version  string `json:"version"`
	Basis    string `json:"basis"`
	SourceID string `json:"sourceId"`
}

// CrossingSpec is a rule's reviewed crossing declaration.
type CrossingSpec struct {
	Change        CrossingChange    `json:"change"`
	Horizon       CrossingHorizon   `json:"horizon"`
	Restored      *CrossingRestored `json:"restored,omitempty"`
	Distributions []string          `json:"distributions,omitempty"`
}

// Cap is min(horizon.lt, restored.version): the exclusive upper bound of the
// target versions the crossing covers.
func (c CrossingSpec) Cap() string {
	if c.Restored != nil {
		if cmp, ok := compareVersions(c.Restored.Version, c.Horizon.Lt); ok && cmp < 0 {
			return c.Restored.Version
		}
	}
	return c.Horizon.Lt
}

// contains reports the crossing region: from < C <= to < Cap, both versions
// valid. A downgrade, an equal pair and an unparseable version never match.
func (c CrossingSpec) contains(from, to string) bool {
	below, ok1 := compareVersions(from, c.Change.Version)
	reached, ok2 := compareVersions(to, c.Change.Version)
	capped, ok3 := compareVersions(to, c.Cap())
	strict, ok4 := compareVersions(from, to)
	return ok1 && ok2 && ok3 && ok4 && below < 0 && reached >= 0 && capped < 0 && strict < 0
}

// Crosses reports whether the pair is a crossing hop of this spec: a strict
// upgrade with from < C <= to < Cap, both versions valid.
func (c CrossingSpec) Crosses(from, to string) bool { return c.contains(from, to) }

// MinorLineStart reports whether the version is a valid X.Y.0.
func MinorLineStart(version string) bool {
	parsed, ok := parseVersion(version)
	return ok && minorStart(parsed)
}

// CrossingHorizonWithinLimit reports whether the horizon is a valid minor-line
// start of the change version's major line, at most CrossingMaxHorizonLines
// minor lines above the change version. Both versions must be valid.
func CrossingHorizonWithinLimit(change, horizon string) bool {
	c, ok1 := parseVersion(change)
	h, ok2 := parseVersion(horizon)
	return ok1 && ok2 && c[0] == h[0] && h[1] >= c[1] && uint64(h[1])-uint64(c[1]) <= CrossingMaxHorizonLines
}

// admits reports whether both observed distributions are in the rule's
// scope. An undeclared distribution is upstream; an absent list means
// upstream only.
func (c CrossingSpec) admits(fromDistribution, toDistribution string) bool {
	scope := c.Distributions
	if len(scope) == 0 {
		scope = []string{DistributionUpstream}
	}
	norm := func(d string) string {
		if d == "" {
			return DistributionUpstream
		}
		return d
	}
	return contains(scope, norm(fromDistribution)) && contains(scope, norm(toDistribution))
}

// usesCrossing reports whether a parsed rule needs the crossing contract.
func (r rule) usesCrossing() bool { return r.Crossing != nil }

// validateCrossingRule checks the crossing object of one rule. Every failure
// is ErrInvalid: a crossing the engine cannot fully check is never admitted.
func validateCrossingRule(r rule) error {
	if r.ReasonCode == ReasonCrossingPassNotReviewed || r.ReasonCode == ReasonCrossingNotReviewed || r.ReasonCode == ReasonReleaseBoundaryNotReviewed {
		return fmt.Errorf("reason code %s belongs to the engine: %w", r.ReasonCode, ErrInvalid)
	}
	c := r.Crossing
	if c == nil {
		return nil
	}
	fail := func(what string) error { return fmt.Errorf("crossing %s: %w", what, ErrInvalid) }
	if r.Operator != "forbid_predicate_value" && r.Operator != OperatorForbidSetMember {
		return fail("is only valid for forbid operators")
	}
	// A consensus rule may only block with a verdict-neutral reading and a
	// lead never blocks: neither carries the reviewed removal a crossing needs.
	if r.Evidence.Basis == BasisLead || r.Evidence.Basis == BasisConsensus {
		return fail("cannot sit on a consensus or lead rule")
	}
	if c.Change.Basis != BasisRemovedInRelease {
		return fail("change basis must be " + BasisRemovedInRelease)
	}
	if c.Horizon.Basis != BasisReviewedThroughMinorLine {
		return fail("horizon basis must be " + BasisReviewedThroughMinorLine)
	}
	change, ok := parseVersion(c.Change.Version)
	if !ok || !minorStart(change) {
		return fail("change version must be a minor-line start X.Y.0")
	}
	horizon, ok := parseVersion(c.Horizon.Lt)
	if !ok || !minorStart(horizon) {
		return fail("horizon must be a finite minor-line start X.Y.0")
	}
	if cmp, _ := compareVersions(c.Change.Version, c.Horizon.Lt); cmp >= 0 {
		return fail("horizon must be above the change version")
	}
	if !CrossingHorizonWithinLimit(c.Change.Version, c.Horizon.Lt) {
		return fail(fmt.Sprintf("horizon must stay in the change version's major line and at most %d minor lines above it", CrossingMaxHorizonLines))
	}
	sources := make(map[string]bool, len(r.Evidence.Sources))
	for _, source := range r.Evidence.Sources {
		sources[source.ID] = true
	}
	cited := func(id string) bool { return idRE.MatchString(id) && sources[id] }
	if !cited(c.Change.SourceID) || !cited(c.Horizon.SourceID) {
		return fail("change and horizon must each cite one of the rule's evidence sources")
	}
	if c.Restored != nil {
		if c.Restored.Basis != BasisRestoredInRelease || !cited(c.Restored.SourceID) {
			return fail("restored must carry basis " + BasisRestoredInRelease + " and a cited source")
		}
		restored, ok := parseVersion(c.Restored.Version)
		if !ok || !minorStart(restored) {
			return fail("restored version must be a minor-line start X.Y.0")
		}
		// A restoration lies above everything the rule's own subject
		// matches: above the change version and, with a range, at or above
		// the end of its target side. Otherwise a hop past the restoration
		// would still range-match and be BLOCKED for a served API.
		floor := c.Change.Version
		if r.Range != nil {
			floor = r.Range.To.Lt
		}
		above, _ := compareVersions(c.Restored.Version, c.Change.Version)
		aboveRange, aboveRangeOK := compareVersions(c.Restored.Version, floor)
		within, _ := compareVersions(c.Restored.Version, c.Horizon.Lt)
		if above <= 0 || !aboveRangeOK || aboveRange < 0 || within > 0 {
			return fail("restored must lie above the change version and the range, and not above the horizon")
		}
	}
	if c.Distributions != nil {
		if len(c.Distributions) == 0 {
			return fail("distributions must be non-empty when present")
		}
		for i, name := range c.Distributions {
			if !ReviewedDistribution(name) || i > 0 && c.Distributions[i-1] >= name {
				return fail("distributions must be a strictly ascending list of reviewed distributions")
			}
		}
	}
	if r.Range != nil && (!sameVersion(r.Range.From.Lt, c.Change.Version) || !sameVersion(r.Range.To.Gte, c.Change.Version)) {
		return fail("change version must equal range.from.lt and range.to.gte")
	}
	// The reviewed anchor pair is itself a crossing hop inside the cap.
	if !c.contains(r.Subject.From, r.Subject.To) {
		return fail("anchor pair must cross the change version below the horizon")
	}
	return nil
}

// validateCrossingShape is the exact-key gate for a rule's crossing object,
// run before struct decoding like every other shape gate.
func validateCrossingShape(raw json.RawMessage) error {
	object, err := exactObject(raw, []string{"change", "horizon"}, []string{"restored", "distributions"})
	if err != nil {
		return err
	}
	if _, err := exactObject(object["change"], []string{"version", "basis", "sourceId"}, nil); err != nil {
		return err
	}
	if _, err := exactObject(object["horizon"], []string{"lt", "basis", "sourceId"}, nil); err != nil {
		return err
	}
	if restored, ok := object["restored"]; ok {
		if _, err := exactObject(restored, []string{"version", "basis", "sourceId"}, nil); err != nil {
			return err
		}
	}
	if raw, ok := object["distributions"]; ok {
		values, err := exactArray(raw)
		if err != nil || len(values) == 0 || len(values) > len(reviewedDistributions) {
			return ErrInvalid
		}
		for _, value := range values {
			var name string
			if json.Unmarshal(value, &name) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

// AnyCrossingRule reports whether any raw rule declares a crossing object,
// which needs RulesSchemaCrossing. It reads the key only; ParseRuleSet
// remains the authority on validity.
func AnyCrossingRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape["crossing"]; ok {
			return true, nil
		}
	}
	return false, nil
}

// CrossingMatch discloses a crossing match: the reviewed anchor pair, the
// removal release the hop crosses and the exclusive upper bound the
// crossing is reviewed to.
type CrossingMatch struct {
	Mode       string `json:"mode"`
	AnchorFrom string `json:"anchorFrom"`
	AnchorTo   string `json:"anchorTo"`
	Change     string `json:"change"`
	CappedAt   string `json:"cappedAt"`
}

// applyCrossing finishes a claim whose subject matched by crossing: it
// discloses the match, keeps BLOCKED, and turns a would-be PASS into UNKNOWN.
// Every other UNKNOWN passes through unchanged.
func applyCrossing(claim Claim, r rule) Claim {
	claim.CrossingMatch = NewCrossingMatch(r.transition())
	if claim.Status == "PASS" {
		claim.Status, claim.ReasonCode = "UNKNOWN", ReasonCrossingPassNotReviewed
		claim.NextAction = boundedAction(crossingPassAction, "no reviewed rule covers this whole hop")
		return claim
	}
	claim.NextAction = CrossingNextAction(claim.NextAction, r.transition())
	return claim
}

// NewCrossingMatch is the disclosure of a crossing subject: its reviewed
// anchor pair, the removal release and the exclusive upper bound. It is nil
// for a subject without a crossing.
func NewCrossingMatch(t RuleTransition) *CrossingMatch {
	if t.Crossing == nil {
		return nil
	}
	return &CrossingMatch{Mode: crossingModeName, AnchorFrom: t.From, AnchorTo: t.To, Change: t.Crossing.Change.Version, CappedAt: t.Crossing.Cap()}
}

// CrossingNextAction appends the crossing disclosure to a rule's next
// action, within the bound every next action keeps.
func CrossingNextAction(action string, t RuleTransition) string {
	if t.Crossing == nil {
		return action
	}
	full := boundedAction(action+fmt.Sprintf(crossingNextActionTemplate, t.Crossing.Change.Version, t.From, t.To), "")
	if full == "" {
		full = boundedAction(action+fmt.Sprintf(crossingNextActionShort, t.Crossing.Change.Version), action)
	}
	return full
}

// engineContractDigestCrossing identifies the contract for rule documents
// that hold a crossing rule. It extends the severity contract with the
// crossing object, the crossing disclosure and its semantics.
func engineContractDigestCrossing() string {
	return digestBytes([]byte(engineContractDigestSeverity() + "\n" + RulesSchemaCrossing + "\nrule:crossing\nclaim:crossingMatch\nsubject:" + crossingModeName + "\nreason:" + ReasonCrossingPassNotReviewed + "\nreason:" + ReasonCrossingNotReviewed + "\n" + crossingSemantics))
}

// EngineContractDigestCrossing exposes the contract identity for rule
// documents that hold a crossing rule.
func EngineContractDigestCrossing() string { return engineContractDigestCrossing() }

// scopeContractDigestCrossing adds crossing rules to the severity scope
// vocabulary. It is used only with the crossing engine contract.
func scopeContractDigestCrossing() string {
	return digestBytes([]byte(scopeContractDigestSeverity() + "\n" + ScopeContractVersionCrossing + "\n" + crossingSemantics + "\nnotEvaluated:" + ApplicabilityUndetermined + ":" + ReasonCrossingPassNotReviewed + "\nnotEvaluated:" + ApplicabilityUndetermined + ":" + ReasonCrossingNotReviewed))
}

// ScopeContractDigestCrossing exposes the crossing scope-completeness
// identity.
func ScopeContractDigestCrossing() string { return scopeContractDigestCrossing() }

// atLeastSeverityContract reports a digest that admits every feature of the
// severity contract: the severity contract itself or the crossing one.
func atLeastSeverityContract(digest string) bool {
	return digest == engineContractDigestSeverity() || digest == engineContractDigestCrossing()
}

// validCrossingClaims binds the crossing semantics to the crossing contract:
// a claim that discloses a crossing match is legal only under it, comes from a
// forbid operator, is never a PASS, and holds a well-formed disclosure; the
// crossing reason code appears only on such a claim.
//
// It cannot tell that a disclosure was stripped from a claim that is
// otherwise well formed: once the disclosure is gone nothing in the report
// says the claim matched by crossing (the same holds for a range disclosure).
// Replay, which recomputes the whole report from the input and the rules, is
// the authority on the match mode; the seal gate is not.
func validCrossingClaims(report Report) bool {
	crossingContract := report.EngineContractDigest == engineContractDigestCrossing()
	for _, claim := range report.Claims {
		match := claim.CrossingMatch
		if match == nil {
			// The pass reason is the disclosure of a crossing match; the
			// not-reviewed reason is the crossing contract's own UNKNOWN.
			if claim.ReasonCode == ReasonCrossingPassNotReviewed || claim.ReasonCode == ReasonCrossingNotReviewed && (!crossingContract || claim.Status != "UNKNOWN") {
				return false
			}
			continue
		}
		if !crossingContract || match.Mode != crossingModeName || claim.Status == "PASS" || claim.SubjectMatch != nil || claim.Operator != "forbid_predicate_value" && claim.Operator != OperatorForbidSetMember || claim.IsLead() || claim.EvidenceBasis == BasisConsensus {
			return false
		}
		if claim.ReasonCode == ReasonCrossingPassNotReviewed && claim.Status != "UNKNOWN" || claim.Status == "UNKNOWN" && (claim.ReasonCode == "RULE_TRANSITION_NOT_REVIEWED" || claim.ReasonCode == ReasonCrossingNotReviewed || claim.ReasonCode == ReasonReleaseBoundaryNotReviewed) {
			return false
		}
		change, changeOK := parseVersion(match.Change)
		_, capOK := parseVersion(match.CappedAt)
		above, aboveOK := compareVersions(match.CappedAt, match.Change)
		if !validVersion(match.AnchorFrom) || !validVersion(match.AnchorTo) || !changeOK || !minorStart(change) || !capOK || !aboveOK || above <= 0 {
			return false
		}
		below, ok1 := compareVersions(match.AnchorFrom, match.Change)
		reached, ok2 := compareVersions(match.AnchorTo, match.Change)
		if !ok1 || !ok2 || below >= 0 || reached < 0 {
			return false
		}
	}
	return true
}

// validReleaseBoundaryClaims binds ReasonReleaseBoundaryNotReviewed to the
// range-capable contracts: it is an UNKNOWN reason that never appears under
// the exact-only contract, never on a PASS or BLOCKED claim, and never on a
// claim that carries a match disclosure (the claim did not match).
func validReleaseBoundaryClaims(report Report) bool {
	for _, claim := range report.Claims {
		if claim.ReasonCode != ReasonReleaseBoundaryNotReviewed {
			continue
		}
		if report.EngineContractDigest == engineContractDigest() || claim.Status != "UNKNOWN" || claim.SubjectMatch != nil || claim.CrossingMatch != nil {
			return false
		}
	}
	return true
}

// crossingRegions are the from and to intervals a crossing rule matches:
// from in [0.0.0, C) and to in [C, Cap).
func crossingRegions(c *CrossingSpec) (interval, interval) {
	return interval{low: "0.0.0", high: c.Change.Version}, interval{low: c.Change.Version, high: c.Cap()}
}
