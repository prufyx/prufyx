// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// A ranged rule R that pins a release boundary C answers a hop crossing C
// outside its range with RULE_RELEASE_BOUNDARY_NOT_REVIEWED. Under the
// boundary-covered contract, and only there, that answer is replaced when an
// exact reviewed rule E decides the same check on the exact declared pair:
//
//   - R is a ranged application rule (no crossing, no chart) of one of the
//     three operators below, reviewed or mechanical or empirical;
//   - E is an exact rule (no range, no crossing, no chart) of the same
//     component whose anchor pair is byte-identical to the declared pair,
//     whose claim is PASS or BLOCKED with current or pinned evidence, and
//     whose decision key equals R's. The decision key is every field of the
//     rule except id, subject, range, evidence, reason code and next action;
//     a future rule field enters the key by construction. For
//     require_component_version the dependency version is excluded from the
//     key and E's must be at least R's, with comparison gte on both;
//   - the hop is an upgrade across C (from < C <= to). A downgrade is never
//     covered.
//
// R keeps its UNKNOWN claim, now with reason RULE_BOUNDARY_COVERED_BY_EXACT_RULE
// and the covering rule id. It never becomes a PASS: E's claim alone carries
// the verdict. The claim says "decided on the exact pair for the same check",
// not "boundary reviewed". Every other case stays RULE_RELEASE_BOUNDARY_NOT_REVIEWED.

const (
	// RulesSchemaBoundaryCovered is carried by a rule document that opts in
	// to the boundary-covered contract. Opt-in is by schema only. It also
	// admits every feature of the lower schemas and needs at least one
	// ranged rule.
	RulesSchemaBoundaryCovered = "prufyx.io/deterministic-constraint-rules/v1alpha11"

	// ScopeContractVersionBoundaryCovered is its scope-completeness contract.
	ScopeContractVersionBoundaryCovered = "scope-completeness-contract-v10"

	// ReasonBoundaryCoveredByExact belongs to the engine: a rule document
	// can never carry it. It is issued only under the boundary-covered
	// contract and only with a covering rule (validCoveredClaims).
	ReasonBoundaryCoveredByExact = "RULE_BOUNDARY_COVERED_BY_EXACT_RULE"

	rangeBoundaryPolicyCovered = rangeBoundaryPolicy + ";boundary-covered:" + ReasonBoundaryCoveredByExact +
		":exact-sibling:anchor-pair-byte-equal:decision-key-equal:pass-or-blocked:upgrade-only:never-crossing:never-chart:never-pass:not-applicable-in-scope:claim-keeps-unknown"
)

// engineContractDigestBoundaryCovered identifies the boundary-covered engine
// contract. It extends the chart range contract.
func engineContractDigestBoundaryCovered() string {
	return digestBytes([]byte(engineContractDigestChartRanged() + "\n" + RulesSchemaBoundaryCovered + "\n" + rangeBoundaryPolicyCovered))
}

// EngineContractDigestBoundaryCovered exposes the contract identity.
func EngineContractDigestBoundaryCovered() string { return engineContractDigestBoundaryCovered() }

// scopeContractDigestBoundaryCovered is the scope contract paired with it.
func scopeContractDigestBoundaryCovered() string {
	return digestBytes([]byte(scopeContractDigestChartRanged() + "\n" + ScopeContractVersionBoundaryCovered + "\n" + rangeBoundaryPolicyCovered + "\nnotApplicable:" + ReasonBoundaryCoveredByExact))
}

// ScopeContractDigestBoundaryCovered exposes the scope contract identity.
func ScopeContractDigestBoundaryCovered() string { return scopeContractDigestBoundaryCovered() }

// IsBoundaryCovered reports a claim whose boundary question was answered by
// an exact sibling. It is meaningful only on a sealed report: MarshalReport
// binds the reason to a valid covering claim, so a consumer that excludes
// such a claim from its undecided count does so on a validated report.
func (c Claim) IsBoundaryCovered() bool {
	return c.ReasonCode == ReasonBoundaryCoveredByExact && c.CoveringRuleID != ""
}

var coverableOperators = map[string]bool{
	"forbid_predicate_value":    true,
	OperatorForbidSetMember:     true,
	"require_component_version": true,
}

// coverDecisionKey is the canonical decision key of a rule. ok is false for
// a rule that may not take part.
func coverDecisionKey(r rule) (string, string, bool) {
	if !coverableOperators[r.Operator] || r.Subject.Chart != nil || r.Crossing != nil || !BasisMayPass(r.Evidence.Basis) || r.verdictNeutral() {
		return "", "", false
	}
	version := ""
	copied := r
	copied.ID, copied.Subject, copied.Range, copied.Evidence, copied.ReasonCode, copied.NextAction = "", transition{}, nil, evidence{}, "", ""
	if r.Operator == "require_component_version" {
		if r.Dependency == nil || r.Dependency.Comparison != "gte" {
			return "", "", false
		}
		dependency := *r.Dependency
		version, dependency.Version = dependency.Version, ""
		copied.Dependency = &dependency
	} else if r.Dependency != nil {
		return "", "", false
	}
	raw, err := json.Marshal(copied)
	if err != nil {
		return "", "", false
	}
	return string(raw), version, true
}

func coverableClaim(claim Claim) bool {
	return (claim.Status == "PASS" || claim.Status == "BLOCKED") && claim.SubjectMatch == nil && claim.CrossingMatch == nil && claim.CoveringRuleID == "" &&
		(claim.EvidenceFreshness == "current" || claim.EvidenceFreshness == FreshnessPinned) && !claim.IsVerdictNeutral() && BasisMayPass(claim.EvidenceBasis)
}

// coverBoundaryClaims rewrites, in place, every boundary claim an exact
// sibling covers. It runs only under the boundary-covered contract. claims is
// positionally aligned with rules.
func coverBoundaryClaims(input inputDocument, rules []rule, claims []Claim) {
	for index, r := range rules {
		claim := claims[index]
		if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed || r.Range == nil || r.Crossing != nil || r.Subject.Chart != nil {
			continue
		}
		key, version, ok := coverDecisionKey(r)
		if !ok {
			continue
		}
		current, foundCurrent := findComponent(input, "current", r.Subject.Component)
		proposed, foundProposed := findComponent(input, "proposed", r.Subject.Component)
		if !foundCurrent || !foundProposed || current.Chart != nil || proposed.Chart != nil || !upgradesAcrossBoundary(r.transition(), current.Version, proposed.Version) {
			continue
		}
		for other, candidate := range rules {
			if other == index || candidate.Range != nil || candidate.Subject.Component != r.Subject.Component || !coverableClaim(claims[other]) {
				continue
			}
			// Match compares the anchor pair with the declared versions
			// byte for byte; no other form of a version is an exact hop.
			if candidate.transition().Match(current.Version, proposed.Version) != MatchAnchor {
				continue
			}
			candidateKey, candidateVersion, candidateOK := coverDecisionKey(candidate)
			if !candidateOK || candidateKey != key {
				continue
			}
			if r.Operator == "require_component_version" {
				if c, comparable := compareVersions(candidateVersion, version); !comparable || c < 0 {
					continue
				}
			}
			claims[index].ReasonCode = ReasonBoundaryCoveredByExact
			claims[index].CoveringRuleID = candidate.ID
			claims[index].NextAction = boundedAction(fmt.Sprintf("this hop crosses the release boundary of a reviewed range; the exact reviewed rule %s decides the same check on the declared pair; the range itself is not reviewed for this hop", candidate.ID), "decided by an exact reviewed rule on the declared pair; see the covering rule")
			break
		}
	}
}

// upgradesAcrossBoundary reports an upgrade from < C <= to for the boundary C
// of the subject. A downgrade or an unparseable version never qualifies.
func upgradesAcrossBoundary(subject RuleTransition, from, to string) bool {
	change, ok := subject.changeVersion()
	if !ok || subject.refusesPreRelease(from, to) {
		return false
	}
	order, orderOK := compareVersions(from, to)
	below, belowOK := compareVersions(LineFloor(from), change)
	reached, reachedOK := compareVersions(LineFloor(to), change)
	return orderOK && belowOK && reachedOK && order < 0 && below < 0 && reached >= 0
}

// validCoveredClaims binds the covered reason and the covering rule id to the
// boundary-covered contract and to a covering claim of the same report. The
// seal gate checks what the report holds; Replay, which recomputes the whole
// report from the input and the rules, is the authority on the decision key.
func validCoveredClaims(report Report) bool {
	covered := report.EngineContractDigest == engineContractDigestBoundaryCovered()
	byID := make(map[string]Claim, len(report.Claims))
	for _, claim := range report.Claims {
		byID[claim.RuleID] = claim
	}
	for _, claim := range report.Claims {
		if claim.ReasonCode != ReasonBoundaryCoveredByExact && claim.CoveringRuleID == "" {
			continue
		}
		if !covered || claim.ReasonCode != ReasonBoundaryCoveredByExact || claim.CoveringRuleID == "" || !idRE.MatchString(claim.CoveringRuleID) || claim.CoveringRuleID == claim.RuleID ||
			claim.Status != "UNKNOWN" || claim.SubjectMatch != nil || claim.CrossingMatch != nil || claim.IsVerdictNeutral() || !coverableOperators[claim.Operator] || !BasisMayPass(claim.EvidenceBasis) {
			return false
		}
		cover, found := byID[claim.CoveringRuleID]
		if !found || !coverableClaim(cover) || cover.Operator != claim.Operator || cover.Severity != claim.Severity || !reflect.DeepEqual(cover.RequiredFacts, claim.RequiredFacts) {
			return false
		}
	}
	return true
}
