// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
)

// A ranged chart rule widens a chart rule from its anchor pair (the first
// release of one chart release line to the first release of the next) to
// every release of both lines. It admits exactly the two release-line
// shapes a line-wide derivation produces, and nothing else:
//
//   - consecutive lines M.(m-1) -> M.m of one major: from [M.(m-1).0,
//     M.m.0) and to [M.m.0, M.(m+1).0), bounds PREVIOUS_MINOR_LINE,
//     CHANGED_IN_RELEASE or REMOVED_IN_RELEASE (the same on from.lt and
//     to.gte), and TARGET_SERIES. The range pins the release boundary
//     M.m.0, so a hop that crosses it outside the range (a skipped line) is
//     RULE_RELEASE_BOUNDARY_NOT_REVIEWED, undetermined in scope, never an
//     exclusion;
//   - any other pair of lines (a new major, a gap in minor numbers): each
//     side is one whole line, bounds UPGRADE_FROM_SERIES twice and
//     TARGET_SERIES twice. No boundary is known, so a hop outside the range
//     is excluded as for any range without release-basis bounds. This shape
//     is refused for consecutive lines, which always take the boundary
//     shape.
//
// Every other basis (ANCHOR_ONLY, RESTORED_IN_RELEASE,
// REVIEWED_THROUGH_MINOR_LINE) is refused on a chart rule, because nothing
// in a chart derivation licenses it. A ranged chart rule is one of the three
// operators a chart derivation produces (require_component_version,
// require_set_member, forbid_set_member); it never carries a crossing or a
// severity, and every structural range guard applies unchanged. A set notice
// stays anchor-only.
//
// Documents holding a ranged chart rule carry RulesSchemaChartRanged and are
// evaluated under their own engine and scope contracts, so binaries that
// predate them reject such documents, and every other document keeps its
// schema, digest and replay bytes.

const (
	// RulesSchemaChartRanged is carried by, and only by, a rule document
	// holding at least one chart rule with a range. It also admits every
	// feature of the lower schemas.
	RulesSchemaChartRanged = "prufyx.io/deterministic-constraint-rules/v1alpha10"

	// ScopeContractVersionChartRanged adds ranged chart rules to the chart
	// notice scope contract.
	ScopeContractVersionChartRanged = "scope-completeness-contract-v9"

	chartRangeSemantics = "chart-rule:range:line-shapes:consecutive(" + BasisPreviousMinorLine + "," + BasisChangedInRelease + "|" + BasisRemovedInRelease + "," + BasisTargetSeries + ")" +
		"|whole-line(" + BasisUpgradeFromSeries + "," + BasisTargetSeries + "):non-consecutive-lines-only" +
		";operators:require_component_version," + OperatorRequireSetMember + "," + OperatorForbidSetMember +
		";set-notice:anchor-only;no-crossing;no-severity;" + rangeBoundaryPolicy
)

// usesChartRange reports whether a parsed rule needs the ranged chart
// contract.
func (r rule) usesChartRange() bool { return r.Subject.Chart != nil && r.Range != nil }

// chartRangeOperators are the operators a ranged chart rule may use.
var chartRangeOperators = map[string]bool{
	"require_component_version": true,
	OperatorRequireSetMember:    true,
	OperatorForbidSetMember:     true,
}

// validateChartRange checks that a chart rule's range has one of the two
// release-line shapes. validateRange applies every other range guard. Every
// failure is ErrInvalid.
func validateChartRange(r rule) error {
	if !chartRangeOperators[r.Operator] {
		return fmt.Errorf("a ranged chart rule must be require_component_version, require_set_member or forbid_set_member: %w", ErrInvalid)
	}
	if !chartRangeShape(*r.Range) {
		return fmt.Errorf("a chart rule's range must be the consecutive-line or whole-line shape: %w", ErrInvalid)
	}
	return nil
}

// ValidChartRangeShape reports whether a chart rule with this operator may
// carry this range: one of the three ranged chart operators, and one of the
// two release-line shapes. It does not apply the other range guards;
// ParseRuleSet remains the authority.
func ValidChartRangeShape(operator string, rng VersionRange) bool {
	return chartRangeOperators[operator] && chartRangeShape(rng)
}

// chartRangeShape reports the consecutive-line shape between consecutive
// lines of one major, or the whole-line shape between any other two lines.
// validateBasisStructure binds the versions each basis names.
func chartRangeShape(rng VersionRange) bool {
	if len(rng.Bounds) != len(boundOrder) {
		return false
	}
	basis := make([]string, len(rng.Bounds))
	for i, bound := range rng.Bounds {
		if bound.Bound != boundOrder[i] {
			return false
		}
		basis[i] = bound.Basis
	}
	from, fromOK := parseVersion(rng.From.Gte)
	to, toOK := parseVersion(rng.To.Gte)
	if !fromOK || !toOK {
		return false
	}
	consecutive := from[0] == to[0] && uint64(from[1])+1 == uint64(to[1])
	release := basis[1] == BasisChangedInRelease || basis[1] == BasisRemovedInRelease
	switch {
	case basis[0] == BasisPreviousMinorLine && release && basis[2] == basis[1] && basis[3] == BasisTargetSeries:
		return consecutive
	case basis[0] == BasisUpgradeFromSeries && basis[1] == BasisUpgradeFromSeries && basis[2] == BasisTargetSeries && basis[3] == BasisTargetSeries:
		return !consecutive
	}
	return false
}

// AnyChartRangedRule reports whether any raw rule carries a chart subject
// and a range, which needs RulesSchemaChartRanged. It reads the keys only;
// ParseRuleSet remains the authority on validity.
func AnyChartRangedRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape struct {
			Subject map[string]json.RawMessage `json:"subject"`
			Range   json.RawMessage            `json:"range"`
		}
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape.Subject["chart"]; ok && shape.Range != nil {
			return true, nil
		}
	}
	return false, nil
}

// engineContractDigestChartRanged identifies the contract for rule
// documents that hold a ranged chart rule. It extends the chart notice
// contract.
func engineContractDigestChartRanged() string {
	return digestBytes([]byte(engineContractDigestChartNotice() + "\n" + RulesSchemaChartRanged + "\nrule:chart.range\n" + chartRangeSemantics))
}

// EngineContractDigestChartRanged exposes the contract identity for rule
// documents that hold a ranged chart rule.
func EngineContractDigestChartRanged() string { return engineContractDigestChartRanged() }

// scopeContractDigestChartRanged adds ranged chart rules to the chart
// notice scope vocabulary. It is used only with the ranged chart engine
// contract.
func scopeContractDigestChartRanged() string {
	return digestBytes([]byte(scopeContractDigestChartNotice() + "\n" + ScopeContractVersionChartRanged + "\n" + chartRangeSemantics + "\nunresolved:" + unresolvedTransitionNotAnchor + ":chart-range"))
}

// ScopeContractDigestChartRanged exposes the ranged chart
// scope-completeness identity.
func ScopeContractDigestChartRanged() string { return scopeContractDigestChartRanged() }
