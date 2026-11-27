// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// offAnchorSiblings are the verdict rules of component that do not match
// from -> to although their anchor lies inside the range of a verdict rule
// that matches it through that range (constraintengine RangeHoldsUnmatched).
// The check routes report each as unreviewed for the pair; scan does the same,
// so such a rule never leaves a hop covered. No notice or lead rule takes part,
// and neither does a chart rule: from and to are application versions.
func offAnchorSiblings(rules []cncfcheck.ScanRule, component, from, to string) []cncfcheck.ScanRule {
	verdict := func(rule cncfcheck.ScanRule) bool {
		return rule.Scope.Component == component && rule.Scope.Transition.Chart == nil && !rule.Notice && !rule.SetNotice && rule.Basis != constraintengine.BasisLead
	}
	var siblings []cncfcheck.ScanRule
	for _, sibling := range rules {
		if !verdict(sibling) {
			continue
		}
		for _, ranged := range rules {
			if verdict(ranged) && ranged.Scope.Transition.RangeHoldsUnmatched(sibling.Scope.Transition, from, to) {
				siblings = append(siblings, sibling)
				break
			}
		}
	}
	return siblings
}

// offAnchorReason is the engine's reason of such a rule's claim.
const offAnchorReason = "RULE_TRANSITION_NOT_REVIEWED"
