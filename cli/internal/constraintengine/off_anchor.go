// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import "fmt"

// A verdict rule reviewed at one pair says nothing about another pair, also
// when that other pair lies inside the reviewed range of a sibling rule. The
// sibling's range does not answer for it: its claim stays
// UNKNOWN RULE_TRANSITION_NOT_REVIEWED, and because the rule's anchor lies
// inside a range that decides this transition, it is named in its next action
// and marked so that no report folds it into the rules about other
// transitions. Nothing here changes a status or a reason code.

// IsOffAnchorSibling reports a claim of a verdict rule that does not match the
// declared pair although its anchor lies inside a reviewed range that does. It
// is set by Evaluate only: it is not serialized, so a decoded claim never
// carries it.
func (c Claim) IsOffAnchorSibling() bool { return c.offAnchorSibling }

// markOffAnchorSiblings marks, in place, every such claim. claims is
// positionally aligned with rules.
func markOffAnchorSiblings(input inputDocument, rules []rule, claims []Claim) {
	for index, sibling := range rules {
		claim := claims[index]
		if sibling.verdictNeutral() || claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
			continue
		}
		current, foundCurrent := findComponent(input, "current", sibling.Subject.Component)
		proposed, foundProposed := findComponent(input, "proposed", sibling.Subject.Component)
		if !foundCurrent || !foundProposed {
			continue
		}
		for _, ranged := range rules {
			if ranged.verdictNeutral() || !ranged.transition().RangeHoldsUnmatched(sibling.transition(), current.Version, proposed.Version) {
				continue
			}
			claims[index].offAnchorSibling = true
			claims[index].NextAction = boundedAction(fmt.Sprintf("rule %s is not reviewed for the declared pair, although its reviewed pair %s %s -> %s lies inside a reviewed range of this transition; check it by hand against its cited source or request coverage: %s", sibling.ID, sibling.Subject.Component, sibling.Subject.From, sibling.Subject.To, RequestCoverageURL),
				"a rule reviewed at a pair inside a reviewed range of this transition is not reviewed for the declared pair; check it by hand against its cited source")
			break
		}
	}
}
