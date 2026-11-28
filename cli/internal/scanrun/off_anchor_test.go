// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestOffAnchorSiblings: scan finds the same rules the check selections keep,
// and nothing else.
func TestOffAnchorSiblings(t *testing.T) {
	t.Parallel()
	const component = "pkg:github/kubernetes/kubernetes"
	rule := func(id, from, to string, ranged bool) cncfcheck.ScanRule {
		var out cncfcheck.ScanRule
		out.Scope.ID, out.Scope.Component = id, component
		out.Scope.Transition = constraintengine.RuleTransition{Component: component, From: from, To: to}
		if ranged {
			out.Scope.Transition.Range = &constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: "1.40.0", Lt: "1.41.0"}, To: constraintengine.VersionBound{Gte: "1.41.0", Lt: "1.42.0"}}
		}
		return out
	}
	ranged := rule("ranged", "1.40.0", "1.41.0", true)
	sibling := rule("sibling", "1.40.0", "1.41.0", false)
	outside := rule("outside", "1.38.0", "1.39.0", false)
	notice, setNotice, lead, otherRange := sibling, sibling, sibling, ranged
	notice.Scope.ID, notice.Notice = "notice", true
	setNotice.Scope.ID, setNotice.SetNotice = "set-notice", true
	lead.Scope.ID, lead.Basis = "lead", constraintengine.BasisLead
	rules := []cncfcheck.ScanRule{ranged, sibling, outside, notice, setNotice, lead}
	got := offAnchorSiblings(rules, component, "1.40.1", "1.41.2")
	if len(got) != 1 || got[0].Scope.ID != "sibling" {
		t.Fatalf("siblings %+v", got)
	}
	// At the anchor pair the sibling matches; outside the range nothing is
	// brought in; a notice range brings nothing in.
	for name, pair := range map[string][2]string{"anchor": {"1.40.0", "1.41.0"}, "outside the range": {"1.42.0", "1.43.0"}} {
		if got := offAnchorSiblings(rules, component, pair[0], pair[1]); len(got) != 0 {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	otherRange.Notice = true
	if got := offAnchorSiblings([]cncfcheck.ScanRule{otherRange, sibling}, component, "1.40.1", "1.41.2"); len(got) != 0 {
		t.Fatalf("a notice range brought a rule in: %+v", got)
	}
	if got := offAnchorSiblings(rules, "pkg:github/other/other", "1.40.1", "1.41.2"); len(got) != 0 {
		t.Fatalf("another component: %+v", got)
	}
}
