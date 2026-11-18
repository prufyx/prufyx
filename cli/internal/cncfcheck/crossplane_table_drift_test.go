// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const crossplaneCompositionRulePrefix = "crossplane.composition-resources-mode-removed."

// The preparer's table of cited Crossplane versions must stay tied to the
// shipped rule ranges. Every cited version must be admitted by a rule, and no
// rule range may admit a whole minor series the table does not list. The rule
// range necessarily admits patch releases newer than the last cited tag; that
// gap is the preparer table's job to refuse and is stated as an omission.
func TestCrossplaneCitedTableMatchesRuleRanges(t *testing.T) {
	t.Parallel()
	identities, err := EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	var rules []RuleIdentity
	for _, identity := range identities {
		if strings.HasPrefix(identity.RuleID, crossplaneCompositionRulePrefix) {
			rules = append(rules, identity)
		}
	}
	if len(rules) == 0 {
		t.Fatal("no crossplane composition rules shipped")
	}
	from, to := cncfprepare.CrossplaneCitedVersions()
	admitted := func(version string, side func(RuleIdentity) constraintengine.VersionBound) bool {
		for _, rule := range rules {
			if rule.Range != nil && side(rule).Contains(version) {
				return true
			}
		}
		return false
	}
	fromSide := func(r RuleIdentity) constraintengine.VersionBound { return r.Range.From }
	toSide := func(r RuleIdentity) constraintengine.VersionBound { return r.Range.To }
	for _, version := range from {
		if !admitted(version, fromSide) {
			t.Errorf("cited from version %s is admitted by no shipped rule range", version)
		}
	}
	for _, version := range to {
		if !admitted(version, toSide) {
			t.Errorf("cited to version %s is admitted by no shipped rule range", version)
		}
	}
	// A rule range that admits a version the table does not list is allowed
	// only as the open end of a cited series: the next patch after the last
	// cited one. Any other admitted uncited version means the rule widened
	// (a new series, or a gap inside a series) without a reviewed table.
	listed := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, v := range values {
			out[v] = true
		}
		return out
	}
	fromSet, toSet := listed(from), listed(to)
	probe := func(side func(RuleIdentity) constraintengine.VersionBound, set map[string]bool, label string) {
		for _, rule := range rules {
			if rule.Range == nil {
				t.Errorf("rule %s has no range", rule.RuleID)
				continue
			}
			bound := side(rule)
			for major := 0; major <= 3; major++ {
				for minor := 0; minor <= 30; minor++ {
					for patch := 0; patch <= 40; patch++ {
						version := fmt.Sprintf("%d.%d.%d", major, minor, patch)
						if bound.Contains(version) && !set[version] {
							if !openEnd(set, major, minor, patch) {
								t.Errorf("%s: rule %s admits %s, which the preparer table neither lists nor leaves as the open end of a cited series", label, rule.RuleID, version)
							}
						}
					}
				}
			}
		}
	}
	probe(fromSide, fromSet, "from")
	probe(toSide, toSet, "to")
	// The gap exists and is declared: the rule admits the next patch, the
	// preparer refuses it, and the omission says so.
	for _, version := range []string{"1.20.15", "1.18.6", "1.19.4"} {
		if !admitted(version, fromSide) {
			t.Errorf("expected rule range to admit unlisted %s (open end)", version)
		}
		prepared, err := cncfprepare.PrepareCrossplaneComposition([]byte(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"a"},"spec":{"mode":"Resources"}}`), version, "2.0.0", cncfprepare.CrossplaneDistributionOfficial, true)
		if err != nil || prepared.State != cncfprepare.StateUnknown || prepared.Reason != cncfprepare.ReasonCrossplanePairUnsupported {
			t.Errorf("%s prepared=%+v err=%v", version, prepared, err)
		}
		found := false
		for _, omission := range prepared.Omissions {
			found = found || omission == cncfprepare.OmissionCrossplaneRangeAdmitsUnlistedPatches
		}
		if !found {
			t.Errorf("omission for the open range end missing: %v", prepared.Omissions)
		}
	}
}

// openEnd reports whether version M.m.p lies beyond the last listed patch of
// its own listed series.
func openEnd(set map[string]bool, major, minor, patch int) bool {
	if !set[fmt.Sprintf("%d.%d.0", major, minor)] {
		return false
	}
	for listed := patch; listed <= 40; listed++ {
		if set[fmt.Sprintf("%d.%d.%d", major, minor, listed)] {
			return false
		}
	}
	return true
}
