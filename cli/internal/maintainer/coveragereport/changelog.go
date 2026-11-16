// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// FamilyChangelogAttested is the id of the changelog-attested family. It is
// defined here as a plain string so this package does not depend on the
// line-attestation change that registers the family; the two strings must
// stay equal. Until that family is registered, LookupFamily refuses it and
// no attestation of it decides a pair.
const FamilyChangelogAttested = "changelog.attested_entries"

// Typed reasons a pair of a changelog-attested member project is a gap.
const (
	GapNoAttestation        = "NO_ATTESTATION"
	GapNotCurrent           = "ATTESTATION_NOT_CURRENT"
	GapCompletenessMismatch = "COMPLETENESS_MISMATCH"
	GapStaleReleases        = "STALE_RELEASES"
	GapRuleNotLineWide      = "RULE_NOT_LINE_WIDE"
	GapFamilyNotRegistered  = "FAMILY_NOT_REGISTERED"
	GapMixedMember          = "MIXED_MEMBER"
)

// changelogStats counts, over the CNCF member projects of the changelog
// family, the pairs it decides and the typed reasons of the others.
type changelogStats struct {
	targets int // projects with a reviewed changelog target
	decided int // pairs decided (A) by the changelog family
	bounded int // pairs of member projects decided by a rule (B)
	spot    int // pairs of member projects with a rule for one exact version pair only (S)
	gap     int
	pairs   int
	reasons map[string]int
}

func (c *changelogStats) active() bool { return c.targets > 0 || c.decided > 0 }

func (c *changelogStats) addPair(p Pair, reason string) {
	c.pairs++
	switch {
	case p.Status == StatusA && hasFamily(p.Families, FamilyChangelogAttested):
		c.decided++
	case p.Status == StatusB:
		c.bounded++
	case p.Status == StatusS:
		c.spot++
	case p.Status == StatusG:
		c.gap++
		if c.reasons == nil {
			c.reasons = map[string]int{}
		}
		c.reasons[reason]++
	}
}

func hasFamily(list []string, f string) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}

// mixedComponents returns the components that are in the CRD family (a
// reviewed CRD target, or an attestation of the CRD family) and also in the
// changelog family (a changelog target, or an attestation of it). A component
// is never in both families: such a component is refused and counts nothing
// for the changelog family.
func mixedComponents(in Input, atts []lineattest.LineAttestation) map[string]bool {
	crd := map[string]bool{}
	for _, c := range in.CRDTargetComponents {
		crd[c] = true
	}
	for _, a := range atts {
		if a.FactFamily == lineattest.FamilyCustomResourceVersions {
			crd[a.Component] = true
		}
	}
	out := map[string]bool{}
	for _, c := range in.ChangelogTargetComponents {
		if crd[c] {
			out[c] = true
		}
	}
	for _, a := range atts {
		if a.FactFamily == FamilyChangelogAttested && crd[a.Component] {
			out[a.Component] = true
		}
	}
	return out
}

// changelogGapReason names why a pair of a member project (component) is not
// decided: the most specific typed reason over its changelog attestations of
// the pair's hop, else NO_ATTESTATION. atts holds all attestations, current
// or not.
func changelogGapReason(component, from, to string, atts []lineattest.LineAttestation, now time.Time, byID map[string]*ruleRec, releases map[string][]string, mixed map[string]bool) string {
	if mixed[component] {
		return GapMixedMember
	}
	rank := map[string]int{GapNotCurrent: 1, GapCompletenessMismatch: 2, GapStaleReleases: 3, GapFamilyNotRegistered: 4, GapRuleNotLineWide: 5}
	best := GapNoAttestation
	consider := func(r string) {
		if rank[r] > rank[best] {
			best = r
		}
	}
	for _, a := range atts {
		if a.FactFamily != FamilyChangelogAttested || a.Component != component || a.Line != to || !a.HopFrom(from) {
			continue
		}
		if a.Freshness(now) != lineattest.FreshnessCurrent {
			consider(GapNotCurrent)
			continue
		}
		if a.Completeness != lineattest.Completeness {
			consider(GapCompletenessMismatch)
			continue
		}
		if !releasesMatch(a.Releases, releases[from], releases[to]) {
			consider(GapStaleReleases)
			continue
		}
		family, ok := lineattest.LookupFamily(a.FactFamily)
		if !ok {
			consider(GapFamilyNotRegistered)
			continue
		}
		for _, id := range a.RuleIDs {
			r := byID[id]
			if r == nil || !r.valid || !family.CoversLine(a.Component, r.tr, to) {
				consider(GapRuleNotLineWide)
				break
			}
		}
	}
	return best
}

// crossingLineWide reports whether a crossing rule decides every upgrade of
// the pair: it starts exactly at the first release (x.y.0) of the to line,
// its to region covers the whole to line, its from region covers the whole
// from line, and it admits upstream on both sides. A crossing at x.y.1 or
// later does not match a hop into x.y.0 and never counts.
func crossingLineWide(tr constraintengine.RuleTransition, fromLine, toLine string, toBound constraintengine.VersionBound) bool {
	cf, ct, ok := tr.CrossingBounds()
	if !ok || ct.Gte != toBound.Gte || !cf.CoversLine(fromLine) || !ct.CoversLine(toLine) {
		return false
	}
	return tr.CrossingAdmits(constraintengine.DistributionUpstream, constraintengine.DistributionUpstream)
}

// changelogSentence is the README line for the changelog family, empty when
// no project has a changelog target and no pair is decided by it.
func changelogSentence(c changelogStats) string {
	if !c.active() {
		return ""
	}
	var reasons []string
	keys := make([]string, 0, len(c.reasons))
	for k := range c.reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		reasons = append(reasons, fmt.Sprintf("%s %d", k, c.reasons[k]))
	}
	hist := "none"
	if len(reasons) > 0 {
		hist = strings.Join(reasons, ", ")
	}
	return fmt.Sprintf("Changelog-attested (`%s`): %d decided, %d gap over %d upgrades of its member projects (%d more decided by a rule, %d by a rule for one exact version pair only). %d projects have a changelog target; that is catalogue coverage, not the number of upgrades decided. Gap reasons: %s.\n", FamilyChangelogAttested, c.decided, c.gap, c.pairs, c.bounded, c.spot, c.targets, hist)
}
