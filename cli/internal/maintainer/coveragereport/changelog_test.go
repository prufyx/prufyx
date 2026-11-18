// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const c40 = "0123456789012345678901234567890123456789"

func clAtt(component, family, until string, from, to []string) lineattest.LineAttestation {
	rel := func(vs []string) []lineattest.Release {
		var out []lineattest.Release
		for _, v := range vs {
			out = append(out, lineattest.Release{Version: v, Commit: c40})
		}
		return out
	}
	return lineattest.LineAttestation{Component: component, Line: "1.9", FactFamily: family, Completeness: lineattest.Completeness,
		Releases: &lineattest.Releases{From: rel(from), To: rel(to)},
		Evidence: lineattest.Evidence{ReviewedAt: "2026-09-01T00:00:00Z", ValidUntil: until}}
}

func TestChangelogGapReasons(t *testing.T) {
	const comp = "pkg:github/example/project"
	rels := map[string][]string{"1.8": {"1.8.0", "1.8.1"}, "1.9": {"1.9.0"}}
	now := baselineNow
	cases := []struct {
		name string
		atts []lineattest.LineAttestation
		want string
	}{
		{"none", nil, GapNoAttestation},
		{"expired", []lineattest.LineAttestation{clAtt(comp, FamilyChangelogAttested, "2026-10-01T00:00:00Z", []string{"1.8.0", "1.8.1"}, []string{"1.9.0"})}, GapNotCurrent},
		{"other component", []lineattest.LineAttestation{clAtt("pkg:github/example/other", FamilyChangelogAttested, valid, []string{"1.8.0", "1.8.1"}, []string{"1.9.0"})}, GapNoAttestation},
		{"other family", []lineattest.LineAttestation{clAtt(comp, lineattest.FamilyCustomResourceVersions, valid, []string{"1.8.0", "1.8.1"}, []string{"1.9.0"})}, GapNoAttestation},
		{"stale release set", []lineattest.LineAttestation{clAtt(comp, FamilyChangelogAttested, valid, []string{"1.8.0"}, []string{"1.9.0"})}, GapStaleReleases},
		{"completeness mismatch", []lineattest.LineAttestation{withCompleteness(clAtt(comp, FamilyChangelogAttested, valid, []string{"1.8.0", "1.8.1"}, []string{"1.9.0"}), "PARTIAL")}, GapCompletenessMismatch},
		// Releases match: without the family registered the report refuses to
		// read it (fail closed); registered, no rule is listed and no gap
		// reason applies, so the best reason stays NO_ATTESTATION.
		{"matching releases", []lineattest.LineAttestation{clAtt(comp, FamilyChangelogAttested, valid, []string{"1.8.0", "1.8.1"}, []string{"1.9.0"})}, ""},
	}
	for _, c := range cases {
		got := changelogGapReason(comp, "1.8", "1.9", c.atts, now, nil, rels, nil)
		if c.want == "" {
			if _, reg := lineattest.LookupFamily(FamilyChangelogAttested); reg {
				c.want = GapNoAttestation
			} else {
				c.want = GapFamilyNotRegistered
			}
		}
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := changelogGapReason(comp, "1.8", "1.9", nil, now, nil, rels, map[string]bool{comp: true}); got != GapMixedMember {
		t.Errorf("mixed: %s", got)
	}
}

func TestChangelogMixedMemberRefused(t *testing.T) {
	const comp = "pkg:github/example/project"
	in := Input{CRDTargetComponents: map[string]string{"p": comp}, ChangelogTargetComponents: map[string]string{"q": comp, "r": "pkg:github/example/clean"}}
	m := mixedComponents(in, nil)
	if !m[comp] || m["pkg:github/example/clean"] {
		t.Fatalf("mixed = %v", m)
	}
	// A CRD-family attestation and a changelog attestation on one component.
	atts := []lineattest.LineAttestation{
		clAtt(comp, lineattest.FamilyCustomResourceVersions, valid, nil, nil),
		clAtt(comp, FamilyChangelogAttested, valid, nil, nil),
	}
	if m := mixedComponents(Input{}, atts); !m[comp] {
		t.Fatalf("attestation mix not refused: %v", m)
	}
	if m := mixedComponents(Input{}, atts[1:]); len(m) != 0 {
		t.Fatalf("lone changelog attestation refused: %v", m)
	}
}

func TestChangelogReportRowAndCRDUnchanged(t *testing.T) {
	const comp = "pkg:github/prometheus/prometheus"
	base := Input{Pack: pack(nil, nil), Lines: lines("prometheus", "1.8", "1.9", "1.10"), Now: baselineNow}
	without, err := Compute(base)
	if err != nil {
		t.Fatal(err)
	}
	base.ChangelogTargetComponents = map[string]string{"prometheus": comp}
	with, err := Compute(base)
	if err != nil {
		t.Fatal(err)
	}
	if with.CRDPublishedProjects != without.CRDPublishedProjects || with.CRDVersionProjects != without.CRDVersionProjects || with.crd != without.crd {
		t.Fatal("the CRD counts moved")
	}
	if got, want := statuses(with.Projects[0]), statuses(without.Projects[0]); got != want || got != "GG" {
		t.Fatalf("statuses %q vs %q", got, want)
	}
	if with.changelog.targets != 1 || with.changelog.gap != 2 || with.changelog.decided != 0 || with.changelog.reasons[GapNoAttestation] != 2 {
		t.Fatalf("stats %+v", with.changelog)
	}
	if changelogSentence(without.changelog) != "" {
		t.Fatal("a row without a changelog target")
	}
	s := changelogSentence(with.changelog)
	for _, want := range []string{"`changelog.listed_entries`", "0 upgrades with the complete upstream change list", "never a pass", "not counted as decided", "2 gap", "1 projects have a changelog target", "NO_ATTESTATION 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("sentence lacks %q: %s", want, s)
		}
	}
}

func withCompleteness(a lineattest.LineAttestation, c string) lineattest.LineAttestation {
	a.Completeness = c
	return a
}

func TestChangelogMixedMemberCompute(t *testing.T) {
	const comp = "pkg:github/prometheus/prometheus"
	in := Input{Pack: pack(nil, nil), Lines: lines("prometheus", "1.8", "1.9", "1.10"), Now: baselineNow,
		CRDTargetComponents:       map[string]string{"prometheus": comp},
		ChangelogTargetComponents: map[string]string{"prometheus": comp}}
	r, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	c := r.changelog
	if c.decided != 0 || c.reasons[GapMixedMember] != 2 || c.targets != 0 || c.gap != 2 {
		t.Fatalf("stats %+v", c)
	}
	if statuses(r.Projects[0]) != "GG" {
		t.Fatalf("statuses %s", statuses(r.Projects[0]))
	}
}

func TestChangelogSpotBucket(t *testing.T) {
	c := changelogStats{targets: 1}
	c.addPair(Pair{Status: StatusS}, "")
	c.addPair(Pair{Status: StatusG}, GapNoAttestation)
	if c.pairs != 2 || c.spot != 1 || c.gap != 1 || c.decided+c.bounded+c.spot+c.gap != c.pairs {
		t.Fatalf("%+v", c)
	}
}

// A refused mixed member whose pair is decided by a rule (B) must still land
// in the G bucket with MIXED_MEMBER only: decided and bounded stay 0.
func TestChangelogMixedMemberNeverDecided(t *testing.T) {
	const comp = "pkg:github/prometheus/prometheus"
	const crossing = `"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`
	r, err := Compute(Input{Pack: pack([]string{relnotesSetRule("p.r", "1.8.2", "1.9.0", crossing)}, nil), Lines: lines("prometheus", "1.8", "1.9"), Now: baselineNow,
		CRDTargetComponents:       map[string]string{"prometheus": comp},
		ChangelogTargetComponents: map[string]string{"prometheus": comp}})
	if err != nil {
		t.Fatal(err)
	}
	if statuses(r.Projects[0]) != "B" {
		t.Fatalf("setup: %s", statuses(r.Projects[0]))
	}
	c := r.changelog
	if c.decided != 0 || c.bounded != 0 || c.gap != 1 || c.pairs != 1 || c.reasons[GapMixedMember] != 1 {
		t.Fatalf("stats %+v", c)
	}
}

// A pair decided only by the changelog family is marked Changelog with status
// G, so it moves no existing counter; the changelog row counts it as decided.
func TestChangelogOnlyClassSplit(t *testing.T) {
	const comp = "pkg:github/strimzi/strimzi-kafka-operator"
	atts := []lineattest.LineAttestation{clAtt(comp, FamilyChangelogAttested, "2027-01-01T00:00:00Z", []string{"1.8.0"}, []string{"1.9.0"})}
	rels := map[string][]string{"1.8": {"1.8.0"}, "1.9": {"1.9.0"}}
	pair := classify("strimzi", "1.8", "1.9", nil, atts, map[string]*ruleRec{}, rels)
	if pair.Status != StatusG || !pair.Changelog || len(pair.Families) != 0 {
		t.Fatalf("changelog-only pair: %+v", pair)
	}
	var c changelogStats
	c.addPair(pair, changelogGapReason(comp, "1.8", "1.9", atts, baselineNow, map[string]*ruleRec{}, rels, nil))
	if c.decided != 1 || c.gap != 0 || c.bounded != 0 || c.pairs != 1 {
		t.Fatalf("stats %+v", c)
	}
	// Another attested family decides too: a source decision, not a changelog one.
	if plain := (Pair{Status: StatusA, Families: []string{"other.family", FamilyChangelogAttested}}); true {
		var d changelogStats
		d.addPair(plain, "")
		if d.decided != 0 || d.bounded != 1 {
			t.Fatalf("source pair counted as changelog: %+v", d)
		}
	}
	// A release mismatch decides nothing and is typed.
	stale := map[string][]string{"1.8": {"1.8.0", "1.8.1"}, "1.9": {"1.9.0"}}
	if p := classify("strimzi", "1.8", "1.9", nil, atts, map[string]*ruleRec{}, stale); p.Changelog || p.Status != StatusG {
		t.Fatalf("stale pair: %+v", p)
	}
	if r := changelogGapReason(comp, "1.8", "1.9", atts, baselineNow, map[string]*ruleRec{}, stale, nil); r != GapStaleReleases {
		t.Fatalf("reason %s", r)
	}
}

func TestDecidedChangelogJSON(t *testing.T) {
	b, err := json.Marshal(Totals{})
	if err != nil || strings.Contains(string(b), "decidedChangelog") {
		t.Fatalf("zero count not omitted: %s %v", b, err)
	}
	b, _ = json.Marshal(Totals{DecidedChangelog: 2})
	if !strings.Contains(string(b), `"decidedChangelog":2`) {
		t.Fatalf("%s", b)
	}
}
