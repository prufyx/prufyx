// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
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
		// Until the family is registered in the line-attestation package the
		// report refuses to read it: fail closed. With it registered, the
		// reasons below are STALE_RELEASES for a new patch release.
		{"unregistered or stale", []lineattest.LineAttestation{clAtt(comp, FamilyChangelogAttested, valid, []string{"1.8.0"}, []string{"1.9.0"})}, ""},
	}
	for _, c := range cases {
		got := changelogGapReason(comp, "1.8", "1.9", c.atts, now, nil, rels, nil)
		if c.want == "" {
			if _, reg := lineattest.LookupFamily(FamilyChangelogAttested); reg {
				c.want = GapStaleReleases
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
	for _, want := range []string{"`changelog.attested_entries`", "0 decided, 2 gap", "1 projects have a changelog target", "NO_ATTESTATION 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("sentence lacks %q: %s", want, s)
		}
	}
}

func TestStrictCrossingLineWide(t *testing.T) {
	mk := func(change string) string {
		return `"crossing":{"change":{"version":"` + change + `","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`
	}
	run := func(rule string, window ...string) string {
		report, err := Compute(Input{Pack: pack([]string{rule}, nil), Lines: lines("prometheus", window...), Now: baselineNow})
		if err != nil {
			t.Fatal(err)
		}
		return statuses(report.Projects[0])
	}
	if got := run(relnotesSetRule("p.r", "1.8.2", "1.9.0", mk("1.9.0")), "1.8", "1.9"); got != "B" {
		t.Errorf("x.y.0 crossing: %s", got)
	}
	// A removal in the middle of the line does not match a hop into x.y.0.
	if got := run(relnotesSetRule("p.r", "1.8.2", "1.9.1", mk("1.9.1")), "1.8", "1.9"); got == "B" {
		t.Errorf("x.y.1 crossing counted line-wide: %s", got)
	}
	// A crossing at 1.8.5 does not cover the whole from line 1.8.
	if got := run(relnotesSetRule("p.r", "1.8.2", "1.9.0", mk("1.8.5")), "1.8", "1.9"); got == "B" {
		t.Errorf("from region short counted: %s", got)
	}
}
