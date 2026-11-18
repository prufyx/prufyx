// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const listedComp = "pkg:github/prometheus/prometheus"

func TestListedFamilyIdIsTheRegisteredOne(t *testing.T) {
	if FamilyChangelogListed != lineattest.FamilyChangelogListedEntries {
		t.Fatalf("%q != %q", FamilyChangelogListed, lineattest.FamilyChangelogListedEntries)
	}
	if _, ok := lineattest.LookupFamily(FamilyChangelogListed); !ok {
		t.Fatal("not registered")
	}
}

// listedAttJSON is a listed-entries attestation of line 1.9: from releases of
// 1.8, the given to releases of 1.9.
func listedAttJSON(component string, to ...string) string {
	rel := func(v string) string { return fmt.Sprintf(`{"version":%q,"commit":%q}`, v, rev) }
	var rs []string
	for _, v := range to {
		rs = append(rs, rel(v))
	}
	src := fmt.Sprintf(`{"id":"changelog-1.9.0","url":"https://github.com/prometheus/prometheus/blob/%s/CHANGELOG.md","revision":%q,"contentDigest":"sha256:%s","startLine":1,"endLine":10}`, rev, rev, strings.Repeat("a", 64))
	return fmt.Sprintf(`{"component":%q,"line":"1.9","factFamily":%q,"completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":[],`+
		`"releases":{"from":[%s],"to":[%s]},`+
		`"evidence":{"basis":"mechanical","extractor":{"id":"changelog.listed.prometheus","version":"1.0.0","codeDigest":"sha256:%s"},"derivedAt":"2026-09-01T00:00:00Z","reviewedAt":"2026-09-01T00:00:00Z","validUntil":%q,"sources":[%s]}}`,
		component, lineattest.FamilyChangelogListedEntries, rel("1.8.0"), strings.Join(rs, ","), strings.Repeat("b", 64), valid, src)
}

func listedLines() []byte {
	return []byte(fmt.Sprintf(`{"schema":%q,"projects":{"prometheus":{"lines":["1.8","1.9","1.10"],"releases":{"1.8":["1.8.0"],"1.9":["1.9.0","1.9.1"],"1.10":["1.10.0"]}}}}`, LinesSchema))
}

func computeListed(t *testing.T, rules []string, att string, members map[string]string, crd map[string]string) Report {
	t.Helper()
	var atts []string
	if att != "" {
		atts = []string{att}
	}
	r, err := Compute(Input{Pack: pack(rules, atts), Lines: listedLines(), Now: baselineNow, ChangelogTargetComponents: members, CRDTargetComponents: crd})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The positive end to end: a listed attestation whose releases are exactly the
// snapshot's marks the pair L, and L is never A, B or decided.
func TestListedPairIsLNeverDecided(t *testing.T) {
	r := computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1"), map[string]string{"prometheus": listedComp}, nil)
	p := r.Projects[0]
	if len(p.Pairs) != 2 || !p.Pairs[0].Changelog || p.Pairs[1].Changelog {
		t.Fatalf("pairs %+v", p.Pairs)
	}
	if p.Pairs[0].Status != StatusG || len(p.Pairs[0].Families) != 0 {
		t.Fatalf("an L pair is not a plain G: %+v", p.Pairs[0])
	}
	if p.A != 0 || p.B != 0 || p.S != 0 || p.G != 2 || p.DecidedChangelog != 1 {
		t.Fatalf("row %+v", p)
	}
	if r.Fleet.A != 0 || r.Fleet.B != 0 || r.Fleet.DecidedChangelog != 1 {
		t.Fatalf("totals %+v", r.Fleet)
	}
	if r.changelog.decided != 1 || r.changelog.bounded != 0 || r.changelog.gap != 1 || r.changelog.targets != 1 {
		t.Fatalf("changelog row %+v", r.changelog)
	}
	b, err := json.Marshal(p.Pairs[0])
	if err != nil || !strings.Contains(string(b), `"changelog":true`) || !strings.Contains(string(b), `"status":"G"`) {
		t.Fatalf("%s %v", b, err)
	}
	s := changelogSentence(r.changelog)
	if !strings.Contains(s, "never a pass") || strings.Contains(s, "1 decided") {
		t.Fatalf("sentence %q", s)
	}
}

// A partial to-line gives no L: the attestation names fewer releases than the
// snapshot's line holds.
func TestListedPartialToLineGivesNoL(t *testing.T) {
	r := computeListed(t, nil, listedAttJSON(listedComp, "1.9.0"), map[string]string{"prometheus": listedComp}, nil)
	p := r.Projects[0]
	if p.Pairs[0].Changelog || p.DecidedChangelog != 0 || r.changelog.reasons[GapStaleReleases] != 1 {
		t.Fatalf("pairs %+v stats %+v", p.Pairs, r.changelog)
	}
	// More releases than the snapshot's line is as refused.
	r = computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1", "1.9.2"), map[string]string{"prometheus": listedComp}, nil)
	if r.Projects[0].Pairs[0].Changelog {
		t.Fatal("an attestation of releases the snapshot lacks counted")
	}
}

// A component with no reviewed row is refused: its attestation counts nothing.
func TestListedComponentOutsideTheRowsGivesNoL(t *testing.T) {
	att := listedAttJSON(listedComp, "1.9.0", "1.9.1")
	for name, members := range map[string]map[string]string{
		"no rows":       nil,
		"another row":   {"prometheus": "pkg:github/example/other"},
		"another slugs": {"other": "pkg:github/example/other"},
	} {
		r := computeListed(t, nil, att, members, nil)
		if r.Projects[0].Pairs[0].Changelog || r.Projects[0].DecidedChangelog != 0 || r.changelog.decided != 0 {
			t.Errorf("%s: an attestation of a component without a row counted", name)
		}
	}
}

// A component that is also a custom-resource member is refused.
func TestListedMixedMemberGivesNoL(t *testing.T) {
	r := computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1"),
		map[string]string{"prometheus": listedComp}, map[string]string{"prometheus": listedComp})
	if r.Projects[0].Pairs[0].Changelog || r.changelog.decided != 0 || r.changelog.reasons[GapMixedMember] != 2 {
		t.Fatalf("stats %+v pairs %+v", r.changelog, r.Projects[0].Pairs)
	}
}

// A pair a valid line-wide rule bounds stays B with its own families: the
// listed family is never a family of an A or B pair, and L never replaces it.
func TestListedNeverMakesAOrBAndNeverOverridesB(t *testing.T) {
	const crossing = `"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`
	rules := []string{relnotesSetRule("p.r", "1.8.2", "1.9.0", crossing)}
	r := computeListed(t, rules, listedAttJSON(listedComp, "1.9.0", "1.9.1"), map[string]string{"prometheus": listedComp}, nil)
	p := r.Projects[0].Pairs[0]
	if p.Status != StatusB || p.Changelog {
		t.Fatalf("bounded pair: %+v", p)
	}
	for _, f := range p.Families {
		if f == FamilyChangelogListed {
			t.Fatalf("the listed family is a family of a B pair: %v", p.Families)
		}
	}
	// Without a rule the same attestation is only L.
	r = computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1"), map[string]string{"prometheus": listedComp}, nil)
	if p := r.Projects[0].Pairs[0]; p.Status != StatusG || !p.Changelog {
		t.Fatalf("listed pair: %+v", p)
	}
}

// classify of a pair only the listed family covers: plain G with the L mark,
// no family, no blocking.
func TestListedOnlyClassifyIsPlainL(t *testing.T) {
	const comp = "pkg:github/example/project"
	atts := []lineattest.LineAttestation{
		clAtt(comp, FamilyChangelogListed, "2027-01-01T00:00:00Z", []string{"1.8.0"}, []string{"1.9.0"}),
	}
	rels := map[string][]string{"1.8": {"1.8.0"}, "1.9": {"1.9.0"}}
	p := classify("p", "1.8", "1.9", nil, atts, map[string]*ruleRec{}, rels)
	if p.Status != StatusG || !p.Changelog || len(p.Families) != 0 || p.canBlock {
		t.Fatalf("%+v", p)
	}
}

// Order A, B, S, L: an exact-pair rule keeps S; the listed record only adds
// the mark, and the pair is counted as S, not as listed.
func TestListedKeepsAnExactPairS(t *testing.T) {
	rules := []string{relnotesSetRule("p.r", "1.8.0", "1.9.0", "")}
	members := map[string]string{"prometheus": listedComp}
	without := computeListed(t, rules, "", members, nil)
	with := computeListed(t, rules, listedAttJSON(listedComp, "1.9.0", "1.9.1"), members, nil)
	if without.Projects[0].Pairs[0].Status != StatusS {
		t.Fatalf("setup: %+v", without.Projects[0].Pairs[0])
	}
	p := with.Projects[0]
	if p.Pairs[0].Status != StatusS || !p.Pairs[0].Changelog {
		t.Fatalf("pair %+v", p.Pairs[0])
	}
	if p.S != 1 || p.DecidedChangelog != 0 || with.Fleet.S != without.Fleet.S || with.Fleet.G != without.Fleet.G || with.Fleet.DecidedChangelog != 0 {
		t.Fatalf("row %+v fleet %+v vs %+v", p, with.Fleet, without.Fleet)
	}
	if with.changelog.spot != 1 || with.changelog.decided != 0 {
		t.Fatalf("changelog row %+v", with.changelog)
	}
}

func TestChangelogCounterSpotBeforeListed(t *testing.T) {
	var c changelogStats
	c.addPair(Pair{Status: StatusS, Changelog: true}, "")
	if c.spot != 1 || c.decided != 0 {
		t.Fatalf("%+v", c)
	}
}

// A list is not coverage: a project with only a listed record is not covered.
func TestListedOnlyProjectIsNotCovered(t *testing.T) {
	members := map[string]string{"prometheus": listedComp}
	without := computeListed(t, nil, "", members, nil)
	with := computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1"), members, nil)
	if with.Projects[0].Covered || with.Fleet.C1 != without.Fleet.C1 || with.PackProjects != without.PackProjects {
		t.Fatalf("covered %v C1 %d vs %d", with.Projects[0].Covered, with.Fleet.C1, without.Fleet.C1)
	}
	if !with.Projects[0].Pairs[0].Changelog {
		t.Fatal("setup: no L pair")
	}
}
