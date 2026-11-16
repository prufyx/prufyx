// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const (
	clComp  = "pkg:github/example/changelog-project"
	clOther = "pkg:github/example/other-project"
)

// withChangelogMember installs a family table whose changelog table holds
// clComp, for one test.
func withChangelogMember(t *testing.T) {
	t.Helper()
	crd := customResourceMembers(customresources.Projects())
	cl, err := changelogMembers(crd, []string{clComp})
	if err != nil {
		t.Fatal(err)
	}
	saved := families
	families = buildFamilies(crd, cl)
	t.Cleanup(func() { families = saved })
}

func clAttestation(ids ...string) LineAttestation {
	a := mechanical("0.51", ids...)
	a.Component, a.FactFamily = clComp, FamilyChangelogAttestedEntries
	a.Releases = &Releases{
		From: []Release{{Version: "0.50.0", Commit: commit(1)}, {Version: "0.50.1", Commit: commit(2)}},
		To:   []Release{{Version: "0.51.0", Commit: commit(3)}},
	}
	return a
}

const upstreamHorizon = `"horizon":{"lt":"0.60.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}`

// crossingRule is a release-note shaped rule: a forbid_set_member crossing
// with change version c, reading a fact of the component itself.
func crossingRule(id, component, from, to, change, extra string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":%q,"to":%q},"crossing":{"change":{"version":%q,"basis":"CHANGED_IN_RELEASE","sourceId":"s"},%s%s},"setCondition":{"side":"proposed","component":%q,"factId":"component.example.flags_set","members":["x"]}}`,
		id, component, from, to, change, upstreamHorizon, extra, component))
}

func problemKinds(t *testing.T, atts []LineAttestation, rules ...json.RawMessage) []string {
	t.Helper()
	ps, err := CheckRuleSets(atts, rules)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range ps {
		out = append(out, p.Kind+":"+p.RuleID)
	}
	return out
}

func TestChangelogFamilyRegistration(t *testing.T) {
	f, ok := LookupFamily(FamilyChangelogAttestedEntries)
	if !ok || !f.ReleaseScoped() || !f.fromPreviousLine || !f.subjectWide || !f.crossingLineWide {
		t.Fatalf("family %+v", f)
	}
	if !strings.HasPrefix(f.Scope(), "according to the upstream changelog entries of tags X..Y") {
		t.Fatalf("scope %q", f.Scope())
	}
	if len(f.Components()) != 0 {
		t.Fatalf("the member table must be empty, got %v", f.Components())
	}
	if !slices.Contains(FamilyIDs(), FamilyChangelogAttestedEntries) {
		t.Fatal("family not listed")
	}
	// Only the changelog family opts in.
	for _, id := range []string{FamilyKubernetesRemovedServedGVK, FamilyCustomResourceVersions} {
		o, _ := LookupFamily(id)
		if o.subjectWide || o.crossingLineWide {
			t.Fatalf("%s opted in", id)
		}
	}
}

// With the member table empty nothing is in the family: every rule keeps its
// scope, and an attestation of the family has no rule to list.
func TestChangelogFamilyEmptyTableChangesNothing(t *testing.T) {
	r := crossingRule("c.1", clComp, "0.50.0", "0.51.0", "0.51.0", "")
	s, err := ScopeOf(r)
	if err != nil || len(s.Families) != 0 || s.Line != "" {
		t.Fatalf("%+v %v", s, err)
	}
	if got := problemKinds(t, []LineAttestation{clAttestation()}, r); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestChangelogFamilySubjectWideMembership(t *testing.T) {
	withChangelogMember(t)
	// Any rule of the member subject belongs, whatever fact it reads (even none).
	for _, raw := range []json.RawMessage{
		crossingRule("c.1", clComp, "0.50.0", "0.51.0", "0.51.0", ""),
		json.RawMessage(`{"id":"nofact","subject":{"component":"` + clComp + `","from":"0.50.0","to":"0.51.0"}}`),
	} {
		s, err := ScopeOf(raw)
		if err != nil || !slices.Equal(s.Families, []string{FamilyChangelogAttestedEntries}) || s.Line != "0.51" {
			t.Fatalf("%+v %v", s, err)
		}
	}
	// A rule of another component never belongs, even reading the member's fact.
	other := json.RawMessage(`{"id":"o","subject":{"component":"` + clOther + `","from":"0.50.0","to":"0.51.0"},"condition":{"component":"` + clComp + `","factId":"component.example.flags_set"}}`)
	if s, _ := ScopeOf(other); len(s.Families) != 0 {
		t.Fatalf("%+v", s)
	}
	// A member rule whose subject.to is not a release is an error, not silence.
	bad := json.RawMessage(`{"id":"b","subject":{"component":"` + clComp + `","from":"0.50.0","to":"latest"}}`)
	if _, err := ScopeOf(bad); err == nil {
		t.Fatal("non-release subject.to accepted")
	}
}

func TestChangelogFamilyCheckRuleSets(t *testing.T) {
	withChangelogMember(t)
	line := crossingRule("c.line", clComp, "0.50.0", "0.51.0", "0.51.0", "")
	late := crossingRule("c.late", clComp, "0.50.0", "0.51.1", "0.51.1", "")
	short := crossingRule("c.short", clComp, "0.50.0", "0.51.0", "0.50.5", "")
	ranged := json.RawMessage(fmt.Sprintf(`{"id":"r.line","operator":"forbid_set_member","subject":{"component":%q,"from":"0.50.0","to":"0.51.0"},"range":{"from":{"gte":"0.50.0","lt":"0.51.0"},"to":{"gte":"0.51.0","lt":"0.52.0"}}}`, clComp))
	anchor := json.RawMessage(fmt.Sprintf(`{"id":"a.only","subject":{"component":%q,"from":"0.50.0","to":"0.51.0"}}`, clComp))
	otherComp := crossingRule("o.1", clOther, "0.50.0", "0.51.0", "0.51.0", "")

	cases := []struct {
		name  string
		ids   []string
		rules []json.RawMessage
		want  []string
	}{
		{"crossing at x.y.0 is line-wide", []string{"c.line"}, []json.RawMessage{line}, nil},
		{"range rule is line-wide", []string{"r.line"}, []json.RawMessage{ranged}, nil},
		{"both", []string{"c.line", "r.line"}, []json.RawMessage{line, ranged}, nil},
		{"empty list, no rule", nil, nil, nil},
		{"missing", nil, []json.RawMessage{line}, []string{"missing-rule:c.line"}},
		{"extra", []string{"ghost"}, nil, []string{"extra-rule:ghost"}},
		{"other component is not listed and not required", nil, []json.RawMessage{otherComp}, nil},
		{"other component listed is extra", []string{"o.1"}, []json.RawMessage{otherComp}, []string{"extra-rule:o.1"}},
		{"crossing at x.y.1 not line-wide", []string{"c.late"}, []json.RawMessage{late}, []string{"rule-not-line-wide:c.late"}},
		{"crossing at x.y.1 unlisted is missing", nil, []json.RawMessage{late}, []string{"missing-rule:c.late"}},
		{"from region short (change inside previous line)", []string{"c.short"}, []json.RawMessage{short}, []string{"rule-not-line-wide:c.short"}},
		{"anchor-only rule not line-wide", []string{"a.only"}, []json.RawMessage{anchor}, []string{"rule-not-line-wide:a.only"}},
	}
	for _, c := range cases {
		a := clAttestation(c.ids...)
		got := problemKinds(t, []LineAttestation{a}, c.rules...)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestChangelogFamilyCrossingNegatives(t *testing.T) {
	withChangelogMember(t)
	f, _ := LookupFamily(FamilyChangelogAttestedEntries)
	covers := func(raw json.RawMessage) bool {
		s, err := ScopeOf(raw)
		if err != nil {
			t.Fatal(err)
		}
		return f.CoversLine(clComp, s.Transition, "0.51")
	}
	if !covers(crossingRule("ok", clComp, "0.50.0", "0.51.0", "0.51.0", "")) {
		t.Fatal("exact line crossing refused")
	}
	// Horizon or restoration inside the line cap the to region short.
	short := json.RawMessage(fmt.Sprintf(`{"id":"h","subject":{"component":%q,"from":"0.50.0","to":"0.51.0"},"crossing":{"change":{"version":"0.51.0","basis":"CHANGED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"0.51.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}}`, clComp))
	if covers(short) {
		t.Fatal("empty or short to region accepted")
	}
	restored := crossingRule("r", clComp, "0.50.0", "0.51.0", "0.51.0", `,"restored":{"version":"0.51.5","basis":"CHANGED_IN_RELEASE","sourceId":"s"}`)
	if covers(restored) {
		t.Fatal("crossing restored inside the line accepted")
	}
	// A distribution scope that excludes upstream is not line-wide.
	gke := crossingRule("g", clComp, "0.50.0", "0.51.0", "0.51.0", `,"distributions":["gke"]`)
	if covers(gke) {
		t.Fatal("non-upstream crossing accepted")
	}
	// Change at the next line or a later line: the line is not reached.
	if covers(crossingRule("n", clComp, "0.50.0", "0.51.0", "0.52.0", "")) {
		t.Fatal("crossing after the line accepted")
	}
	// A rule that carries both a range and a crossing is refused.
	both := json.RawMessage(fmt.Sprintf(`{"id":"b","subject":{"component":%q,"from":"0.50.0","to":"0.51.0"},"range":{"from":{"gte":"0.50.0","lt":"0.51.0"},"to":{"gte":"0.51.0","lt":"0.52.0"}},"crossing":{"change":{"version":"0.51.0","basis":"CHANGED_IN_RELEASE","sourceId":"s"},%s}}`, clComp, upstreamHorizon))
	if covers(both) {
		t.Fatal("range plus crossing accepted")
	}
	// The first line of a major has no previous line.
	s, _ := ScopeOf(crossingRule("z", clComp, "0.50.0", "0.51.0", "0.51.0", ""))
	if f.CoversLine(clComp, s.Transition, "1.0") {
		t.Fatal("line without a previous minor accepted")
	}
}

// Crossing is never line-wide for the other families.
func TestCrossingNotLineWideForOtherFamilies(t *testing.T) {
	r := crossingRule("c.1", strimzi, "0.50.0", "0.51.0", "0.51.0", "")
	s, _ := ScopeOf(r)
	for _, id := range []string{FamilyKubernetesRemovedServedGVK, FamilyCustomResourceVersions} {
		f, _ := LookupFamily(id)
		if f.CoversLine(strimzi, s.Transition, "0.51") || f.CoversLine(k8s, s.Transition, "0.51") {
			t.Fatalf("%s accepts a crossing", id)
		}
	}
}

func TestChangelogTableDisjointFromCRDTable(t *testing.T) {
	crd := customResourceMembers(customresources.Projects())
	if len(crd) == 0 {
		t.Fatal("no crd members")
	}
	for c := range crd {
		if _, err := changelogMembers(crd, []string{c}); err == nil {
			t.Fatalf("%s accepted in both tables", c)
		}
		if _, err := changelogMembers(crd, []string{clComp, c}); err == nil {
			t.Fatalf("%s accepted in both tables with another", c)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("init did not refuse %s", c)
				}
			}()
			mustFamilies(customresources.Projects(), []string{c})
		}()
		break
	}
	if _, err := changelogMembers(crd, []string{clComp, clComp}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := changelogMembers(crd, []string{"not a component"}); err == nil {
		t.Fatal("invalid component accepted")
	}
	if got, err := changelogMembers(crd, nil); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	// The shipped tables are disjoint.
	for _, c := range changelogComponents {
		if _, ok := crd[c]; ok {
			t.Fatalf("%s in both", c)
		}
	}
}

// A member has no fact pattern: Covers is false for every fact, so the family
// never claims a rule through a fact.
func TestChangelogFamilyCoversNoFact(t *testing.T) {
	withChangelogMember(t)
	f, _ := LookupFamily(FamilyChangelogAttestedEntries)
	if !f.Admits(clComp) || f.Covers(clComp, "component.example.flags_set") {
		t.Fatal("member fact pattern")
	}
}

// The custom-resource and Kubernetes families behave exactly as before: this
// golden is the output of the code before the changelog family existed.
func TestCRDFamilyGolden(t *testing.T) {
	rules := []json.RawMessage{
		setRule("crd.range", strimzi, strimziFact, "0.50.0", "0.51.0", true),
		setRule("crd.anchor", strimzi, strimziFact, "0.50.0", "0.51.0", false),
		setRule("crd.nofact", strimzi, "component.strimzi.other", "0.50.0", "0.51.0", true),
		crossingRule("crd.cross", strimzi, "0.50.0", "0.51.0", "0.51.0", ""),
		json.RawMessage(`{"id":"nocond","subject":{"component":"` + strimzi + `","from":"0.50.0","to":"0.51.0"}}`),
	}
	byKey, byID, err := RulesByScope(rules)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, k := range []Key{{strimzi, "0.51", FamilyCustomResourceVersions}, {strimzi, "0.51", FamilyChangelogAttestedEntries}} {
		lines = append(lines, fmt.Sprintf("%s=%v", k, byKey[k]))
	}
	for _, id := range []string{"crd.range", "crd.anchor", "crd.nofact", "crd.cross", "nocond"} {
		s := byID[id]
		lines = append(lines, fmt.Sprintf("%s fam=%v line=%q", id, s.Families, s.Line))
	}
	got := strings.Join(lines, "\n")
	want := strings.Join([]string{
		"pkg:github/strimzi/strimzi-kafka-operator 0.51 crd.custom_resource_versions=[crd.anchor crd.range]",
		"pkg:github/strimzi/strimzi-kafka-operator 0.51 changelog.attested_entries=[]",
		`crd.range fam=[crd.custom_resource_versions] line="0.51"`,
		`crd.anchor fam=[crd.custom_resource_versions] line="0.51"`,
		`crd.nofact fam=[] line=""`,
		`crd.cross fam=[] line=""`,
		`nocond fam=[] line=""`,
	}, "\n")
	if got != want {
		t.Fatalf("golden drift:\n%s\nwant:\n%s", got, want)
	}
	// The line-wide verdicts are unchanged: range yes, anchor no.
	f, _ := LookupFamily(FamilyCustomResourceVersions)
	if !f.CoversLine(strimzi, byID["crd.range"].Transition, "0.51") || f.CoversLine(strimzi, byID["crd.anchor"].Transition, "0.51") || f.CoversLine(strimzi, byID["crd.cross"].Transition, "0.51") {
		t.Fatal("CoversLine drift")
	}
	atts := []LineAttestation{crdAttestation("crd.anchor", "crd.range")}
	ps, err := CheckRuleSets(atts, rules)
	if err != nil || len(ps) != 1 || ps[0].Kind != ProblemRuleNotLineWide || ps[0].RuleID != "crd.anchor" {
		t.Fatalf("%+v %v", ps, err)
	}
}
