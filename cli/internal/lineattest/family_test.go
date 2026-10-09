// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const (
	strimzi     = "pkg:github/strimzi/strimzi-kafka-operator"
	strimziFact = "component.strimzi.custom_resource_versions_set"
	argoFact    = "component.argo_cd.custom_resource_versions_set"
)

func commit(n int) string { return fmt.Sprintf("%040x", n) }

// crdAttestation is a mechanical attestation of Strimzi line 0.51 that read
// 0.50.0, 0.50.1 and 0.51.0.
func crdAttestation(ids ...string) LineAttestation {
	a := mechanical("0.51", ids...)
	a.Component, a.FactFamily = strimzi, FamilyCustomResourceVersions
	a.Releases = &Releases{
		From: []Release{{Version: "0.50.0", Commit: commit(1)}, {Version: "0.50.1", Commit: commit(2)}},
		To:   []Release{{Version: "0.51.0", Commit: commit(3)}},
	}
	return a
}

func setRule(id, component, fact, from, to string, ranged bool) json.RawMessage {
	rng := ""
	if ranged {
		line, _ := LineOf(to)
		major, minor := lineNumbers(line)
		rng = fmt.Sprintf(`,"range":{"from":{"gte":"%d.%d.0","lt":"%d.%d.0"},"to":{"gte":"%d.%d.0","lt":"%d.%d.0"}}`, major, minor-1, major, minor, major, minor, major, minor+1)
	}
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":%q,"to":%q}%s,"setCondition":{"side":"proposed","component":%q,"factId":%q,"members":["kafka.strimzi.io/v1beta1/Kafka"]}}`,
		id, component, from, to, rng, component, fact))
}

// The custom-resource family's members are exactly the projects of the
// reviewed custom-resource table, each with exactly its own set fact.
func TestCustomResourceFamilyMembersAreTheReviewedTable(t *testing.T) {
	f, ok := LookupFamily(FamilyCustomResourceVersions)
	if !ok || !f.ReleaseScoped() || !f.fromPreviousLine || f.Scope() == "" {
		t.Fatalf("family %+v", f)
	}
	var want []string
	community := 0
	for _, p := range customresources.Projects() {
		if p.Community() {
			// A community project is registered but never attested.
			community++
			if f.Admits(p.Component) || f.Covers(p.Component, p.FactID()) {
				t.Fatalf("community project %s is a family member", p.Slug)
			}
			continue
		}
		want = append(want, p.Component)
		if !f.Covers(p.Component, p.FactID()) {
			t.Fatalf("%s does not cover its own fact", p.Slug)
		}
		for _, q := range customresources.Projects() {
			if q.Slug != p.Slug && f.Covers(p.Component, q.FactID()) {
				t.Fatalf("%s covers the fact of %s", p.Slug, q.Slug)
			}
		}
		if f.Covers(p.Component, p.FactID()+"x") || f.Covers(p.Component, "x"+p.FactID()) {
			t.Fatalf("%s: fact pattern is not exact", p.Slug)
		}
	}
	slices.Sort(want)
	if !slices.Equal(f.Components(), want) || len(want) == 0 {
		t.Fatalf("components %v, want %v", f.Components(), want)
	}
	for _, c := range []string{k8s, "pkg:github/prometheus/prometheus", ""} {
		if f.Admits(c) {
			t.Fatalf("%q admitted", c)
		}
	}
	// The Kubernetes family is unchanged: one component, not release-scoped.
	k, _ := LookupFamily(FamilyKubernetesRemovedServedGVK)
	if !slices.Equal(k.Components(), []string{k8s}) || k.ReleaseScoped() || k.Covers(strimzi, strimziFact) {
		t.Fatalf("kubernetes family %+v", k)
	}
	if community == 0 {
		t.Fatal("the table has no community project")
	}
	// A table that names a component twice admits nothing for it.
	dup := customResourceMembers([]customresources.Project{{Slug: "a", FactProject: "a", Component: strimzi}, {Slug: "b", FactProject: "b", Component: strimzi}})
	if len(dup) != 0 {
		t.Fatalf("duplicate component admitted: %v", dup)
	}
}

func TestCustomResourceAttestationValidation(t *testing.T) {
	if err := crdAttestation("a.rule").Validate(); err != nil {
		t.Fatal(err)
	}
	doc := encode(t, []LineAttestation{crdAttestation()})
	got, err := Parse(doc)
	if err != nil || len(got) != 1 || got[0].Releases == nil || len(got[0].Releases.From) != 2 {
		t.Fatalf("parse %+v %v", got, err)
	}
	if !strings.Contains(string(doc), `"releases":{"from":[{"version":"0.50.0","commit":"`) {
		t.Fatalf("encoding %s", doc)
	}
	for name, mutate := range map[string]func(a *LineAttestation){
		"no releases":            func(a *LineAttestation) { a.Releases = nil },
		"component not in table": func(a *LineAttestation) { a.Component = "pkg:github/prometheus/prometheus" },
		"kubernetes component":   func(a *LineAttestation) { a.Component = k8s },
		"no earlier release":     func(a *LineAttestation) { a.Releases.From = nil },
		"no later release":       func(a *LineAttestation) { a.Releases.To = []Release{} },
		"earlier release of another line": func(a *LineAttestation) {
			a.Releases.From[0].Version = "0.49.0"
		},
		"later release of another line": func(a *LineAttestation) { a.Releases.To[0].Version = "0.52.0" },
		"not ascending": func(a *LineAttestation) {
			a.Releases.From[0], a.Releases.From[1] = a.Releases.From[1], a.Releases.From[0]
		},
		"repeated release":      func(a *LineAttestation) { a.Releases.From[1] = a.Releases.From[0] },
		"short commit":          func(a *LineAttestation) { a.Releases.To[0].Commit = "abc" },
		"upper-case commit":     func(a *LineAttestation) { a.Releases.To[0].Commit = strings.Repeat("AB", 20) },
		"not a release version": func(a *LineAttestation) { a.Releases.To[0].Version = "0.51.0-rc.1" },
		"line without a previous minor": func(a *LineAttestation) {
			a.Line = "1.0"
			a.Releases.To = []Release{{Version: "1.0.0", Commit: commit(3)}}
		},
		"too many releases": func(a *LineAttestation) {
			a.Releases.To = nil
			for i := 0; i <= MaxReleases; i++ {
				a.Releases.To = append(a.Releases.To, Release{Version: fmt.Sprintf("0.51.%d", i), Commit: commit(i + 10)})
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := crdAttestation()
			mutate(&a)
			if err := a.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// A family that is not release-scoped refuses releases.
	k := reviewed("1.28")
	k.Releases = &Releases{From: []Release{{Version: "1.27.0", Commit: commit(1)}}, To: []Release{{Version: "1.28.0", Commit: commit(2)}}}
	if err := k.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("kubernetes attestation with releases: %v", err)
	}
	// The exact shape check covers the new member.
	valid := string(doc)
	for name, bad := range map[string]string{
		"null releases":         strings.Replace(valid, `"releases":{`, `"releases":null,"x":{`, 1),
		"unknown release field": strings.Replace(valid, `{"version":"0.50.0",`, `{"tag":"v0.50.0","version":"0.50.0",`, 1),
		"repeated member":       strings.Replace(valid, `{"version":"0.50.0",`, `{"version":"0.50.0","version":"0.50.0",`, 1),
		"case-folded member":    strings.Replace(valid, `"releases"`, `"Releases"`, 1),
		"number version":        strings.Replace(valid, `"version":"0.51.0"`, `"version":51`, 1),
		"missing commit":        strings.Replace(valid, `,"commit":"`+commit(3)+`"`, ``, 1),
		"releases is an array":  strings.Replace(strings.Replace(valid, `"releases":{"from":`, `"releases":[`, 1), `}]},"evidence"`, `}]],"evidence"`, 1),
	} {
		if bad == valid {
			t.Fatalf("%s: fixture did not change", name)
		}
		if _, err := Parse([]byte(bad)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: accepted: %v", name, err)
		}
	}
}

// A rule of a table project belongs to the family through its own set
// fact, and it must cover the whole line to be listed.
func TestCustomResourceRulesAndExactSet(t *testing.T) {
	ranged := setRule("strimzi.kafka.0-50-0-to-0-51-0", strimzi, strimziFact, "0.50.0", "0.51.0", true)
	anchor := setRule("strimzi.topic.0-50-0-to-0-51-0", strimzi, strimziFact, "0.50.0", "0.51.0", false)
	foreign := setRule("strimzi.reads-argo.0-50-0-to-0-51-0", strimzi, argoFact, "0.50.0", "0.51.0", true)
	s, err := ScopeOf(ranged)
	if err != nil || s.Line != "0.51" || !slices.Equal(s.Families, []string{FamilyCustomResourceVersions}) {
		t.Fatalf("scope %+v %v", s, err)
	}
	if s, err := ScopeOf(foreign); err != nil || len(s.Families) != 0 {
		t.Fatalf("a rule over another project's set is in the family: %+v %v", s, err)
	}
	problems, err := CheckRuleSets([]LineAttestation{crdAttestation("strimzi.kafka.0-50-0-to-0-51-0")}, []json.RawMessage{ranged, foreign})
	if err != nil || len(problems) != 0 {
		t.Fatalf("exact line-wide set: %+v %v", problems, err)
	}
	problems, _ = CheckRuleSets([]LineAttestation{crdAttestation()}, []json.RawMessage{ranged})
	if len(problems) != 1 || problems[0].Kind != ProblemMissingRule {
		t.Fatalf("missing rule: %+v", problems)
	}
	problems, _ = CheckRuleSets([]LineAttestation{crdAttestation("strimzi.topic.0-50-0-to-0-51-0")}, []json.RawMessage{anchor})
	if len(problems) != 1 || problems[0].Kind != ProblemRuleNotLineWide {
		t.Fatalf("anchor-only rule: %+v", problems)
	}
}

func TestCoversReleases(t *testing.T) {
	a := crdAttestation()
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"0.50.0", "0.51.0", true},
		{"0.50.1", "0.51.0", true},
		{"0.50.2", "0.51.0", false}, // released after the derivation
		{"0.50.1", "0.51.1", false},
		{"0.51.0", "0.51.0", false},
	} {
		if got := a.CoversReleases(c.from, c.to); got != c.want {
			t.Fatalf("%s -> %s: %v", c.from, c.to, got)
		}
	}
	if !reviewed("1.28").CoversReleases("1.27.9", "1.28.99") {
		t.Fatal("a family that is not release-scoped covers every release")
	}
	b := crdAttestation()
	b.Releases = nil
	if b.CoversReleases("0.50.0", "0.51.0") {
		t.Fatal("a release-scoped attestation without releases covers a hop")
	}
	// The index hands out copies.
	ix := NewIndex([]LineAttestation{a})
	got := ix.AttestationsFor(strimzi, "0.51", FamilyCustomResourceVersions, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if len(got) != 1 || !got[0].Current() {
		t.Fatalf("lookup %+v", got)
	}
	got[0].Attestation.Releases.To[0].Version = "9.9.9"
	again := ix.AttestationsFor(strimzi, "0.51", FamilyCustomResourceVersions, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if again[0].Attestation.Releases.To[0].Version != "0.51.0" {
		t.Fatal("the index exposes its releases")
	}
}

// Any change of the releases is loosening and never a renewal.
func TestClassifyReleases(t *testing.T) {
	base := crdAttestation()
	more := crdAttestation()
	more.Releases.To = append(more.Releases.To, Release{Version: "0.51.1", Commit: commit(4)})
	fewer := crdAttestation()
	fewer.Releases.From = fewer.Releases.From[:1]
	renewedMore := more
	renewedMore.Evidence.ReviewedAt, renewedMore.Evidence.DerivedAt, renewedMore.Evidence.ValidUntil = "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2027-01-30T00:00:00Z"
	for name, after := range map[string]LineAttestation{"more": more, "fewer": fewer, "renewed with a new release": renewedMore} {
		got, err := Classify([]LineAttestation{base}, []LineAttestation{after})
		if err != nil || len(got) != 1 || got[0].Class != Loosening || got[0].Renewal || !slices.Contains(got[0].Fields, "releases") {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	if _, err := Marshal([]LineAttestation{crdAttestation(), mechanical("1.28")}); err != nil {
		t.Fatalf("a document with both families: %v", err)
	}
}
