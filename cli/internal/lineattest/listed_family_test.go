// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const listedComp = "pkg:github/example/listed-project"

func listedAttestation() LineAttestation {
	a := mechanical("0.51")
	a.Component, a.FactFamily = listedComp, FamilyChangelogListedEntries
	a.Releases = &Releases{
		From: []Release{{Version: "0.50.0", Commit: commit(1)}, {Version: "0.50.1", Commit: commit(2)}},
		To:   []Release{{Version: "0.51.0", Commit: commit(3)}, {Version: "0.51.1", Commit: commit(4)}},
	}
	return a
}

func TestListedFamilyRegistration(t *testing.T) {
	f, ok := LookupFamily(FamilyChangelogListedEntries)
	if !ok || !f.ReleaseScoped() || !f.fromPreviousLine || !f.listOnly || f.subjectWide || f.crossingLineWide {
		t.Fatalf("family %+v", f)
	}
	if !slices.Contains(FamilyIDs(), FamilyChangelogListedEntries) {
		t.Fatal("family not listed")
	}
	if !strings.Contains(f.Scope(), "never a pass") || !strings.Contains(f.Scope(), "did not judge") {
		t.Fatalf("scope %q", f.Scope())
	}
	if FamilyChangelogListedEntries == FamilyChangelogAttestedEntries {
		t.Fatal("the listed family is the attested family")
	}
	// The attested family is untouched: still no member.
	if a, _ := LookupFamily(FamilyChangelogAttestedEntries); len(a.Components()) != 0 {
		t.Fatalf("attested members %v", a.Components())
	}
}

func TestListedFamilyAdmission(t *testing.T) {
	f, _ := LookupFamily(FamilyChangelogListedEntries)
	for _, c := range []string{listedComp, "pkg:github/prometheus/prometheus"} {
		if !f.Admits(c) {
			t.Fatalf("%s refused", c)
		}
	}
	for _, c := range []string{
		"", "prometheus", "pkg:generic/foo", "pkg:github/Upper/Case", "pkg:github/owner", "pkg:github/a/b/c",
		"pkg:github//repo", "pkg:gitlab/a/b", "pkg:github/a/b?x=1", "pkg:github/a/b@1.0",
	} {
		if f.Admits(c) {
			t.Fatalf("%q admitted", c)
		}
	}
	// A calendar or published-line component has no hop of the family's shape.
	for c := range calverComponents {
		if f.Admits(c) {
			t.Fatalf("calendar component %s admitted", c)
		}
	}
	for c := range publishedLineComponents {
		if f.Admits(c) {
			t.Fatalf("published-line component %s admitted", c)
		}
	}
	// A component of the custom-resource family is never a member.
	for _, p := range customresources.Projects() {
		if f.Admits(p.Component) {
			t.Fatalf("%s is in both families", p.Component)
		}
	}
	if len(f.Components()) != 0 {
		t.Fatal("a predicate family lists no members")
	}
}

func TestListedAttestationValidates(t *testing.T) {
	a := listedAttestation()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	// Round trip through the pack document check.
	if _, err := Parse(encode(t, []LineAttestation{a})); err != nil {
		t.Fatal(err)
	}
}

func TestListedAttestationRefusals(t *testing.T) {
	cases := map[string]func(*LineAttestation){
		"a rule id":              func(a *LineAttestation) { a.RuleIDs = []string{"some.rule"} },
		"no releases":            func(a *LineAttestation) { a.Releases = nil },
		"a non-GitHub component": func(a *LineAttestation) { a.Component = "pkg:generic/foo" },
		"a custom-resource member": func(a *LineAttestation) {
			ps := customresources.Projects()
			a.Component = ps[0].Component
		},
		"a bad completeness": func(a *LineAttestation) { a.Completeness = "partial" },
	}
	for name, mutate := range cases {
		a := listedAttestation()
		mutate(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

// No rule belongs to the listed family: the family claims nothing about any
// rule, so a rule of a member keeps its own scope and an attestation of the
// family has no rule to list.
func TestListedFamilyTakesNoRule(t *testing.T) {
	raw := json.RawMessage(`{"id":"r1","subject":{"component":"` + listedComp + `","from":"0.50.0","to":"0.51.0"},"condition":{"component":"` + listedComp + `","factId":"component.example.flags_set"}}`)
	s, err := ScopeOf(raw)
	if err != nil || slices.Contains(s.Families, FamilyChangelogListedEntries) {
		t.Fatalf("%+v %v", s, err)
	}
	if ps := problemKinds(t, []LineAttestation{listedAttestation()}, raw); len(ps) != 0 {
		t.Fatalf("%v", ps)
	}
	// Listing a rule is refused whatever the pack holds.
	a := listedAttestation()
	a.RuleIDs = []string{"r1"}
	if err := a.Validate(); err == nil {
		t.Fatal("rule listed")
	}
}

// A list is derived: a hand-asserted (reviewed) record of the family is invalid.
func TestListedAttestationMustBeMechanical(t *testing.T) {
	a := listedAttestation()
	a.Evidence = reviewed("0.51").Evidence
	if err := a.Validate(); err == nil {
		t.Fatal("a reviewed-basis listed record validated")
	}
}
