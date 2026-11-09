// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const publishedComponent = "pkg:github/example/published"

// The set is empty in production code: no component is of the published-line
// scheme until a reviewed change registers one.
func TestPublishedLineSetIsEmpty(t *testing.T) {
	if len(publishedLineComponents) != 0 {
		t.Fatalf("publishedLineComponents must be empty, got %v", publishedLineComponents)
	}
	if PublishedLineComponent(publishedComponent) || PublishedLineComponent("pkg:github/mariadb-operator/mariadb-operator") {
		t.Fatal("no component is registered")
	}
}

func TestReleasesValidatePublishedLines(t *testing.T) {
	defer SetPublishedLineComponentsForTest(publishedComponent)()
	for _, c := range []struct {
		name, component, line string
		releases              *Releases
		wantErr               bool
	}{
		{"calver hop across a skipped minor", publishedComponent, "26.3", calverReleases([]string{"25.10.1", "25.10.2"}, []string{"26.3.0"}), false},
		{"calver same year skipped months", publishedComponent, "25.10", calverReleases([]string{"25.8.4"}, []string{"25.10.0"}), false},
		{"from spanning two lines", publishedComponent, "26.3", calverReleases([]string{"25.10.1", "26.1.1"}, []string{"26.3.0"}), true},
		{"from of the line itself", publishedComponent, "26.3", calverReleases([]string{"26.3.0"}, []string{"26.3.1"}), true},
		{"from above the line", publishedComponent, "26.3", calverReleases([]string{"26.6.0"}, []string{"26.3.1"}), true},
		{"from in the semver era for a calver line", publishedComponent, "25.0", calverReleases([]string{"0.38.0"}, []string{"25.0.0"}), true},
		{"calver from for a semver line", publishedComponent, "0.38", calverReleases([]string{"25.0.0"}, []string{"0.38.0"}), true},
		{"semver strict m-1", publishedComponent, "0.35", calverReleases([]string{"0.34.0"}, []string{"0.35.0"}), false},
		{"semver 0.34 to 0.36 skips a minor", publishedComponent, "0.36", calverReleases([]string{"0.34.0"}, []string{"0.36.0"}), true},
		{"era boundary 19 is semver", publishedComponent, "19.5", calverReleases([]string{"19.3.0"}, []string{"19.5.0"}), true},
		{"era boundary 19 strict", publishedComponent, "19.5", calverReleases([]string{"19.4.0"}, []string{"19.5.0"}), false},
		{"era boundary 20 is calver", publishedComponent, "20.5", calverReleases([]string{"20.2.0"}, []string{"20.5.0"}), false},
		{"across the era boundary 19 to 20", publishedComponent, "20.0", calverReleases([]string{"19.9.0"}, []string{"20.0.0"}), true},
		{"empty from", publishedComponent, "26.3", calverReleases(nil, []string{"26.3.0"}), true},
		{"an unregistered component keeps M.(m-1)", otherComponent, "26.3", calverReleases([]string{"25.10.1"}, []string{"26.3.0"}), true},
		{"an unregistered component keeps M.(m-1), accepted", otherComponent, "26.3", calverReleases([]string{"26.2.1"}, []string{"26.3.0"}), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.releases.validate(c.component, c.line)
			if (err != nil) != c.wantErr || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("validate(%q, %q) = %v, wantErr %v", c.component, c.line, err, c.wantErr)
			}
		})
	}
}

// Without the registration, the same documents are refused as before.
func TestReleasesValidateUnregisteredRefusesSkippedLine(t *testing.T) {
	if err := calverReleases([]string{"25.10.1"}, []string{"26.3.0"}).validate(publishedComponent, "26.3"); err == nil {
		t.Fatal("a skipped-line hop of an unregistered component must be invalid")
	}
	if err := calverReleases([]string{"0.34.0"}, []string{"0.36.0"}).validate(publishedComponent, "0.36"); err == nil {
		t.Fatal("0.34 to 0.36 must be invalid")
	}
}

func TestAdjacentPublishedLine(t *testing.T) {
	for _, c := range []struct {
		name      string
		published []string
		to        string
		want      string
		ok        bool
	}{
		{"skipped months", []string{"25.0", "25.8", "25.10", "26.3", "26.6"}, "26.3", "25.10", true},
		{"max below, not the lowest", []string{"25.10", "26.1", "26.3"}, "26.3", "26.1", true},
		{"no line below", []string{"26.3"}, "26.3", "", false},
		{"era boundary 19 to 20", []string{"19.9", "20.0"}, "20.0", "", false},
		{"0.38 to 25.0 is cross era", []string{"0.37", "0.38", "25.0"}, "25.0", "", false},
		{"semver skip: 0.35 not published", []string{"0.34", "0.36"}, "0.36", "", false},
		{"semver strict", []string{"0.34", "0.35", "0.36"}, "0.36", "0.35", true},
		{"unreadable line in the list blocks", []string{"25.10", "x.y", "26.3"}, "26.3", "", false},
		{"invalid target", []string{"25.10"}, "26", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := AdjacentPublishedLine(c.published, c.to)
			if got != c.want || ok != c.ok {
				t.Fatalf("AdjacentPublishedLine(%v, %q) = %q, %v; want %q, %v", c.published, c.to, got, ok, c.want, c.ok)
			}
		})
	}
}

func publishedAtt(line string, from, to []string, ruleIDs ...string) LineAttestation {
	a := mechanical(line, ruleIDs...)
	a.Component = publishedComponent
	a.Releases = calverReleases(from, to)
	return a
}

func TestFromLineIsCarriedByTheAttestation(t *testing.T) {
	a := publishedAtt("26.3", []string{"25.10.1", "25.10.2"}, []string{"26.3.0"})
	if l, ok := a.FromLine(); !ok || l != "26.2" {
		t.Fatalf("an unregistered component derives its from-line from PreviousLine (26.2), not the releases: %q, %v", l, ok)
	}
	if a.HopFrom("25.10") {
		t.Fatal("unregistered component must not accept a from-line it does not own")
	}
	defer SetPublishedLineComponentsForTest(publishedComponent)()
	if l, ok := a.FromLine(); !ok || l != "25.10" || !a.HopFrom("25.10") {
		t.Fatalf("FromLine = %q, %v", l, ok)
	}
	for _, other := range []string{"26.1", "26.2", "25.8", "26.3", ""} {
		if a.HopFrom(other) {
			t.Fatalf("HopFrom(%q) = true", other)
		}
	}
	two := publishedAtt("26.3", []string{"25.10.1", "26.1.1"}, []string{"26.3.0"})
	if _, ok := two.FromLine(); ok {
		t.Fatal("a from list spanning two lines has no from-line")
	}
	none := a
	none.Releases = nil
	if _, ok := none.FromLine(); ok {
		t.Fatal("no releases, no from-line")
	}
	if l, ok := publishedAtt("0.35", []string{"0.34.0"}, []string{"0.35.0"}).FromLine(); !ok || l != "0.34" {
		t.Fatalf("semver strict hop: %q, %v", l, ok)
	}
	if _, ok := publishedAtt("0.36", []string{"0.34.0"}, []string{"0.36.0"}).FromLine(); ok {
		t.Fatal("0.34 -> 0.36 has no from-line")
	}
}

func TestLineHopPublished(t *testing.T) {
	defer SetPublishedLineComponentsForTest(publishedComponent)()
	for _, c := range []struct {
		component, from, to string
		want                bool
	}{
		{publishedComponent, "25.10", "26.3", true},
		{publishedComponent, "26.3", "25.10", false},
		{publishedComponent, "26.3", "26.3", false},
		{publishedComponent, "0.34", "0.36", false},
		{publishedComponent, "0.38", "25.0", false},
		{publishedComponent, "19.9", "20.0", false},
		{otherComponent, "25.10", "26.3", false},
		{otherComponent, "26.2", "26.3", true},
		{calverComponent, "25.12", "26.1", true},
	} {
		if got := LineHop(c.component, c.from, c.to); got != c.want {
			t.Errorf("LineHop(%q, %q, %q) = %v, want %v", c.component, c.from, c.to, got, c.want)
		}
	}
}

// A published-line component has no line-wide rules: a rule list is never
// covering, so a hand-crafted attestation listing a rule cannot be line-wide.
func TestPublishedComponentHasNoLineTransitions(t *testing.T) {
	family, _ := LookupFamily(FamilyCustomResourceVersions)
	tr := constraintengine.RuleTransition{Range: &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "26.2.0", Lt: "26.3.0"},
		To:   constraintengine.VersionBound{Gte: "26.3.0", Lt: "26.4.0"},
	}}
	if !family.Admits(publishedComponent) {
		// The family admits only the table's projects: Covers needs a
		// registered member, LineTransitions does not.
		t.Log("test component is not a family member; LineTransitions is checked directly")
	}
	if _, _, ok := family.LineTransitions(publishedComponent, "26.3"); !ok {
		t.Fatal("control: an unregistered component keeps its line transitions")
	}
	defer SetPublishedLineComponentsForTest(publishedComponent)()
	if _, _, ok := family.LineTransitions(publishedComponent, "26.3"); ok {
		t.Fatal("a published-line component must have no line transitions")
	}
	if family.CoversLine(publishedComponent, tr, "26.3") {
		t.Fatal("a published-line component must not be covered by a line-wide rule")
	}
}
