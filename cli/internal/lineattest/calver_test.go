// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	calverComponent = "pkg:github/clastix/kamaji"
	otherComponent  = "pkg:github/kubernetes/kubernetes"
)

func TestPreviousLine(t *testing.T) {
	for _, c := range []struct {
		name, component, line, want string
		ok                          bool
	}{
		{"calver mid year", calverComponent, "26.2", "26.1", true},
		{"calver december", calverComponent, "26.12", "26.11", true},
		{"calver year rollover", calverComponent, "26.1", "25.12", true},
		{"calver rollover 25.1", calverComponent, "25.1", "24.12", true},
		{"calver month 13", calverComponent, "26.13", "", false},
		{"calver month 0", calverComponent, "26.0", "", false},
		{"calver year 0 has no earlier year", calverComponent, "0.1", "", false},
		{"calver not a line", calverComponent, "26", "", false},
		{"ordinary minor", otherComponent, "1.28", "1.27", true},
		{"ordinary 26.1 is 26.0", otherComponent, "26.1", "26.0", true},
		{"ordinary 1.0 has none", otherComponent, "1.0", "", false},
		{"ordinary month 13 is a plain minor", otherComponent, "26.13", "26.12", true},
		{"empty component is ordinary", "", "26.1", "26.0", true},
		{"ordinary not a line", otherComponent, "1.x", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := PreviousLine(c.component, c.line)
			if got != c.want || ok != c.ok {
				t.Fatalf("PreviousLine(%q, %q) = %q, %v; want %q, %v", c.component, c.line, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestValidCalverLine(t *testing.T) {
	for line, want := range map[string]bool{"26.1": true, "26.12": true, "24.7": true, "26.0": false, "26.13": false, "1.2.3": false, "": false} {
		if got := ValidCalverLine(line); got != want {
			t.Errorf("ValidCalverLine(%q) = %v, want %v", line, got, want)
		}
	}
}

// A calendar component has no line-wide rules: the hop shape arithmetic of a
// rule range is about minor lines of one major.
func TestCalverComponentHasNoLineTransitions(t *testing.T) {
	family, _ := LookupFamily(FamilyCustomResourceVersions)
	if _, _, ok := family.LineTransitions("pkg:github/argoproj/argo-cd", "26.3"); !ok {
		t.Fatal("an ordinary component keeps its line transitions")
	}
	if _, _, ok := family.LineTransitions(calverComponent, "26.3"); ok {
		t.Fatal("a calendar component must have no line transitions")
	}
	tr := constraintengine.RuleTransition{Range: &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "26.2.0", Lt: "26.3.0"},
		To:   constraintengine.VersionBound{Gte: "26.3.0", Lt: "26.4.0"},
	}}
	if !family.CoversLine("pkg:github/argoproj/argo-cd", tr, "26.3") {
		t.Fatal("control: the same rule covers the line of an ordinary component")
	}
	if family.CoversLine(calverComponent, tr, "26.3") {
		t.Fatal("a calendar component must not be covered by a line-wide rule")
	}
}

func calverReleases(from, to []string) *Releases {
	conv := func(vs []string) []Release {
		out := make([]Release, 0, len(vs))
		for _, v := range vs {
			out = append(out, Release{Version: v, Commit: strings.Repeat("a", 40)})
		}
		return out
	}
	return &Releases{From: conv(from), To: conv(to)}
}

func TestReleasesValidateCalendarLines(t *testing.T) {
	for _, c := range []struct {
		name, component, line string
		releases              *Releases
		wantErr               bool
	}{
		{"rollover 25.12 to 26.1", calverComponent, "26.1", calverReleases([]string{"25.12.1", "25.12.5"}, []string{"26.1.1"}), false},
		{"rollover 24.12 to 25.1", calverComponent, "25.1", calverReleases([]string{"24.12.1"}, []string{"25.1.2"}), false},
		{"mid year", calverComponent, "26.3", calverReleases([]string{"26.2.1"}, []string{"26.3.1"}), false},
		{"december is not the previous line of january in the same year", calverComponent, "26.1", calverReleases([]string{"26.0.1"}, []string{"26.1.1"}), true},
		{"calendar: M.(m-1) of the same year is not the rollover line", calverComponent, "26.1", calverReleases([]string{"26.12.1"}, []string{"26.1.1"}), true},
		{"ordinary line 26.1 reads 26.0", otherComponent, "26.1", calverReleases([]string{"26.0.1"}, []string{"26.1.1"}), false},
		{"ordinary line 26.1 does not read 25.12", otherComponent, "26.1", calverReleases([]string{"25.12.1"}, []string{"26.1.1"}), true},
		{"ordinary 1.0 has no previous line", otherComponent, "1.0", calverReleases([]string{"1.0.1"}, []string{"1.0.2"}), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.releases.validate(c.component, c.line)
			if (err != nil) != c.wantErr || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("validate(%q, %q) = %v, wantErr %v", c.component, c.line, err, c.wantErr)
			}
		})
	}
}
