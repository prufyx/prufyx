// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// asChartRule gives a synthetic rule a chart subject: its versions are then
// chart versions, not release versions of the component.
func asChartRule(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	out := strings.Replace(string(raw), `"subject":{`, `"subject":{"chart":{"source":"https://charts.example.com","name":"example"},`, 1)
	if out == string(raw) {
		t.Fatal("fixture did not change")
	}
	return json.RawMessage(out)
}

// The scope of a chart rule keeps its chart identity, and it stays a rule of
// its family, component and line.
func TestScopeKeepsChartSubject(t *testing.T) {
	app := setRule("strimzi.kafka.0-50-0-to-0-51-0", strimzi, strimziFact, "0.50.0", "0.51.0", true)
	s, err := ScopeOf(asChartRule(t, app))
	if err != nil {
		t.Fatal(err)
	}
	want := constraintengine.ChartRef{Source: "https://charts.example.com", Name: "example"}
	if s.Transition.Chart == nil || *s.Transition.Chart != want {
		t.Fatalf("chart identity %+v", s.Transition.Chart)
	}
	if s.Line != "0.51" || !slices.Equal(s.Families, []string{FamilyCustomResourceVersions}) {
		t.Fatalf("scope %+v", s)
	}
	if s, err := ScopeOf(app); err != nil || s.Transition.Chart != nil {
		t.Fatalf("application rule %+v %v", s, err)
	}
	// A chart member that is not an object is refused, never read as absent.
	bad := strings.Replace(string(app), `"subject":{`, `"subject":{"chart":"example",`, 1)
	if _, err := ScopeOf(json.RawMessage(bad)); err == nil {
		t.Fatal("malformed chart accepted")
	}
}

// A chart rule is never line-wide: an attestation that lists it is refused,
// and one that leaves it out is refused too, so the line cannot be attested.
func TestChartRuleIsNeverLineWide(t *testing.T) {
	const id = "strimzi.kafka.0-50-0-to-0-51-0"
	app := setRule(id, strimzi, strimziFact, "0.50.0", "0.51.0", true)
	chart := asChartRule(t, app)
	if got := problemKinds(t, []LineAttestation{crdAttestation(id)}, app); len(got) != 0 {
		t.Fatalf("application control: %v", got)
	}
	if got := problemKinds(t, []LineAttestation{crdAttestation(id)}, chart); !slices.Equal(got, []string{ProblemRuleNotLineWide + ":" + id}) {
		t.Fatalf("listed chart rule: %v", got)
	}
	if got := problemKinds(t, []LineAttestation{crdAttestation()}, chart); !slices.Equal(got, []string{ProblemMissingRule + ":" + id}) {
		t.Fatalf("unlisted chart rule: %v", got)
	}
}

// The crossing shape of the changelog family is refused for a chart rule too.
func TestChartCrossingRuleIsNeverLineWide(t *testing.T) {
	withChangelogMember(t)
	f, _ := LookupFamily(FamilyChangelogAttestedEntries)
	app := crossingRule("c.1", clComp, "0.50.0", "0.51.0", "0.51.0", "")
	for name, c := range map[string]struct {
		raw  json.RawMessage
		want bool
	}{"application": {app, true}, "chart": {asChartRule(t, app), false}} {
		s, err := ScopeOf(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.CoversLine(clComp, s.Transition, "0.51"); got != c.want {
			t.Fatalf("%s: covers %v, want %v", name, got, c.want)
		}
	}
}
