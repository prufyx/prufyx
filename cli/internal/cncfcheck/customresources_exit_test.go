// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// strimziDeclaredInput is a hand-written operator-declared input for Strimzi
// 0.51.0 -> 1.0.0: the four facts of the reviewed Kafka rule (Kafka v1beta2
// not used) and, when set is non-empty, a complete custom-resource version
// set holding only served versions.
func strimziDeclaredInput(set string) []byte {
	facts := `{"id":"component.strimzi.distribution","state":"declared","enumValue":"official_upstream"},` +
		`{"id":"component.strimzi.execution_surface","state":"declared","enumValue":"kafka_custom_resource"},` +
		`{"id":"component.strimzi.kafka_v1beta2_api_present","state":"declared","boolValue":false},` +
		`{"id":"component.strimzi.target_kafka_crd_admission_required","state":"declared","boolValue":true}`
	if set != "" {
		facts = `{"id":"` + crdStrimziFact + `","state":"declared","setValue":` + set + `},` + facts
	}
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
		`"current":{"components":[{"component":"` + crdStrimziComponent + `","version":"0.51.0","facts":[]}]},` +
		`"proposed":{"components":[{"component":"` + crdStrimziComponent + `","version":"1.0.0","facts":[` + facts + `]}]}}`)
}

const servedStrimziSet = `{"members":["kafka.strimzi.io/v1/Kafka","kafka.strimzi.io/v1/KafkaTopic"],"complete":true}`

// passingClaims fails unless every claim of the report passes, and returns
// how many of them read a custom-resource version set.
func passingClaims(t *testing.T, report Report, want int) int {
	t.Helper()
	if len(report.Check.Claims) != want {
		t.Fatalf("%d claims, want %d", len(report.Check.Claims), want)
	}
	reading := 0
	for _, claim := range report.Check.Claims {
		if claim.Status != "PASS" {
			t.Fatalf("claim %s %s %s", claim.RuleID, claim.Status, claim.ReasonCode)
		}
		if ReadsCustomResourceVersions(claim) {
			reading++
		}
	}
	return reading
}

// The generic caller-input route evaluates every rule of the project. When
// one of them reads a custom-resource version set, passing every rule never
// exits 0, on embedded and on external knowledge alike: nothing yet shows
// that the published rules name every version the target release stops
// serving.
func TestClaimExitNeverPassesCustomResourceRules(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	plain, err := load()
	if err != nil {
		t.Fatal(err)
	}
	// Baseline: the reviewed Kafka rule alone passes and exits 0.
	report, err := plain.check("strimzi", "", strimziDeclaredInput(""), now)
	if err != nil {
		t.Fatal(err)
	}
	if reading := passingClaims(t, report, 1); reading != 0 || ClaimExit(report) != 0 {
		t.Fatalf("Kafka rule alone: %d set claims, exit %d", reading, ClaimExit(report))
	}

	pack := crdPack(t, compiledDefinitions(), crdKafkaEntry())
	withSet, err := assembleWith(pack, compiledDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	report, err = withSet.check("strimzi", "", strimziDeclaredInput(servedStrimziSet), now)
	if err != nil {
		t.Fatal(err)
	}
	if reading := passingClaims(t, report, 2); reading != 1 {
		t.Fatalf("%d claims read the set", reading)
	}
	if got := ClaimExit(report); got != 11 {
		t.Fatalf("embedded: every claim passes and one reads the set: exit %d, want 11", got)
	}

	raw, err := ExportExternalBundleFromPack(pack, "9")
	if err != nil {
		t.Fatal(err)
	}
	external, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	report, err = external.Evaluate("strimzi", strimziDeclaredInput(servedStrimziSet), now)
	if err != nil {
		t.Fatal(err)
	}
	if reading := passingClaims(t, report, 2); reading != 1 {
		t.Fatalf("external: %d claims read the set", reading)
	}
	if got := ClaimExit(report); got != 11 {
		t.Fatalf("external: exit %d, want 11", got)
	}

	// A removed version still blocks.
	report, err = withSet.check("strimzi", "", strimziDeclaredInput(`{"members":["kafka.strimzi.io/v1beta2/Kafka"],"complete":true}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if got := ClaimExit(report); got != 10 {
		t.Fatalf("removed version: exit %d, want 10", got)
	}
}

func TestReadsCustomResourceVersions(t *testing.T) {
	claim := func(ids ...string) constraintengine.Claim {
		var c constraintengine.Claim
		for _, id := range ids {
			c.RequiredFacts = append(c.RequiredFacts, constraintengine.RequiredFact{Side: "proposed", Component: crdStrimziComponent, FactID: id})
		}
		return c
	}
	for id, want := range map[string]bool{
		crdStrimziFact: true,
		"component.argo_cd.custom_resource_versions_set":     true,
		"component.future.custom_resource_versions_set":      true,
		"component.strimzi.kafka_v1beta2_api_present":        false,
		"component.strimzi.custom_resource_versions_set_old": false,
		"component..custom_resource_versions_set":            false,
		"custom_resource_versions_set":                       false,
		"cluster.strimzi.custom_resource_versions_set":       false,
	} {
		if got := ReadsCustomResourceVersions(claim("component.strimzi.distribution", id)); got != want {
			t.Fatalf("%s: %t, want %t", id, got, want)
		}
	}
	if ReadsCustomResourceVersions(claim()) {
		t.Fatal("a claim without facts reads no set")
	}
	// Every registered set is recognised.
	for _, d := range compiledDefinitions() {
		if d.Type == constraintengine.FactSet && strings.HasSuffix(d.ID, ".custom_resource_versions_set") && !ReadsCustomResourceVersions(claim(d.ID)) {
			t.Fatalf("%s not recognised", d.ID)
		}
	}
}
