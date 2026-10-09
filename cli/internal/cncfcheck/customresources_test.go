// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const (
	crdStrimziFact      = "component.strimzi.custom_resource_versions_set"
	crdStrimziComponent = "pkg:github/strimzi/strimzi-kafka-operator"
	crdKafkaRuleID      = "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0"
)

// crdKafkaEntry is a test-only rule of the shape the CRD extractor derives:
// Kafka v1beta2 is not served by Strimzi 1.0.0. It is never published.
func crdKafkaEntry() Entry {
	rule := `{"id":"` + crdKafkaRuleID + `","operator":"forbid_set_member","subject":{"component":"` + crdStrimziComponent + `","from":"0.51.0","to":"1.0.0"},` +
		`"setCondition":{"side":"proposed","component":"` + crdStrimziComponent + `","factId":"` + crdStrimziFact + `","members":["kafka.strimzi.io/v1beta2/Kafka"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + syntheticRevision + `/install/cluster-operator/040-Crd-kafka.yaml","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 1.0.0"}`
	return Entry{Project: "strimzi", Description: "Synthetic test-only CRD version removal.", RequiredFacts: []Fact{{Side: "proposed", ID: crdStrimziFact, Component: crdStrimziComponent, Type: constraintengine.FactSet, Description: "Custom-resource versions of the Strimzi custom resources."}}, Rule: json.RawMessage(rule)}
}

// withoutCustomResourceFacts is the compiled registry without the
// custom-resource version sets.
func withoutCustomResourceFacts() []constraintengine.FactDefinition {
	var out []constraintengine.FactDefinition
	for _, d := range compiledDefinitions() {
		if !strings.HasSuffix(d.ID, ".custom_resource_versions_set") {
			out = append(out, d)
		}
	}
	return out
}

// crdPack is the embedded pack plus entries at the set-rule level, bound
// to the registry of definitions.
func crdPack(t *testing.T, definitions []constraintengine.FactDefinition, entries ...Entry) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Entries = append(pack.Entries, entries...)
	sort.SliceStable(pack.Entries, func(i, j int) bool { return ruleID(t, pack.Entries[i]) < ruleID(t, pack.Entries[j]) })
	registry, err := constraintengine.NewCompiledRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	pack.Schema, pack.RegistryDigest = packSchemaSet, registry.Digest()
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assembleWith(packRaw []byte, definitions []constraintengine.FactDefinition) (bundle, error) {
	landscape, _ := packagedFiles.ReadFile("data/landscape-projects.json")
	priority, _ := packagedFiles.ReadFile("data/priority-portfolio.json")
	return assemble(landscape, priority, packRaw, definitions)
}

// The custom-resource version set is registered exactly for the projects
// of the reviewed custom-resource table (which a crdversions test pins to
// the CRD extractor's targets), as a set fact of each project's catalog
// component, and for no other project.
func TestCustomResourceFactsRegisteredForExtractorTargets(t *testing.T) {
	want := map[string]string{}
	for _, p := range customresources.Projects() {
		want[p.FactID()] = p.Component
	}
	got := map[string]string{}
	for _, d := range compiledDefinitions() {
		if strings.HasSuffix(d.ID, ".custom_resource_versions_set") {
			if d.Type != constraintengine.FactSet || len(d.EnumTokens) != 0 {
				t.Fatalf("%s: type %s", d.ID, d.Type)
			}
			got[d.ID] = d.Component
		}
	}
	if len(got) != len(want) || len(want) != len(customresources.Projects()) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	for id, component := range want {
		if got[id] != component || !RegisteredFact(id) {
			t.Fatalf("%s: registered for %q, want %q", id, got[id], component)
		}
	}
	components, err := CatalogSubjectComponents()
	if err != nil {
		t.Fatal(err)
	}
	// A CNCF table project is a catalog subject component; a community
	// project is not one, so nothing about it can claim CNCF status.
	for _, p := range customresources.Projects() {
		found := false
		for _, c := range components {
			found = found || c == p.Component
		}
		if found == p.Community() {
			t.Fatalf("%s (%s): catalog subject component %v", p.Slug, p.Catalog, found)
		}
		if _, err := Component(p.Slug); p.Community() && err == nil {
			t.Fatalf("community project %s has a CNCF catalog slug", p.Slug)
		}
	}
}

// The registered fact of a community project admits no rule into the CNCF
// pack yet: a pack entry for a community project is refused, because the
// project is not in the CNCF catalog. Rules of community projects need the
// community knowledge step (its own reviewed change, code before data).
func TestCommunityCustomResourceRuleRefused(t *testing.T) {
	var p customresources.Project
	for _, q := range customresources.Projects() {
		if q.Community() {
			p = q
			break
		}
	}
	if p.Slug == "" {
		t.Fatal("no community project in the table")
	}
	if !RegisteredFact(p.FactID()) {
		t.Fatalf("%s: fact not registered", p.FactID())
	}
	entry := crdKafkaEntry()
	raw := strings.NewReplacer(crdStrimziComponent, p.Component, crdStrimziFact, p.FactID(), crdKafkaRuleID, p.Slug+".crd-version-removal.synthetic.0-51-0-to-1-0-0").Replace(string(entry.Rule))
	entry.Project, entry.Rule = p.Slug, json.RawMessage(raw)
	entry.RequiredFacts[0].ID, entry.RequiredFacts[0].Component = p.FactID(), p.Component
	if _, err := assembleWith(crdPack(t, compiledDefinitions(), entry), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("rule of community project %s admitted into the CNCF pack: %v", p.Slug, err)
	}
}

// Registration is what admits a set rule over the fact: the same pack is
// refused against the registry without the custom-resource sets and
// admitted with them.
func TestCustomResourceRuleAdmissionNeedsTheRegisteredFact(t *testing.T) {
	entry := crdKafkaEntry()
	if _, err := assembleWith(crdPack(t, withoutCustomResourceFacts(), entry), withoutCustomResourceFacts()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("rule over an unregistered custom-resource fact admitted: %v", err)
	}
	if _, err := assembleWith(crdPack(t, compiledDefinitions(), entry), compiledDefinitions()); err != nil {
		t.Fatalf("rule over the registered fact refused: %v", err)
	}
	// The embedded pack itself carries no such rule.
	if b, err := load(); err != nil {
		t.Fatal(err)
	} else {
		for _, e := range b.pack.Entries {
			for _, f := range e.RequiredFacts {
				if strings.HasSuffix(f.ID, ".custom_resource_versions_set") {
					t.Fatalf("embedded pack reads %s", f.ID)
				}
			}
		}
	}
}

// The adapter's input decides the rule: BLOCKED on the removed version with
// or without a complete scope, PASS only when the set is complete and holds
// no removed version, UNKNOWN for every partial set.
func TestCustomResourceRuleOverPreparedInput(t *testing.T) {
	b, err := assembleWith(crdPack(t, compiledDefinitions(), crdKafkaEntry()), compiledDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	kafka := func(version string) string {
		return "apiVersion: kafka.strimzi.io/" + version + "\nkind: Kafka\nmetadata:\n  name: main\n  namespace: kafka\n"
	}
	other := "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  name: tls\n"
	for name, tc := range map[string]struct {
		docs     []string
		complete bool
		status   string
		reason   string
	}{
		"removed version, complete":     {[]string{kafka("v1beta2")}, true, "BLOCKED", "CRD_VERSION_NOT_SERVED"},
		"removed version, partial":      {[]string{kafka("v1beta2")}, false, "BLOCKED", "CRD_VERSION_NOT_SERVED"},
		"removed version, unattributed": {[]string{kafka("v1beta2"), other}, true, "BLOCKED", "CRD_VERSION_NOT_SERVED"},
		"served version, complete":      {[]string{kafka("v1")}, true, "PASS", "CRD_VERSION_NOT_SERVED"},
		"served version, partial":       {[]string{kafka("v1")}, false, "UNKNOWN", "RULE_SET_FACT_INCOMPLETE"},
		"served version, unattributed":  {[]string{kafka("v1"), other}, true, "UNKNOWN", "RULE_SET_FACT_INCOMPLETE"},
		"templated input":               {[]string{kafka("v1"), "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ x }}\n"}, true, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
	} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(strings.Join(tc.docs, "---\n"))
			prepared, err := cncfprepare.PrepareCustomResourceVersionsBytes(raw, "strimzi", "0.51.0", "1.0.0", tc.complete)
			if err != nil {
				t.Fatal(err)
			}
			report, err := b.checkFacts("strimzi", []string{crdStrimziFact}, prepared.CanonicalInputJSON, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Check.Claims) != 1 {
				t.Fatalf("%d claims", len(report.Check.Claims))
			}
			claim := report.Check.Claims[0]
			if claim.RuleID != crdKafkaRuleID || claim.Status != tc.status || claim.ReasonCode != tc.reason {
				t.Fatalf("claim %s %s %s", claim.RuleID, claim.Status, claim.ReasonCode)
			}
			if tc.status == "BLOCKED" && (len(claim.MatchedMembers) != 1 || claim.MatchedMembers[0] != "kafka.strimzi.io/v1beta2/Kafka") {
				t.Fatalf("matched %v", claim.MatchedMembers)
			}
		})
	}
}
