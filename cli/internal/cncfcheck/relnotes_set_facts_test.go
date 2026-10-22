// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// These tests hold the set facts of the relnotes line-attestation work to the
// pack parser. relnotesSetFacts is the canonical list of the facts that
// packagedDefinitions registers (a registryDigest member change with an owner
// approval, see maintainer/knowledgegate registry_member.go). The packs below
// are test-only; the embedded pack holds no rule over these facts.

type relnotesSetFact struct {
	project   string // fact id segment and catalog slug
	component string
	kind      string // cli_flags_set, config_keys_set, runtime_keys_set
	member    string // a synthetic member in the canonical spelling
	desc      string
}

const (
	descFlags   = "Command-line flags the deployment passes: long names without leading dashes (--web.enable-lifecycle is web.enable-lifecycle); values are not part of the set."
	descConfig  = "Configuration keys the deployment sets: dotted key paths from the document root (server.tls.enabled); values are not part of the set."
	descRuntime = "Envoy runtime keys the deployment sets: the full runtime key (envoy.reloadable_features.example); values are not part of the set."
)

func relnotesSetFacts() []relnotesSetFact {
	projects := []struct{ project, component string }{
		{"prometheus", "pkg:github/prometheus/prometheus"},
		{"envoy", "pkg:github/envoyproxy/envoy"},
		{"containerd", "pkg:github/containerd/containerd"},
		{"coredns", "pkg:github/coredns/coredns"},
		{"falco", "pkg:github/falcosecurity/falco"},
		{"fluentd", "pkg:github/fluent/fluentd"},
		{"thanos", "pkg:github/thanos-io/thanos"},
		{"vitess", "pkg:github/vitessio/vitess"},
	}
	var out []relnotesSetFact
	for _, p := range projects {
		out = append(out,
			relnotesSetFact{p.project, p.component, "cli_flags_set", "synthetic-removed-flag", descFlags},
			relnotesSetFact{p.project, p.component, "config_keys_set", "synthetic.removed.key", descConfig})
		if p.project == "envoy" {
			out = append(out, relnotesSetFact{p.project, p.component, "runtime_keys_set", "envoy.reloadable_features.synthetic_removed", descRuntime})
		}
	}
	return out
}

func (f relnotesSetFact) id() string { return "component." + f.project + "." + f.kind }

// relnotesDefinitions are the definitions the compiled registry does not
// hold yet, so the tests stay valid once the registry change has landed.
func relnotesDefinitions() []constraintengine.FactDefinition {
	held := map[string]bool{}
	for _, d := range compiledDefinitions() {
		held[d.ID] = true
	}
	var out []constraintengine.FactDefinition
	for _, f := range relnotesSetFacts() {
		if held[f.id()] {
			continue
		}
		out = append(out, constraintengine.FactDefinition{ID: f.id(), Component: f.component, Type: constraintengine.FactSet})
	}
	return out
}

// relnotesCrossingEntry is a crossing-only forbid_set_member rule (no range):
// the anchor subject runs from the newest final release of the previous line
// to C = X.Y.0, the crossing change is C (REMOVED_IN_RELEASE) and the horizon
// is the next X.(Y+1).0 (REVIEWED_THROUGH_MINOR_LINE).
func relnotesCrossingEntry(f relnotesSetFact) Entry {
	const rev = "0000000000000000000000000000000000000002"
	repo := strings.TrimPrefix(f.component, "pkg:github/")
	rule := fmt.Sprintf(`{"id":"%[1]s.synthetic-%[2]s-removed.1-8-2-to-1-9-0","operator":"forbid_set_member","subject":{"component":%[3]q,"from":"1.8.2","to":"1.9.0"},`+
		`"setCondition":{"side":"proposed","component":%[3]q,"factId":%[4]q,"members":[%[5]q]},`+
		`"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"release-notes"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"release-notes"}},`+
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"release-notes","url":"https://github.com/%[6]s/blob/%[7]s/CHANGELOG.md","revision":%[7]q,"contentDigest":"sha256:%[8]s","startLine":1,"endLine":2}]},`+
		`"reasonCode":"RELNOTES_DECLARED_REMOVAL","nextAction":"remove %[5]s from the %[9]s before upgrading"}`,
		f.project, strings.ReplaceAll(f.kind, "_", "-"), f.component, f.id(), f.member, repo, rev, strings.Repeat("0", 64), f.kind)
	return Entry{
		Project:       f.project,
		Description:   "Synthetic test-only removed " + f.kind + " member.",
		RequiredFacts: []Fact{{Side: "proposed", ID: f.id(), Component: f.component, Type: constraintengine.FactSet, Description: f.desc}},
		Rule:          json.RawMessage(rule),
	}
}

func TestRelnotesSetFactsCrossingOnlyRuleAtV1alpha11(t *testing.T) {
	t.Parallel()
	facts := relnotesSetFacts()
	if len(facts) != 17 {
		t.Fatalf("%d relnotes set facts, want 17 (8 projects x flags and config keys, plus envoy runtime keys)", len(facts))
	}
	extra := relnotesDefinitions()
	var entries []Entry
	for _, f := range facts {
		entries = append(entries, relnotesCrossingEntry(f))
	}
	// Every fact is accepted, alone and together, at the crossing level.
	for _, e := range entries {
		if _, err := assembleSynthetic(syntheticPack(t, packSchemaCrossing, extra, e), extra); err != nil {
			t.Fatalf("%s refused at the crossing level: %v", ruleID(t, e), err)
		}
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaCrossing, extra, entries...), extra); err != nil {
		t.Fatalf("all relnotes crossing rules refused at the crossing level: %v", err)
	}
	// Any lower level is refused (the rule needs v1alpha11).
	for _, schema := range []string{packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaServedAPIs} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, extra, entries[0]), extra); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("crossing relnotes rule under %s accepted: %v", schema, err)
		}
	}
}

// TestRelnotesSetFactsRegistered holds the compiled registry to the canonical
// list: every fact is registered as a set of its component.
func TestRelnotesSetFactsRegistered(t *testing.T) {
	t.Parallel()
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]constraintengine.FactDefinition{}
	for _, d := range registry.Definitions() {
		have[d.ID] = d
	}
	for _, f := range relnotesSetFacts() {
		d, ok := have[f.id()]
		if !ok || d.Type != constraintengine.FactSet || d.Component != f.component {
			t.Errorf("%s is not registered as a set fact of %s", f.id(), f.component)
		}
	}
}
