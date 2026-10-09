// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
)

// The community catalog in the gate (code before data): rules of a community
// project are admitted by the same proofs as a CNCF project's, the first one
// moves the pack to its own schema level, and a community line attestation is
// refused until the reviewed path exists. The derivations here run the real
// extractor over the frozen Strimzi fixture, moved onto a community target:
// the rules they produce are never published.

const (
	communityPackSchema = "prufyx.io/cncf-source-rule-pack/v1alpha12"
	gatewayExtractor    = "crd.version-removal.gateway-api"
)

// communityCatalog is the extractor catalog of the gate with one extra
// extractor: the community project gateway-api reading the Strimzi fixture.
func communityCatalog(t *testing.T) (map[string]extractcli.Spec, crdversions.Target) {
	t.Helper()
	tg, ok := crdversions.TargetFor("strimzi")
	if !ok {
		t.Fatal("no strimzi target")
	}
	var gw customresources.Project
	for _, p := range customresources.CommunityProjects() {
		if p.Slug == "gateway-api" {
			gw = p
		}
	}
	if gw.Slug == "" {
		t.Fatal("no gateway-api community project")
	}
	tg.Project, tg.Catalog, tg.Name, tg.Component, tg.FactProject, tg.Attest = gw.Slug, crdversions.CatalogCommunity, gw.Upstream.Name, gw.Component, gw.FactProject, false
	catalog := extractcli.Catalog()
	catalog[gatewayExtractor] = extractcli.Spec{ID: gatewayExtractor, Repo: tg.Repo, New: func(c int) extract.Extractor { return crdversions.NewConcurrent(tg, c) }}
	return catalog, tg
}

func communityEntries(t *testing.T, at time.Time) ([]map[string]any, map[string]extractcli.Spec) {
	t.Helper()
	catalog, tg := communityCatalog(t)
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	src := extract.FixtureReader{Root: strimziFixture}
	out, err := extract.Run(context.Background(), crdversions.New(tg), src, src, extract.Options{Repo: repo, DerivedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := extract.Canonical(out.Entries)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		t.Fatalf("%d entries: %v", len(entries), err)
	}
	for _, e := range entries {
		if e["project"] != "gateway-api" || ruleOf(e)["subject"].(map[string]any)["component"] != "pkg:github/kubernetes-sigs/gateway-api" {
			t.Fatalf("entry %v is not the community project's", ruleID(e))
		}
	}
	return entries, catalog
}

// communityHead is a head whose pack gains the community entries under
// schema.
func communityHead(t *testing.T, entries []map[string]any, schema string) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	p.entries = append(p.entries, entries...)
	p.sortByID()
	p.fields["schema"] = json.RawMessage(`"` + schema + `"`)
	p.write(t, head, cncfRulesPath)
	return base, head
}

func TestGateAdmitsCommunityRulesAtTheCommunitySchema(t *testing.T) {
	entries, catalog := communityEntries(t, gateNow.Add(-time.Hour))
	base, head := communityHead(t, entries, communityPackSchema)
	regenerate(t, head)
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}, Catalog: catalog})
	if !r.Passed() {
		t.Fatalf("failed:\n%s", strings.Join(failedChecks(r), "\n"))
	}
	for _, e := range entries {
		if c := change(t, r, ruleID(e)); !c.OK || c.Proof != ProofRederived {
			t.Fatalf("%s: %+v", c.RuleID, c)
		}
	}
	schemaChanges := 0
	for _, c := range r.Changes {
		if c.Member != "" {
			schemaChanges++
			if c.Member != "schema" || !c.OK || c.Proof != ProofSchemaLevel {
				t.Fatalf("pack-member change %+v", c)
			}
		}
	}
	if schemaChanges != 1 {
		t.Fatalf("%d pack-member changes", schemaChanges)
	}
	// The gate's own size check built the per-project targets, the community
	// project's among them.
	spec := DefaultLayout().Packs[0]
	stats, err := spec.Admit(head)
	if err != nil || stats.SplitErr != nil {
		t.Fatalf("admit: %v / %v", err, stats.SplitErr)
	}
	found := false
	for _, target := range stats.Targets {
		found = found || target.Path == "knowledge/community/projects/gateway-api.v1.json"
	}
	if !found {
		t.Fatalf("targets %v", stats.Targets)
	}
}

func TestGateRefusesCommunityRulesBelowTheCommunitySchema(t *testing.T) {
	entries, catalog := communityEntries(t, gateNow.Add(-time.Hour))
	// The set-rule level is the lowest the entries would need for their
	// shape, but a community entry needs its own level: the head's schema is
	// then not the lowest level its content requires, and the pack itself
	// does not load.
	base, head := communityHead(t, entries, crdSetPackSchema)
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}, Catalog: catalog})
	if c, ok := check(r, "admit/cncf"); !ok || c.OK || r.Passed() {
		t.Fatalf("admit/cncf %+v passed=%v", c, r.Passed())
	}
	// A level above what the content needs is never admitted either.
	base, head = communityHead(t, entries, "prufyx.io/cncf-source-rule-pack/v1alpha13")
	r = runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}, Catalog: catalog})
	if r.Passed() {
		t.Fatal("an unknown schema level passed")
	}
}

// A rule of a community project that no extractor derives is not admitted
// without a proof: there is none for it, so the gate fails it like any
// hand-written loosening.
func TestGateDoesNotAdmitAHandWrittenCommunityRule(t *testing.T) {
	entries, catalog := communityEntries(t, gateNow.Add(-time.Hour))
	reviewed := entries[:1]
	evidence := evidenceOf(reviewed[0])
	delete(evidence, "basis")
	delete(evidence, "extractor")
	delete(evidence, "derivedAt")
	base, head := communityHead(t, reviewed, communityPackSchema)
	regenerate(t, head)
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}, Catalog: catalog})
	if r.Passed() {
		t.Fatal("a hand-written community rule passed the gate")
	}
	if c := change(t, r, ruleID(reviewed[0])); c.OK {
		t.Fatalf("hand-written rule admitted: %+v", c)
	}
}

// Community data cannot attest: a line attestation naming a community
// component fails the pack's admission, so the gate refuses it before any
// proof is looked at.
func TestGateRefusesACommunityLineAttestation(t *testing.T) {
	entries, catalog := communityEntries(t, gateNow.Add(-time.Hour))
	base, head := communityHead(t, entries, communityPackSchema)
	p := readPack(t, head, cncfRulesPath)
	attestation := map[string]any{
		"component": "pkg:github/kubernetes-sigs/gateway-api", "line": "1.2", "factFamily": "crd.custom_resource_versions", "completeness": "COMPLETE_REVIEWED_RULES_FOR_LINE", "ruleIds": []string{},
		"releases": map[string]any{
			"from": []map[string]string{{"version": "1.1.0", "commit": strings.Repeat("1", 40)}},
			"to":   []map[string]string{{"version": "1.2.0", "commit": strings.Repeat("3", 40)}},
		},
		"evidence": map[string]any{"basis": "reviewed", "reviewedAt": gateNow.Add(-time.Hour).UTC().Format(time.RFC3339), "validUntil": gateNow.Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339), "sources": []map[string]any{{"id": "crds", "url": "https://github.com/kubernetes-sigs/gateway-api/blob/" + strings.Repeat("3", 40) + "/crd.yaml", "revision": strings.Repeat("3", 40), "contentDigest": "sha256:" + strings.Repeat("0", 64), "startLine": 1, "endLine": 2}}},
	}
	raw, err := json.Marshal([]any{attestation})
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.write(t, head, cncfRulesPath)
	opts := Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}, Catalog: catalog, Citations: passingCitations{}, Layout: DefaultLayout(), Now: gateNow}
	pinBaseKeys(&opts)
	fromBot(&opts)
	// The gate cannot even read the pack's records: it stops with an error
	// that names the family, rather than classifying the attestation.
	r, err := Verify(context.Background(), opts)
	if err == nil && r != nil && r.Passed() {
		t.Fatal("a community line attestation passed the gate")
	}
	if err != nil && !strings.Contains(err.Error(), "is not the component of family crd.custom_resource_versions") {
		t.Fatalf("refused for another reason: %v", err)
	}
}
