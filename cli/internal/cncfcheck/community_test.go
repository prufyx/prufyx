// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// These tests hold the community catalog (community.go) to its boundaries:
// the shipped knowledge is untouched, a community entry is admitted only at
// its own pack schema and only in the one shape the derivations produce, a
// community project is never a CNCF project (not in the landscape, not in
// the catalogue, not in the corpus attestation), and the targets and index
// that carry it say so. The rules here name a removal that does not exist
// and are never published.

const (
	communitySlug      = "gateway-api"
	communityComponent = "pkg:github/kubernetes-sigs/gateway-api"
	communityFact      = "component.gateway_api.custom_resource_versions_set"
	communityRuleID    = "gateway-api.crd-version-removal.gateways-gateway-networking-k8s-io.1-1-0-to-1-2-0"
	communityMember    = "gateway.networking.k8s.io/v1beta1/Gateway"
)

// communityEntry is a test-only rule of the shape the CRD extractor derives
// for a community project.
func communityEntry() Entry {
	rule := `{"id":"` + communityRuleID + `","operator":"forbid_set_member","subject":{"component":"` + communityComponent + `","from":"1.1.0","to":"1.2.0"},` +
		`"setCondition":{"side":"proposed","component":"` + communityComponent + `","factId":"` + communityFact + `","members":["` + communityMember + `"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"crd-1-2-0","url":"https://github.com/kubernetes-sigs/gateway-api/blob/` + syntheticRevision + `/config/crd/standard/gateway.networking.k8s.io_gateways.yaml","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Gateway to gateway.networking.k8s.io/v1 before upgrading to 1.2.0"}`
	return Entry{Project: communitySlug, Description: "Synthetic test-only CRD version removal of a community project.", RequiredFacts: []Fact{{Side: "proposed", ID: communityFact, Component: communityComponent, Type: constraintengine.FactSet, Description: "Custom-resource versions of the Gateway API custom resources."}}, Rule: json.RawMessage(rule)}
}

// communityPack is the embedded pack plus entries under schema.
func communityPack(t *testing.T, schema string, entries ...Entry) []byte {
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
	pack.Schema = schema
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func communityBundle(t *testing.T, entries ...Entry) bundle {
	t.Helper()
	if len(entries) == 0 {
		entries = []Entry{communityEntry()}
	}
	b, err := assembleWith(communityPack(t, packSchemaCommunity, entries...), compiledDefinitions())
	if err != nil {
		t.Fatalf("community pack refused: %v", err)
	}
	return b
}

func TestCommunityIdentitiesOfTheShippedTable(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	table := customresources.CommunityProjects()
	if len(table) == 0 || len(b.community) != len(table) {
		t.Fatalf("%d community identities for %d table projects", len(b.community), len(table))
	}
	landscape := map[string]bool{}
	subjects := map[string]bool{}
	for _, p := range b.landscape.Projects {
		landscape[p.Slug] = true
		subjects[subjectComponent(p.Slug, p.RepositoryURL)] = true
	}
	for _, p := range table {
		identity, ok := b.community[p.Slug]
		if !ok || identity.CNCFStage != "" || identity.Name != p.Upstream.Name || landscape[p.Slug] || subjects[p.Component] {
			t.Fatalf("%s: identity %+v (landscape slug %v, landscape subject %v)", p.Slug, identity, landscape[p.Slug], subjects[p.Component])
		}
		if component, ok := b.communityComponent(p.Slug); !ok || component != p.Component {
			t.Fatalf("%s: component %q", p.Slug, component)
		}
		if b.hasProject(p.Slug) || !b.isCommunity(p.Slug) || b.catalogOf(p.Slug) != CatalogCommunity {
			t.Fatalf("%s: catalog %q", p.Slug, b.catalogOf(p.Slug))
		}
	}
	// The landscape slugs are never community ones.
	for slug := range landscape {
		if b.isCommunity(slug) || isCommunitySlug(slug) || b.catalogOf(slug) != "" {
			t.Fatalf("landscape project %s is community", slug)
		}
	}
}

// With the shipped knowledge a community project is unknown to every route:
// no data, not checkable, not in a scan snapshot, not in the index.
func TestCommunityIsInertWithShippedKnowledge(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if b.pack.Schema != packSchemaRanged || anyCommunityEntry(b.pack) {
		t.Fatalf("shipped pack: schema %s, community entries %v", b.pack.Schema, anyCommunityEntry(b.pack))
	}
	k, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range customresources.CommunityProjects() {
		if b.communityHasData(p.Slug) || b.hasCheckableProject(p.Slug) || b.hasKnowledgeProject(p.Slug) != true {
			t.Fatalf("%s: data %v checkable %v", p.Slug, b.communityHasData(p.Slug), b.hasCheckableProject(p.Slug))
		}
		if _, ok := k.Component(p.Slug); ok || k.Catalog(p.Slug) != "" || len(k.Rules(p.Slug)) != 0 {
			t.Fatalf("%s is known to a scan of the shipped knowledge", p.Slug)
		}
		if has, err := CommunityProjectHasData(p.Slug); err != nil || has {
			t.Fatalf("%s: embedded data %v %v", p.Slug, has, err)
		}
		if _, err := Check(p.Slug, []byte(`{}`), time.Now()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: check %v", p.Slug, err)
		}
		if _, err := Catalog(false, p.Slug); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: catalogue %v", p.Slug, err)
		}
	}
	for _, slug := range k.Projects() {
		if isCommunitySlug(slug) {
			t.Fatalf("scan catalogue lists community project %s", slug)
		}
	}
	// The index and targets of the shipped pack carry no community project
	// and no catalog member, at the same schema as before.
	index, targets, err := BuildEmbeddedExternalTargets("1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index.Bytes, []byte(`"catalog"`)) || bytes.Contains(index.Bytes, []byte("/v3")) {
		t.Fatalf("index: %s", index.Bytes)
	}
	for _, target := range targets {
		if strings.HasPrefix(target.Path, ExternalCommunityTargetPrefix) {
			t.Fatalf("community target %s from the shipped pack", target.Path)
		}
	}
}

func TestCommunityTableOverlapRefusesThePack(t *testing.T) {
	landscape, _ := packagedFiles.ReadFile("data/landscape-projects.json")
	priority, _ := packagedFiles.ReadFile("data/priority-portfolio.json")
	pack, _ := packagedFiles.ReadFile("data/rules.json")
	community := func(mutate func(*customresources.Project)) []customresources.Project {
		for _, p := range customresources.CommunityProjects() {
			if p.Slug == communitySlug {
				mutate(&p)
				return []customresources.Project{p}
			}
		}
		t.Fatal("no gateway-api")
		return nil
	}
	if _, err := assembleWithCommunity(landscape, priority, pack, compiledDefinitions(), community(func(*customresources.Project) {})); err != nil {
		t.Fatalf("shipped community table refused: %v", err)
	}
	for name, mutate := range map[string]func(*customresources.Project){
		"slug of a landscape project":      func(p *customresources.Project) { p.Slug = "strimzi" },
		"component of a landscape project": func(p *customresources.Project) { p.Component = "pkg:github/strimzi/strimzi-kafka-operator" },
		"repository of a landscape project": func(p *customresources.Project) {
			p.Upstream.Repository = "https://github.com/strimzi/strimzi-kafka-operator"
		},
		"repository that is not GitHub": func(p *customresources.Project) {
			p.Upstream.Repository = "https://gitlab.com/kubernetes-sigs/gateway-api"
		},
		"repository with a user": func(p *customresources.Project) {
			p.Upstream.Repository = "https://x@github.com/kubernetes-sigs/gateway-api"
		},
		"component not named by repository": func(p *customresources.Project) { p.Component = "pkg:github/kubernetes-sigs/other" },
		"empty upstream name":               func(p *customresources.Project) { p.Upstream.Name = "" },
		"slug that is not a catalog slug":   func(p *customresources.Project) { p.Slug = "Gateway_API" },
		"project of the table marked CNCF":  func(p *customresources.Project) { p.Catalog = customresources.CatalogCNCF },
	} {
		table := community(mutate)
		_, err := assembleWithCommunity(landscape, priority, pack, compiledDefinitions(), table)
		if name == "project of the table marked CNCF" {
			// A CNCF table project is not a community identity at all: it
			// simply is not one, and nothing is admitted for it.
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
	// Two community projects with one slug or one component.
	one := community(func(*customresources.Project) {})[0]
	two := one
	if _, err := assembleWithCommunity(landscape, priority, pack, compiledDefinitions(), []customresources.Project{one, two}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("repeated community project accepted: %v", err)
	}
	two.Slug = "gateway-api-copy"
	if _, err := assembleWithCommunity(landscape, priority, pack, compiledDefinitions(), []customresources.Project{one, two}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("one component for two community projects accepted: %v", err)
	}
}

func TestCommunityEntryNeedsItsOwnPackSchema(t *testing.T) {
	entry := communityEntry()
	if _, err := assembleWith(communityPack(t, packSchemaCommunity, entry), compiledDefinitions()); err != nil {
		t.Fatalf("community pack under its schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs, packSchemaCrossing} {
		if _, err := assembleWith(communityPack(t, schema, entry), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("community entry under %s accepted: %v", schema, err)
		}
	}
	// The community schema is used only with a community entry.
	if _, err := assembleWith(communityPack(t, packSchemaCommunity), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("community schema without a community entry accepted: %v", err)
	}
	if schema, err := requiredPackSchema(rulePack{Entries: []Entry{entry}}); err != nil || schema != packSchemaCommunity {
		t.Fatalf("required schema %s %v", schema, err)
	}
	lower, ok := PackSchemaLevel(packSchemaCrossing)
	level, found := PackSchemaLevel(packSchemaCommunity)
	if !ok || !found || level <= lower {
		t.Fatalf("levels %d %d", lower, level)
	}
	// A binary that predates the level does not know the schema.
	if packSchemaCommunity != "prufyx.io/cncf-source-rule-pack/v1alpha12" {
		t.Fatalf("schema %s", packSchemaCommunity)
	}
}

func TestCommunityEntryShapeIsClosed(t *testing.T) {
	good := string(communityEntry().Rule)
	with := func(from, to string) Entry {
		entry := communityEntry()
		if !strings.Contains(good, from) {
			t.Fatalf("rule lacks %q", from)
		}
		entry.Rule = json.RawMessage(strings.Replace(good, from, to, 1))
		return entry
	}
	predicate := func() Entry {
		entry := communityEntry()
		entry.Rule = json.RawMessage(`{"id":"` + communityRuleID + `","operator":"forbid_predicate_value","subject":{"component":"` + communityComponent + `","from":"1.1.0","to":"1.2.0"},` +
			`"condition":{"side":"proposed","component":"` + communityComponent + `","factId":"` + communityFact + `","comparison":"eq","value":true},` +
			`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"crd-1-2-0","url":"https://github.com/kubernetes-sigs/gateway-api/blob/` + syntheticRevision + `/a.yaml","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},"reasonCode":"X","nextAction":"y"}`)
		return entry
	}
	otherFact := communityEntry()
	otherFact.RequiredFacts[0].ID = "component.strimzi.custom_resource_versions_set"
	otherFact.RequiredFacts[0].Component = crdStrimziComponent
	otherFact.Rule = json.RawMessage(strings.NewReplacer(communityFact, "component.strimzi.custom_resource_versions_set", `"setCondition":{"side":"proposed","component":"`+communityComponent, `"setCondition":{"side":"proposed","component":"`+crdStrimziComponent).Replace(good))
	current := with(`"side":"proposed"`, `"side":"current"`)
	current.RequiredFacts[0].Side = "current"
	for name, entry := range map[string]Entry{
		"a predicate rule":              predicate(),
		"the current side":              current,
		"another project's set fact":    otherFact,
		"a lead basis":                  with(`"state":"active"`, `"state":"active","basis":"lead"`),
		"a consensus basis":             with(`"state":"active"`, `"state":"active","basis":"consensus"`),
		"a severity":                    with(`"reasonCode"`, `"severity":"unsupported","reasonCode"`),
		"a notice operator":             with(`"operator":"forbid_set_member"`, `"operator":"notice_one_way"`),
		"a subject outside the project": with(`"component":"`+communityComponent+`","from"`, `"component":"pkg:github/strimzi/strimzi-kafka-operator","from"`),
		"a landscape project owning it": func() Entry { e := communityEntry(); e.Project = "strimzi"; return e }(),
		"an unknown project":            func() Entry { e := communityEntry(); e.Project = "not-a-project"; return e }(),
		"an empty description":          func() Entry { e := communityEntry(); e.Description = ""; return e }(),
		"an applicability fact": func() Entry {
			e := communityEntry()
			e.Rule = json.RawMessage(strings.Replace(good, `"setCondition"`, `"appliesWhen":[{"side":"proposed","component":"`+communityComponent+`","factId":"`+communityFact+`"}],"setCondition"`, 1))
			return e
		}(),
	} {
		if _, err := assembleWith(communityPack(t, packSchemaCommunity, entry), compiledDefinitions()); err == nil {
			t.Fatalf("%s admitted", name)
		}
	}
	// The control: the good shape is admitted by the same helper.
	if _, err := assembleWith(communityPack(t, packSchemaCommunity, communityEntry()), compiledDefinitions()); err != nil {
		t.Fatal(err)
	}
}

// A CNCF project's entry cannot carry a community component, and a
// community entry cannot carry a CNCF one.
func TestCommunityEntryCannotClaimCNCFIdentity(t *testing.T) {
	cncf := crdKafkaEntry()
	cncf.Rule = json.RawMessage(strings.NewReplacer(crdStrimziComponent, communityComponent, crdStrimziFact, communityFact).Replace(string(cncf.Rule)))
	cncf.RequiredFacts[0].ID, cncf.RequiredFacts[0].Component = communityFact, communityComponent
	if _, err := assembleWith(communityPack(t, packSchemaCommunity, cncf, communityEntry()), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("CNCF project's entry with a community component admitted: %v", err)
	}
	b := communityBundle(t)
	if _, ok := b.identities()[communitySlug]; !ok || b.hasProject(communitySlug) {
		t.Fatal("community project is not in the identities only")
	}
	for _, p := range b.landscape.Projects {
		if p.Slug == communitySlug || subjectComponent(p.Slug, p.RepositoryURL) == communityComponent {
			t.Fatalf("landscape lists %s", p.Slug)
		}
	}
}

func TestCommunityStaysOutOfTheCNCFCountsAndCorpus(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	b := communityBundle(t)
	// The catalogue is the CNCF landscape's: same projects, same counts.
	before, err := catalogue(base, false, "")
	if err != nil {
		t.Fatal(err)
	}
	after, err := catalogue(b, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if after.Catalogued != before.Catalogued || after.SourceRuleCovered != before.SourceRuleCovered || len(after.Projects) != len(before.Projects) {
		t.Fatalf("catalogue changed: %d/%d/%d -> %d/%d/%d", before.Catalogued, before.SourceRuleCovered, len(before.Projects), after.Catalogued, after.SourceRuleCovered, len(after.Projects))
	}
	for _, p := range after.Projects {
		if isCommunitySlug(p.Slug) || p.SourceRuleCount != 0 && p.Slug == communitySlug {
			t.Fatalf("catalogue lists community project %s", p.Slug)
		}
	}
	if _, err := catalogue(b, false, communitySlug); !errors.Is(err, ErrInvalid) {
		t.Fatalf("catalogue of a community project: %v", err)
	}
	// The corpus attestation never lists a community component, so a scope
	// naming one is never called complete.
	components, err := b.corpusComponents()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range components {
		if c == communityComponent {
			t.Fatalf("corpus components list %s", c)
		}
	}
	if _, known := b.componentIdentities()[communityComponent]; known {
		t.Fatal("a scope may name the community component")
	}
	// The rule is in the unfiltered rule set (the digest binds it) and in the
	// rule listing, labelled.
	identities, err := ruleIdentities(b)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, item := range identities {
		if item.Project == communitySlug {
			found++
			if item.Catalog != CatalogCommunity || item.RuleID != communityRuleID {
				t.Fatalf("identity %+v", item)
			}
		} else if item.Catalog != "" {
			t.Fatalf("%s carries catalog %q", item.Project, item.Catalog)
		}
	}
	if found != 1 {
		t.Fatalf("%d community identities", found)
	}
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	baseInventory, err := base.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.RuleCount != baseInventory.RuleCount+1 || inventory.RuleSetDigest == baseInventory.RuleSetDigest || len(inventory.Components) != len(baseInventory.Components) {
		t.Fatalf("corpus: %d rules, %d components (base %d, %d)", inventory.RuleCount, len(inventory.Components), baseInventory.RuleCount, len(baseInventory.Components))
	}
}

func TestCommunityTargetPaths(t *testing.T) {
	for slug, want := range map[string]string{
		"gateway-api": "knowledge/community/projects/gateway-api.v1.json",
		"strimzi":     "knowledge/cncf/projects/strimzi.v1.json",
		"kubernetes":  "knowledge/cncf/projects/kubernetes.v1.json",
	} {
		if got := ProjectTargetPath(slug); got != want {
			t.Fatalf("%s: %s", slug, got)
		}
		if back, ok := ProjectFromTargetPath(want); !ok || back != slug {
			t.Fatalf("%s: round trip %q %v", want, back, ok)
		}
	}
	for _, bad := range []string{
		// A community project lives under the community prefix only, a
		// CNCF one under the CNCF prefix only.
		"knowledge/cncf/projects/gateway-api.v1.json",
		"knowledge/community/projects/strimzi.v1.json",
		"knowledge/community/projects/unknown-project.v1.json",
		"knowledge/community/projects/gateway-api.v2.json",
		"knowledge/community/projects/Gateway-Api.v1.json",
		"knowledge/community/projects/../cncf/projects/strimzi.v1.json",
		"knowledge/community/gateway-api.v1.json",
		"knowledge/communities/projects/gateway-api.v1.json",
		"knowledge/community/projects/" + strings.Repeat("a", 65) + ".v1.json",
	} {
		if slug, ok := ProjectFromTargetPath(bad); ok {
			t.Fatalf("%s names project %s", bad, slug)
		}
	}
}

func buildCommunityTargets(t *testing.T, b bundle) (ExternalTarget, []ExternalTarget) {
	t.Helper()
	index, targets, err := buildExternalTargets(b, "7", "synthetic_test_only", func(string, func(string) ([]byte, error)) (string, error) { return "7", nil })
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	return index, targets
}

func TestCommunityTargetsAndIndex(t *testing.T) {
	b := communityBundle(t)
	index, targets := buildCommunityTargets(t, b)
	var document externalIndexDocument
	if err := json.Unmarshal(index.Bytes, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != ExternalIndexSchemaCommunity {
		t.Fatalf("index schema %s", document.Schema)
	}
	communityTargets := 0
	for _, entry := range document.Projects {
		if entry.Project == communitySlug {
			communityTargets++
			if entry.Catalog != CatalogCommunity || entry.TargetPath != "knowledge/community/projects/gateway-api.v1.json" || entry.Records {
				t.Fatalf("entry %+v", entry)
			}
		} else if entry.Catalog != "" || strings.HasPrefix(entry.TargetPath, ExternalCommunityTargetPrefix) {
			t.Fatalf("CNCF entry %+v is labelled community", entry)
		}
	}
	if communityTargets != 1 {
		t.Fatalf("%d community entries", communityTargets)
	}
	parsed, err := parseExternalIndex(index.Bytes, &b)
	if err != nil {
		t.Fatalf("index refused: %v", err)
	}
	for _, target := range targets {
		slug, ok := ProjectFromTargetPath(target.Path)
		if !ok {
			t.Fatalf("target path %s", target.Path)
		}
		envelope, err := AdmitExternalProjectTarget(parsed, slug, target.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", slug, err)
		}
		if slug == communitySlug {
			if envelope.pack.Schema != packSchemaCommunity || len(envelope.pack.Entries) != 1 {
				t.Fatalf("community envelope: %s, %d entries", envelope.pack.Schema, len(envelope.pack.Entries))
			}
		} else if envelope.pack.Schema == packSchemaCommunity {
			t.Fatalf("CNCF envelope %s carries the community schema", slug)
		}
	}
	// The community envelope is an ordinary envelope: it parses on its own
	// against the compiled knowledge and evaluates through the bundle.
	for _, target := range targets {
		if target.Path != ProjectTargetPath(communitySlug) {
			continue
		}
		external, err := ParseExternalBundle(target.Bytes)
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		prepared, err := cncfprepare.PrepareCustomResourceVersionsBytes([]byte("apiVersion: gateway.networking.k8s.io/v1beta1\nkind: Gateway\nmetadata:\n  name: main\n"), communitySlug, "1.1.0", "1.2.0", true)
		if err != nil {
			t.Fatal(err)
		}
		report, err := external.Evaluate(communitySlug, prepared.CanonicalInputJSON, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		if report.Catalog != CatalogCommunity || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" {
			t.Fatalf("report %s %+v", report.Catalog, report.Check.Claims)
		}
	}
}

func TestCommunityIndexRefusals(t *testing.T) {
	b := communityBundle(t)
	index, targets := buildCommunityTargets(t, b)
	var document externalIndexDocument
	if err := json.Unmarshal(index.Bytes, &document); err != nil {
		t.Fatal(err)
	}
	encode := func(mutate func(*externalIndexDocument)) []byte {
		copyDoc := document
		copyDoc.Projects = append([]ExternalIndexEntry(nil), document.Projects...)
		mutate(&copyDoc)
		raw, err := json.Marshal(copyDoc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	at := func(d *externalIndexDocument) *ExternalIndexEntry {
		for i := range d.Projects {
			if d.Projects[i].Project == communitySlug {
				return &d.Projects[i]
			}
		}
		t.Fatal("no community entry")
		return nil
	}
	cncfAt := func(d *externalIndexDocument) *ExternalIndexEntry {
		for i := range d.Projects {
			if d.Projects[i].Project != communitySlug {
				return &d.Projects[i]
			}
		}
		t.Fatal("no CNCF entry")
		return nil
	}
	if _, err := parseExternalIndex(encode(func(*externalIndexDocument) {}), &b); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, raw := range map[string][]byte{
		"community entry without its catalog":       encode(func(d *externalIndexDocument) { at(d).Catalog = "" }),
		"CNCF entry labelled community":             encode(func(d *externalIndexDocument) { cncfAt(d).Catalog = CatalogCommunity }),
		"unknown catalog":                           encode(func(d *externalIndexDocument) { at(d).Catalog = "cncf" }),
		"community entry under the CNCF prefix":     encode(func(d *externalIndexDocument) { at(d).TargetPath = "knowledge/cncf/projects/gateway-api.v1.json" }),
		"community entry under the v1 index schema": encode(func(d *externalIndexDocument) { d.Schema = ExternalIndexSchema }),
		"community entry under the v2 index schema": encode(func(d *externalIndexDocument) { d.Schema = ExternalIndexSchemaRecords }),
		"v3 index with no community entry": encode(func(d *externalIndexDocument) {
			kept := d.Projects[:0]
			for _, e := range d.Projects {
				if e.Project != communitySlug {
					kept = append(kept, e)
				}
			}
			d.Projects = kept
		}),
		"community project not in the table": encode(func(d *externalIndexDocument) {
			entry := at(d)
			entry.Project, entry.TargetPath = "zz-not-a-project", "knowledge/community/projects/zz-not-a-project.v1.json"
		}),
	} {
		if _, err := parseExternalIndex(raw, &b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A project target of another project's name or catalog is refused by
	// the admission against the index.
	parsed, err := parseExternalIndex(index.Bytes, &b)
	if err != nil {
		t.Fatal(err)
	}
	var communityBytes, cncfBytes []byte
	cncfSlug := ""
	for _, target := range targets {
		slug, _ := ProjectFromTargetPath(target.Path)
		if slug == communitySlug {
			communityBytes = target.Bytes
		} else if cncfBytes == nil {
			cncfBytes, cncfSlug = target.Bytes, slug
		}
	}
	if _, err := AdmitExternalProjectTarget(parsed, communitySlug, cncfBytes); err == nil {
		t.Fatal("a CNCF envelope admitted as the community target")
	}
	if _, err := AdmitExternalProjectTarget(parsed, cncfSlug, communityBytes); err == nil {
		t.Fatal("the community envelope admitted as a CNCF target")
	}
	// The index of a pack without a community entry is the v1 or v2 index
	// and carries no catalog member.
	plain, _ := buildCommunityTargets(t, mustLoad(t))
	if bytes.Contains(plain.Bytes, []byte(`"catalog"`)) || bytes.Contains(plain.Bytes, []byte(ExternalIndexSchemaCommunity)) {
		t.Fatalf("plain index: %s", plain.Bytes)
	}
}

func mustLoad(t *testing.T) bundle {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A community project is known to a scan once the knowledge holds data for
// it, and then only with the community catalog label.
func TestCommunityScanKnowledge(t *testing.T) {
	b := communityBundle(t)
	k, err := newScanKnowledge(b)
	if err != nil {
		t.Fatal(err)
	}
	component, ok := k.Component(communitySlug)
	if !ok || component != communityComponent || k.Catalog(communitySlug) != CatalogCommunity {
		t.Fatalf("component %q %v catalog %q", component, ok, k.Catalog(communitySlug))
	}
	rules := k.Rules(communitySlug)
	if len(rules) != 1 || rules[0].Project != communitySlug || rules[0].Scope.ID != communityRuleID {
		t.Fatalf("rules %+v", rules)
	}
	// A community project without data stays unknown, and a CNCF project is
	// never labelled.
	for _, p := range customresources.CommunityProjects() {
		if p.Slug == communitySlug {
			continue
		}
		if _, ok := k.Component(p.Slug); ok || k.Catalog(p.Slug) != "" {
			t.Fatalf("%s is known without data", p.Slug)
		}
	}
	if _, ok := k.Component("strimzi"); !ok || k.Catalog("strimzi") != "" {
		t.Fatal("strimzi is labelled or unknown")
	}
	for _, slug := range k.Projects() {
		if isCommunitySlug(slug) {
			t.Fatalf("catalogue lists %s", slug)
		}
	}
	// The compiled catalogue names every community project (the data is
	// known only once a database is open) and lists none as CNCF.
	catalog := &ScanCatalog{b: bundle{landscape: b.landscape, community: b.community}}
	if _, ok := catalog.Component(communitySlug); !ok {
		t.Fatal("compiled catalogue does not name the community project")
	}
	for _, slug := range catalog.Projects() {
		if isCommunitySlug(slug) {
			t.Fatalf("compiled catalogue lists %s as a project", slug)
		}
	}
}

// Knowledge selected from a store: only the opened community target counts,
// and an empty envelope is no data.
func TestCommunityStoreScanKnowledge(t *testing.T) {
	b := communityBundle(t)
	_, targets := buildCommunityTargets(t, b)
	opened := map[string]ExternalBundle{}
	for _, target := range targets {
		slug, _ := ProjectFromTargetPath(target.Path)
		if slug != communitySlug {
			continue
		}
		envelope, err := ParseExternalBundle(target.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		opened[slug] = envelope
	}
	if len(opened) != 1 {
		t.Fatalf("%d community targets", len(opened))
	}
	k, err := NewStoreScanKnowledge(opened)
	if err != nil {
		t.Fatalf("store knowledge: %v", err)
	}
	if component, ok := k.Component(communitySlug); !ok || component != communityComponent || k.Catalog(communitySlug) != CatalogCommunity || len(k.Rules(communitySlug)) != 1 {
		t.Fatalf("store knowledge: %q %v %q", component, ok, k.Catalog(communitySlug))
	}
	if k.Origin() != "external_signed_local" {
		t.Fatalf("origin %s", k.Origin())
	}
	// A project the index does not list evaluates against an empty envelope
	// and is not known.
	empty, err := EmptyExternalBundle("7", "synthetic_test_only")
	if err != nil {
		t.Fatal(err)
	}
	none, err := NewStoreScanKnowledge(map[string]ExternalBundle{communitySlug: empty})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := none.Component(communitySlug); ok || none.Catalog(communitySlug) != "" || len(none.Rules(communitySlug)) != 0 {
		t.Fatal("an empty envelope makes the community project known")
	}
	// An envelope under the name of a project that is in no catalog is
	// refused.
	if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{"zz-not-a-project": opened[communitySlug]}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("envelope of an unknown project accepted: %v", err)
	}
}

// Community data cannot attest: a line attestation of a community component
// is refused wherever an attestation is admitted, until the reviewed path
// exists; the same attestation for a CNCF component is admitted.
func TestCommunityCannotAttestYet(t *testing.T) {
	attestation := func(component string) lineattest.LineAttestation {
		a := lineattest.LineAttestation{
			Component: component, Line: "1.2", FactFamily: lineattest.FamilyCustomResourceVersions, Completeness: lineattest.Completeness, RuleIDs: []string{},
			Releases: &lineattest.Releases{
				From: []lineattest.Release{{Version: "1.1.0", Commit: strings.Repeat("1", 40)}},
				To:   []lineattest.Release{{Version: "1.2.0", Commit: strings.Repeat("3", 40)}},
			},
			Evidence: lineattest.Evidence{Basis: constraintengine.BasisReviewed, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
				Sources: []constraintengine.SourceEvidence{{ID: "crds", URL: "https://github.com/example/example/blob/" + syntheticRevision + "/crd.yaml", Revision: syntheticRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}}},
		}
		return a
	}
	// The attestation itself is refused for a community component, as it is
	// for any component outside its family (lineattest), and valid for a
	// CNCF custom-resource component.
	if err := attestation(crdStrimziComponent).Validate(); err != nil {
		t.Fatalf("CNCF custom-resource attestation invalid: %v", err)
	}
	for _, p := range customresources.CommunityProjects() {
		if err := attestation(p.Component).Validate(); err == nil {
			t.Fatalf("%s: community attestation is valid", p.Slug)
		}
		if family, _ := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions); family.Admits(p.Component) {
			t.Fatalf("%s: the family admits a community component", p.Slug)
		}
	}
	pack := func(schema string, section []byte, entries ...Entry) []byte {
		t.Helper()
		raw := communityPack(t, schema, entries...)
		var p rulePack
		if err := strictJSON(raw, &p); err != nil {
			t.Fatal(err)
		}
		p.LineAttestations = section
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Control: a quiet attestation of a CNCF custom-resource component.
	if _, err := assembleWith(pack(packSchemaAttested, section(t, attestation(crdStrimziComponent))), compiledDefinitions()); err != nil {
		t.Fatalf("CNCF custom-resource attestation refused: %v", err)
	}
	for _, p := range customresources.CommunityProjects() {
		// Without a community entry the pack is at the attested level; with
		// one it is at the community level. Either way it is refused.
		if _, err := assembleWith(pack(packSchemaAttested, rawSection(t, attestation(p.Component))), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: community attestation admitted: %v", p.Slug, err)
		}
		if p.Slug == communitySlug {
			if _, err := assembleWith(pack(packSchemaCommunity, rawSection(t, attestation(p.Component)), communityEntry()), compiledDefinitions()); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s: community attestation next to a community rule admitted: %v", p.Slug, err)
			}
		}
	}
	// The same refusal holds for a community envelope: a records envelope
	// whose attestation names the community component is not admitted.
	b := communityBundle(t)
	attested := rulePack{Schema: packSchemaCommunity, Revision: "7", PolicyID: b.pack.PolicyID, PolicyDigest: b.pack.PolicyDigest, LandscapeFileDigest: b.pack.LandscapeFileDigest, RegistryDigest: b.pack.RegistryDigest, Entries: []Entry{communityEntry()}, LineAttestations: rawSection(t, attestation(communityComponent))}
	if err := admitExternalRecords(b, mustMarshal(t, attested), attested); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("community attestation in an envelope admitted: %v", err)
	}
	// Path policies and served-API lists name catalog subjects of the
	// landscape only.
	if _, err := admitPathPolicies([]byte(`[{"component":"`+communityComponent+`"}]`), true, b.landscape.Projects); err == nil {
		t.Fatal("a path policy for a community component admitted")
	}
}

// rawSection renders an attestation section without the validity check that
// lineattest.Marshal makes, so the pack's own admission is what refuses it.
func rawSection(t *testing.T, atts ...lineattest.LineAttestation) []byte {
	t.Helper()
	return mustMarshal(t, atts)
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Record ownership knows the community catalog, so a record that is ever
// admitted for a community component lands in its project's target.
func TestCommunityRecordOwnership(t *testing.T) {
	b := communityBundle(t)
	owners := recordOwners(b.knowledgeProjects())
	if owners[communityComponent] != communitySlug || owners[crdStrimziComponent] != "strimzi" {
		t.Fatalf("owners %q %q", owners[communityComponent], owners[crdStrimziComponent])
	}
	if got := recordOwners(b.landscape.Projects)[communityComponent]; got != "" {
		t.Fatalf("landscape owners name the community component: %q", got)
	}
	pack := rulePack{ServedAPIs: json.RawMessage(`[{"component":"` + communityComponent + `"}]`)}
	if !recordsOwnedBy(pack, communitySlug, b.knowledgeProjects()) || recordsOwnedBy(pack, "strimzi", b.knowledgeProjects()) {
		t.Fatal("records of the community component are not owned by exactly the community project")
	}
	if recordsOwnedBy(pack, communitySlug, b.landscape.Projects) {
		t.Fatal("landscape identities own a community record")
	}
}
