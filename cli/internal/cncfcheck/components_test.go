// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// Extra components of a catalog project (components.go). The fixture
// testdata/landscape-components-alertmanager.json is test data only; the
// shipped file lists no entry.

const (
	alertmanager = "pkg:github/prometheus/alertmanager"
	nodeExporter = "pkg:github/prometheus/node_exporter"
	promPurl     = "pkg:github/prometheus/prometheus"
	// shippedCatalogueDigest is the digest of the pinned Landscape reduction,
	// recorded before the components file existed. While the components file
	// lists no entry it is the catalogue digest, so it must never move.
	shippedCatalogueDigest = "sha256:719482946c4f639e2b557aa1f5e4d3e961d21c49f8c4fa2bbd7f7f4e6aa19c4c"
)

func componentsInputs(t *testing.T) (landscape, priority, pack []byte) {
	t.Helper()
	var err error
	if landscape, err = packagedFiles.ReadFile("data/landscape-projects.json"); err != nil {
		t.Fatal(err)
	}
	if priority, err = packagedFiles.ReadFile("data/priority-portfolio.json"); err != nil {
		t.Fatal(err)
	}
	if pack, err = packagedFiles.ReadFile("data/rules.json"); err != nil {
		t.Fatal(err)
	}
	return
}

func assembleComponents(t *testing.T, raw []byte, table []customresources.Project) (bundle, error) {
	t.Helper()
	landscape, priority, pack := componentsInputs(t)
	return assembleWithComponents(landscape, raw, priority, pack, compiledDefinitions(), table)
}

func fixtureComponents(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/landscape-components-alertmanager.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// componentsDoc renders a components document for the given entries over the
// real landscape digest.
func componentsDoc(t *testing.T, entries ...componentEntry) []byte {
	t.Helper()
	landscape, _, _ := componentsInputs(t)
	var parsed landscapeDocument
	if err := strictJSON(landscape, &parsed); err != nil {
		t.Fatal(err)
	}
	if entries == nil {
		entries = []componentEntry{}
	}
	raw, err := json.Marshal(componentsDocument{Schema: componentsSchema, LandscapeFileDigest: parsed.LandscapeFileDigest, Components: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func entry(slug, purl string) componentEntry {
	return componentEntry{Slug: slug, Purl: purl, Source: "https://github.com/prometheus/alertmanager"}
}

// The code PR ships no entry and moves no digest: the shipped load, an
// absent file and an empty file give the same catalogue digest, equal to
// the pre-change golden value, and no project has an extra component.
func TestComponentsEmptyChangesNoDigest(t *testing.T) {
	t.Parallel()
	shipped, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if shipped.catalogueDigest != shippedCatalogueDigest {
		t.Fatalf("catalogue digest %s moved from %s", shipped.catalogueDigest, shippedCatalogueDigest)
	}
	absent, err := assembleComponents(t, nil, customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	empty, err := assembleComponents(t, componentsDoc(t), customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]bundle{"absent": absent, "empty": empty} {
		if b.catalogueDigest != shippedCatalogueDigest || b.packDigest != shipped.packDigest {
			t.Fatalf("%s: digests moved: %s %s", name, b.catalogueDigest, b.packDigest)
		}
		for _, project := range b.landscape.Projects {
			if len(project.Components) != 0 {
				t.Fatalf("%s: %s has components", name, project.Slug)
			}
		}
	}
	extras, err := CatalogExtraComponents()
	if err != nil || len(extras) != 0 {
		t.Fatalf("shipped extras %v %v", extras, err)
	}
	owners := recordOwners(shipped.knowledgeProjects())
	if len(owners) != len(subjectComponents(shipped.knowledgeProjects())) {
		t.Fatal("owner set differs from the subject set")
	}
}

// With the listed fixture a sibling repository of Prometheus is owned by
// Prometheus, its records are admissible under it, and the catalogue digest
// moves intentionally to the combined digest.
func TestComponentsFixtureMakesRecordsAdmissible(t *testing.T) {
	t.Parallel()
	section := json.RawMessage(`[{"component":"` + alertmanager + `"}]`)
	without, err := assembleComponents(t, nil, customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := splitSection(section, recordOwners(without.knowledgeProjects())); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unlisted record: %v", err)
	}
	if subjectComponents(without.knowledgeProjects())[alertmanager] {
		t.Fatal("unlisted component is a subject")
	}
	raw := fixtureComponents(t)
	listed, err := assembleComponents(t, raw, customresources.Projects())
	if err != nil {
		t.Fatalf("fixture refused: %v", err)
	}
	projects := listed.knowledgeProjects()
	owners := recordOwners(projects)
	if owners[alertmanager] != "prometheus" || owners[promPurl] != "prometheus" {
		t.Fatalf("owners %q %q", owners[alertmanager], owners[promPurl])
	}
	if !subjectComponents(projects)[alertmanager] {
		t.Fatal("listed component is not a subject")
	}
	split, err := splitSection(section, owners)
	if err != nil || len(split["prometheus"]) == 0 {
		t.Fatalf("listed record not split to its owner: %v", err)
	}
	pack := rulePack{ServedAPIs: section}
	if !recordsOwnedBy(pack, "prometheus", projects) || recordsOwnedBy(pack, "strimzi", projects) {
		t.Fatal("listed record not owned by exactly Prometheus")
	}
	landscape, _, _ := componentsInputs(t)
	want := digest([]byte(componentsSchema + "\n" + digest(landscape) + "\n" + digest(raw)))
	if listed.catalogueDigest != want || listed.catalogueDigest == shippedCatalogueDigest {
		t.Fatalf("catalogue digest %s, want %s", listed.catalogueDigest, want)
	}
	// Prometheus still has one repositoryURL, no project was added.
	if len(listed.landscape.Projects) != len(without.landscape.Projects) {
		t.Fatal("a project row was added")
	}
	// The pack's rules and its subject check are untouched by extras.
	if listed.packDigest != without.packDigest {
		t.Fatal("pack digest moved")
	}
}

// A sibling that is not listed stays refused even when another is.
func TestComponentsNonListedSiblingStaysRefused(t *testing.T) {
	t.Parallel()
	b, err := assembleComponents(t, fixtureComponents(t), customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	section := json.RawMessage(`[{"component":"` + nodeExporter + `"}]`)
	if _, err := splitSection(section, recordOwners(b.knowledgeProjects())); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unlisted sibling: %v", err)
	}
	if recordsOwnedBy(rulePack{ServedAPIs: section}, "prometheus", b.knowledgeProjects()) {
		t.Fatal("unlisted sibling owned")
	}
}

// Records of the repositoryURL component and the listed component split to
// their owner in order, mixed with another project's records.
func TestComponentsMixedSplitKeepsOrder(t *testing.T) {
	t.Parallel()
	b, err := assembleComponents(t, fixtureComponents(t), customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	const strimzi = "pkg:github/strimzi/strimzi-kafka-operator"
	section := json.RawMessage(`[{"component":"` + alertmanager + `","n":1},{"component":"` + strimzi + `","n":2},{"component":"` + promPurl + `","n":3},{"component":"` + alertmanager + `","n":4}]`)
	split, err := splitSection(section, recordOwners(b.knowledgeProjects()))
	if err != nil {
		t.Fatal(err)
	}
	var prom, strim []struct{ N int }
	if err := json.Unmarshal(split["prometheus"], &prom); err != nil || json.Unmarshal(split["strimzi"], &strim) != nil {
		t.Fatalf("split: %v", err)
	}
	if len(prom) != 3 || prom[0].N != 1 || prom[1].N != 3 || prom[2].N != 4 || len(strim) != 1 || len(split) != 2 {
		t.Fatalf("order/ownership: %v %v", prom, strim)
	}
}

// Two claimants of one component give no owner, and the record is refused.
func TestComponentsTwoClaimantsGiveNoOwner(t *testing.T) {
	t.Parallel()
	projects := []projectIdentity{
		{Slug: "a", RepositoryURL: "https://github.com/x/a", Components: []string{"pkg:github/x/shared"}},
		{Slug: "b", RepositoryURL: "https://github.com/x/b", Components: []string{"pkg:github/x/shared"}},
		{Slug: "c", RepositoryURL: "https://github.com/x/shared"},
	}
	owners := recordOwners(projects)
	if owners["pkg:github/x/shared"] != "" || owners["pkg:github/x/a"] != "a" {
		t.Fatalf("owners %v", owners)
	}
	if _, err := splitSection(json.RawMessage(`[{"component":"pkg:github/x/shared"}]`), owners); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("two claimants: %v", err)
	}
}

// Every problem in the file refuses the whole load.
func TestComponentsRefusals(t *testing.T) {
	t.Parallel()
	good := entry("prometheus", alertmanager)
	cases := map[string][]byte{
		"wildcard":                componentsDoc(t, entry("prometheus", "pkg:github/prometheus/*")),
		"org only":                componentsDoc(t, entry("prometheus", "pkg:github/prometheus")),
		"org with slash":          componentsDoc(t, entry("prometheus", "pkg:github/prometheus/")),
		"versioned":               componentsDoc(t, entry("prometheus", alertmanager+"@v0.27.0")),
		"qualifier":               componentsDoc(t, entry("prometheus", alertmanager+"?x=y")),
		"subpath":                 componentsDoc(t, entry("prometheus", alertmanager+"/sub")),
		"not github":              componentsDoc(t, entry("prometheus", "pkg:oci/prometheus/alertmanager")),
		"malformed":               componentsDoc(t, entry("prometheus", "alertmanager")),
		"empty purl":              componentsDoc(t, entry("prometheus", "")),
		"uppercase":               componentsDoc(t, entry("prometheus", "pkg:github/prometheus/Alertmanager")),
		"cross org":               componentsDoc(t, entry("prometheus", "pkg:github/other/alertmanager")),
		"own repository":          componentsDoc(t, entry("prometheus", promPurl)),
		"unknown project":         componentsDoc(t, entry("no-such-project", alertmanager)),
		"special opentelemetry":   componentsDoc(t, entry("opentelemetry", "pkg:github/open-telemetry/opentelemetry-go")),
		"special buildpacks":      componentsDoc(t, entry("buildpacks", "pkg:github/buildpacks/pack")),
		"special kubeflow":        componentsDoc(t, entry("kubeflow", "pkg:github/kubeflow/pipelines")),
		"special cni":             componentsDoc(t, entry("container-network-interface-cni", "pkg:github/containernetworking/plugins")),
		"other landscape project": componentsDoc(t, entry("spiffe", "pkg:github/spiffe/spire")),
		"no source":               componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager}),
		"http source":             componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager, Source: "http://github.com/prometheus/alertmanager"}),
		"source on another host":  componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager, Source: "https://example.com/prometheus/alertmanager"}),
		"source lookalike host":   componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager, Source: "https://github.com.example.com/prometheus/alertmanager"}),
		"source with user":        componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager, Source: "https://u@github.com/prometheus/alertmanager"}),
		"source not a url":        componentsDoc(t, componentEntry{Slug: "prometheus", Purl: alertmanager, Source: "::"}),
		"self duplicate":          componentsDoc(t, good, good),
		"duplicate other slug":    componentsDoc(t, good, entry("prometheus-operator", alertmanager)),
		"unsorted":                componentsDoc(t, entry("prometheus", nodeExporter), good),
		"unknown field":           []byte(strings.Replace(string(componentsDoc(t, good)), `"source"`, `"extra":1,"source"`, 1)),
		"trailing data":           append(componentsDoc(t, good), []byte(` {}`)...),
		"not json":                []byte(`x`),
		"empty file":              []byte(``),
		"null components":         []byte(strings.Replace(string(componentsDoc(t)), `[]`, `null`, 1)),
		"wrong schema":            []byte(strings.Replace(string(componentsDoc(t)), componentsSchema, "prufyx.io/x/v1", 1)),
		"wrong landscape digest":  []byte(strings.Replace(string(componentsDoc(t)), "sha256:8ee4", "sha256:0000", 1)),
	}
	for name, raw := range cases {
		if _, err := assembleComponents(t, raw, customresources.Projects()); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: load not refused: %v", name, err)
		}
	}
	if _, err := assembleComponents(t, componentsDoc(t, good), customresources.Projects()); err != nil {
		t.Fatalf("control entry refused: %v", err)
	}
}

// A case variant of a listed purl is refused (the load never lower-cases an
// entry into acceptance), and an entry claimed by two landscape projects
// stays refused.
func TestComponentsCaseVariantAndLandscapeCollision(t *testing.T) {
	t.Parallel()
	for _, purl := range []string{"pkg:github/Prometheus/alertmanager", "pkg:github/prometheus/ALERTMANAGER", "pkg:GITHUB/prometheus/alertmanager"} {
		if _, err := assembleComponents(t, componentsDoc(t, entry("prometheus", purl)), customresources.Projects()); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s accepted: %v", purl, err)
		}
	}
	// spin and spinkube share an organization: one cannot take the other's
	// repository.
	if _, err := assembleComponents(t, componentsDoc(t, entry("spin", "pkg:github/spinframework/spin-operator")), customresources.Projects()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("same-org sibling owned by another project accepted: %v", err)
	}
}

// A community project may not duplicate a listed component.
func TestComponentsCommunityCollision(t *testing.T) {
	t.Parallel()
	var one customresources.Project
	for _, p := range customresources.CommunityProjects() {
		if p.Slug == communitySlug {
			one = p
		}
	}
	if one.Slug == "" {
		t.Fatal("no community project")
	}
	if _, err := assembleComponents(t, fixtureComponents(t), []customresources.Project{one}); err != nil {
		t.Fatalf("control refused: %v", err)
	}
	clash := one
	clash.Component = alertmanager
	clash.Upstream.Repository = "https://github.com/prometheus/alertmanager"
	if _, err := assembleComponents(t, fixtureComponents(t), []customresources.Project{clash}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("community duplicate of a listed component accepted: %v", err)
	}
	// Without the listing the same community project is the only claimant.
	if _, err := assembleComponents(t, nil, []customresources.Project{clash}); err != nil {
		t.Fatalf("community project alone refused: %v", err)
	}
}

// A project whose repository URL carries extra path segments owns a subject
// with those segments. An entry equal to it, or a sibling that is not in the
// project's organization, is refused; a same-organization sibling is not.
func TestComponentsRepositoryWithExtraPathSegments(t *testing.T) {
	t.Parallel()
	projects := []projectIdentity{{Slug: "a", Name: "A", RepositoryURL: "https://github.com/org/repo/tree/main/sub"}}
	const digestValue = "sha256:8ee4c10af7d58ddda752ff91c20bf6a5f328bfa5aa288f93801d0ca9d2b0c0ef"
	doc := func(purl string) []byte {
		raw, _ := json.Marshal(componentsDocument{Schema: componentsSchema, LandscapeFileDigest: digestValue, Components: []componentEntry{{Slug: "a", Purl: purl, Source: "https://github.com/org/other"}}})
		return raw
	}
	for purl, ok := range map[string]bool{
		"pkg:github/org/repo/tree/main/sub": false,
		"pkg:github/other/repo":             false,
		"pkg:github/org/other":              true,
	} {
		_, _, err := attachComponents(doc(purl), digestValue, projects)
		if (err == nil) != ok {
			t.Errorf("%s: accepted=%v, want %v", purl, err == nil, ok)
		}
	}
}

// The listed fixture reaches ErrRecordWithoutOwner through the target
// builder only when the record's component is not listed.
func TestComponentsRecordWithoutOwnerThroughTargetBuilder(t *testing.T) {
	t.Parallel()
	b := recordsBase(t, allRecords(t))
	b.landscape.Projects = append([]projectIdentity(nil), b.landscape.Projects...)
	b.pack.ServedAPIs = json.RawMessage(strings.ReplaceAll(string(b.pack.ServedAPIs), k8sComponent, alertmanager))
	build := func(b bundle) error {
		_, _, err := buildExternalTargets(b, "rev", "operator_provided", func(string, func(string) ([]byte, error)) (string, error) { return "rev", nil })
		return err
	}
	if err := build(b); !errors.Is(err, ErrRecordWithoutOwner) || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unlisted record: %v", err)
	}
	listed, err := assembleComponents(t, fixtureComponents(t), customresources.Projects())
	if err != nil {
		t.Fatal(err)
	}
	b.landscape.Projects = listed.landscape.Projects
	if err := build(b); errors.Is(err, ErrRecordWithoutOwner) {
		t.Fatalf("listed record still without owner: %v", err)
	}
}
