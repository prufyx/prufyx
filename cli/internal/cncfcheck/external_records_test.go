// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Records in external targets (EXTPACK): the per-project targets and the
// single target carry line attestations, upgrade-path policies and
// served-API lists; a client admits them with the embedded pack's checks and
// refuses a record in the wrong project's target, a tampered record, a
// records target under the old schema and an index whose level does not
// match its targets.

const extServedEvidence = `{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}`

func extServedSection(line string, apis ...string) json.RawMessage {
	encoded, _ := json.Marshal(apis)
	return json.RawMessage(`[{"component":"` + k8sComponent + `","line":"` + line + `","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":` + string(encoded) + `,"evidence":` + extServedEvidence + `}]`)
}

// recordsPack is the embedded pack with the given record sections (nil for
// none) at the schema level they need.
func recordsPack(t *testing.T, sections recordSections) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.LineAttestations, pack.PathPolicies, pack.ServedAPIs = sections.LineAttestations, sections.PathPolicies, sections.ServedAPIs
	if pack.Schema, err = requiredPackSchema(pack); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func recordsBase(t *testing.T, sections recordSections) bundle {
	t.Helper()
	b, err := assembleSynthetic(recordsPack(t, sections), nil)
	if err != nil {
		t.Fatalf("records pack refused by the loader: %v", err)
	}
	return b
}

func allRecords(t *testing.T) recordSections {
	return recordSections{LineAttestations: validAttestations(t), PathPolicies: validPolicies(t), ServedAPIs: extServedSection("1.29", "apps/v1 Deployment", "v1 ConfigMap")}
}

func splitAt(t *testing.T, b bundle, revision string) (ExternalTarget, map[string][]byte) {
	t.Helper()
	index, targets, err := buildExternalTargets(b, revision, "operator_provided", func(string, func(string) ([]byte, error)) (string, error) { return revision, nil })
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	out := map[string][]byte{}
	for _, target := range targets {
		project, ok := ProjectFromTargetPath(target.Path)
		if !ok {
			t.Fatalf("target path %s", target.Path)
		}
		out[project] = target.Bytes
	}
	return index, out
}

func envelopeOf(t *testing.T, raw []byte) (string, rulePack) {
	t.Helper()
	var envelope struct {
		Schema string   `json:"schema"`
		Pack   rulePack `json:"pack"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Schema, envelope.Pack
}

// TestSplitTargetsCarryRecords: every record lands in the target of the
// project whose subject component it names, that target is a records
// envelope, the index is a v2 index naming exactly those targets, every
// target is admitted against it, and the scan view built from the targets
// answers the same record lookups as the pack.
func TestSplitTargetsCarryRecords(t *testing.T) {
	b := recordsBase(t, allRecords(t))
	index, targets := splitAt(t, b, "7")
	parsed, err := parseExternalIndex(index.Bytes, &b)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if parsed.document.Schema != ExternalIndexSchemaRecords {
		t.Fatalf("index schema %s", parsed.document.Schema)
	}
	withRecords := map[string]bool{}
	for _, entry := range parsed.Entries() {
		if entry.Records {
			withRecords[entry.Project] = true
		}
	}
	if len(withRecords) != 2 || !withRecords["kubernetes"] || !withRecords["cilium"] {
		t.Fatalf("records targets %v", withRecords)
	}
	bundles := map[string]ExternalBundle{}
	for project, raw := range targets {
		admitted, err := AdmitExternalProjectTarget(parsed, project, raw)
		if err != nil {
			t.Fatalf("%s: %v", project, err)
		}
		bundles[project] = admitted
		schema, pack := envelopeOf(t, raw)
		admission, _ := admitted.Admission()
		if withRecords[project] != (schema == externalBundleSchemaRecords) || admission.HasRecords != withRecords[project] {
			t.Fatalf("%s: envelope %s records %v", project, schema, admission.HasRecords)
		}
		if !withRecords[project] && (bytes.Contains(raw, []byte(lineattest.PackMember)) || bytes.Contains(raw, []byte(upgradepath.PackMember))) {
			t.Fatalf("%s carries a record section", project)
		}
		if project == "kubernetes" && (len(pack.LineAttestations) == 0 || len(pack.PathPolicies) == 0 || len(pack.ServedAPIs) == 0) {
			t.Fatal("the kubernetes target lacks one of its records")
		}
		if project == "cilium" && (len(pack.LineAttestations) != 0 || len(pack.ServedAPIs) != 0 || !bytes.Contains(pack.PathPolicies, []byte(ciliumComponent)) || bytes.Contains(pack.PathPolicies, []byte(k8sComponent))) {
			t.Fatalf("cilium target records: %s", pack.PathPolicies)
		}
	}
	store, err := NewStoreScanKnowledge(bundles)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got := store.AttestationsFor(k8sComponent, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, now); len(got) != 1 || !got[0].Current() || len(got[0].Attestation.RuleIDs) != len(line125Rules) {
		t.Fatalf("attestation from the store: %+v", got)
	}
	if status, ok := store.ServedAPIsFor(k8sComponent, "1.29", now); !ok || !status.Current() || len(status.Record.APIs) != 2 {
		t.Fatalf("served list from the store: %+v %v", status, ok)
	}
	if !store.PathPolicyFor(ciliumComponent, now).Found || !store.PathPolicyFor(k8sComponent, now).Found {
		t.Fatal("path policies from the store")
	}
	// The single target carries every record too.
	raw, err := encodeExternalEnvelopeWithRecords(b, "7", "operator_provided", b.pack.Entries, sectionsOf(b.pack))
	if err != nil {
		t.Fatal(err)
	}
	single, err := parseExternalBundle(raw, &b)
	if err != nil {
		t.Fatalf("single target with records: %v", err)
	}
	if admission, _ := single.Admission(); !admission.HasRecords || !admission.HasRule {
		t.Fatalf("single admission %+v", admission)
	}
}

// TestSplitWithoutRecordsIsUnchanged: a pack without records splits exactly
// as before: a v1 index without a records member and v1alpha1 envelopes.
func TestSplitWithoutRecordsIsUnchanged(t *testing.T) {
	index, projects, err := BuildEmbeddedExternalTargets("7", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index.Bytes, []byte(`"records"`)) || !bytes.Contains(index.Bytes, []byte(`"schema":"`+ExternalIndexSchema+`"`)) {
		t.Fatal("a pack without records produced a records index")
	}
	for _, target := range projects {
		if schema, _ := envelopeOf(t, target.Bytes); schema != externalBundleSchema {
			t.Fatalf("%s schema %s", target.Path, schema)
		}
	}
	single, err := ExportEmbeddedExternalBundle("7")
	if err != nil || !bytes.HasPrefix(single, []byte(`{"schema":"`+externalBundleSchema+`"`)) {
		t.Fatalf("single target %v", err)
	}
}

// TestRecordOnlyProjectGetsATarget: a project with a record and no rule gets
// a records target without entries, admitted by its index entry.
func TestRecordOnlyProjectGetsATarget(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	ruled := map[string]bool{}
	for _, entry := range base.pack.Entries {
		ruled[entry.Project] = true
	}
	owners := recordOwners(base.landscape.Projects)
	var project, component string
	for _, p := range base.landscape.Projects {
		c := subjectComponent(p.Slug, p.RepositoryURL)
		if !ruled[p.Slug] && strings.HasPrefix(c, "pkg:github/") && owners[c] == p.Slug {
			project, component = p.Slug, c
			break
		}
	}
	if project == "" {
		t.Fatal("no catalog project without rules")
	}
	b := recordsBase(t, recordSections{PathPolicies: policySection(t, testPolicyRecord(component, upgradepath.PolicyDirect))})
	index, targets := splitAt(t, b, "7")
	parsed, err := parseExternalIndex(index.Bytes, &b)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := AdmitExternalProjectTarget(parsed, project, targets[project])
	if err != nil {
		t.Fatalf("record-only target: %v", err)
	}
	if admission, _ := admitted.Admission(); admission.HasRule || !admission.HasRecords || admission.EvidenceExpiresAt != "2026-12-30T00:00:00Z" || !digestPattern.MatchString(admission.RuleDigest) {
		t.Fatalf("admission %+v", admission)
	}
}

// relabel returns an index over the given targets, every entry computed
// from the target bytes as the publisher computes it, so only the check
// under test can refuse.
func relabel(t *testing.T, b bundle, revision string, targets map[string][]byte) ExternalIndex {
	t.Helper()
	capability, err := externalCapabilityDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	document := externalIndexDocument{Schema: ExternalIndexSchema, Revision: revision, Purpose: "operator_provided", EngineCapabilityDigest: capability}
	projects := make([]string, 0, len(targets))
	for project := range targets {
		projects = append(projects, project)
	}
	sortStrings(projects)
	for _, project := range projects {
		raw := targets[project]
		parsed, err := parseExternalBundle(raw, &b)
		if err != nil {
			t.Fatalf("%s: %v", project, err)
		}
		admission, _ := parsed.Admission()
		if admission.HasRecords {
			document.Schema = ExternalIndexSchemaRecords
		}
		document.Projects = append(document.Projects, ExternalIndexEntry{Project: project, TargetPath: ProjectTargetPath(project), Revision: revision, Length: int64(len(raw)), Digest: digest(raw), RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt, Records: admission.HasRecords})
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	index, err := parseExternalIndex(raw, &b)
	if err != nil {
		t.Fatalf("relabelled index: %v", err)
	}
	return index
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}

// TestProjectTargetRefusesForeignRecords: a record of another project's
// scope moved into a target is refused even when the signed index describes
// the smuggled target exactly; the honest target under the same procedure is
// admitted.
func TestProjectTargetRefusesForeignRecords(t *testing.T) {
	b := recordsBase(t, allRecords(t))
	_, targets := splitAt(t, b, "7")
	if _, err := AdmitExternalProjectTarget(relabel(t, b, "7", targets), "kubernetes", targets["kubernetes"]); err != nil {
		t.Fatalf("control: honest target refused: %v", err)
	}
	var k8sEntries []Entry
	for _, entry := range b.pack.Entries {
		if entry.Project == "kubernetes" {
			k8sEntries = append(k8sEntries, entry)
		}
	}
	// Cilium's path policy in the kubernetes target (both policies), and
	// the kubernetes policy in the cilium target.
	_, k8sPack := envelopeOf(t, targets["kubernetes"])
	smuggled, err := encodeExternalEnvelopeWithRecords(b, "7", "operator_provided", k8sEntries, recordSections{LineAttestations: k8sPack.LineAttestations, PathPolicies: validPolicies(t), ServedAPIs: k8sPack.ServedAPIs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExternalBundle(smuggled, &b); err != nil {
		t.Fatalf("the smuggled envelope must be well formed for this test: %v", err)
	}
	moved := map[string][]byte{}
	for project, raw := range targets {
		moved[project] = raw
	}
	moved["kubernetes"] = smuggled
	if _, err := AdmitExternalProjectTarget(relabel(t, b, "7", moved), "kubernetes", smuggled); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a foreign record was admitted: %v", err)
	}
	ciliumOnly, err := encodeExternalEnvelopeWithRecords(b, "7", "operator_provided", nil, recordSections{PathPolicies: policySection(t, testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor))})
	if err != nil {
		t.Fatal(err)
	}
	moved = map[string][]byte{"kubernetes": targets["kubernetes"], "cilium": ciliumOnly}
	if _, err := AdmitExternalProjectTarget(relabel(t, b, "7", moved), "cilium", ciliumOnly); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("the kubernetes policy was admitted in the cilium target: %v", err)
	}
}

// TestRecordsTargetTamperRefused: a changed record, a record whose rule set
// no longer matches the target's rules, a records target under the old
// envelope schema, a records envelope without records, and an index whose
// records flag or schema level does not match are all refused.
func TestRecordsTargetTamperRefused(t *testing.T) {
	b := recordsBase(t, allRecords(t))
	index, targets := splitAt(t, b, "7")
	parsed, err := parseExternalIndex(index.Bytes, &b)
	if err != nil {
		t.Fatal(err)
	}
	k8s := targets["kubernetes"]

	// A byte change in a record breaks the index binding.
	changed := bytes.Replace(k8s, []byte(`"v1 ConfigMap"`), []byte(`"v1 Secret"`), 1)
	if bytes.Equal(changed, k8s) {
		t.Fatal("test target has no ConfigMap")
	}
	if _, err := AdmitExternalProjectTarget(parsed, "kubernetes", changed); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered record admitted: %v", err)
	}
	// Even re-labelled, an attestation that leaves out a rule of its line
	// is refused by the target parser (exact rule set).
	_, pack := envelopeOf(t, k8s)
	short := bytes.Replace(pack.LineAttestations, []byte(`"`+line125Rules[0]+`",`), nil, 1)
	if bytes.Equal(short, pack.LineAttestations) {
		t.Fatal("test attestation does not list the rule")
	}
	var k8sEntries []Entry
	for _, entry := range b.pack.Entries {
		if entry.Project == "kubernetes" {
			k8sEntries = append(k8sEntries, entry)
		}
	}
	shortened, err := encodeExternalEnvelopeWithRecords(b, "7", "operator_provided", k8sEntries, recordSections{LineAttestations: short, PathPolicies: pack.PathPolicies, ServedAPIs: pack.ServedAPIs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExternalBundle(shortened, &b); err == nil {
		t.Fatal("an attestation leaving out a rule was admitted")
	}
	// A served list naming an API removed at or below its line.
	removed, err := encodeExternalEnvelopeWithRecords(b, "7", "operator_provided", k8sEntries, recordSections{ServedAPIs: extServedSection("1.29", "flowcontrol.apiserver.k8s.io/v1beta2 FlowSchema")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExternalBundle(removed, &b); err == nil {
		t.Fatal("a served list naming a removed API was admitted")
	}
	// The old envelope schema never carries records.
	old := bytes.Replace(k8s, []byte(externalBundleSchemaRecords), []byte(externalBundleSchema), 1)
	if _, err := parseExternalBundle(old, &b); err == nil {
		t.Fatal("a v1alpha1 envelope with records was admitted")
	}
	// A records envelope without records is not the level its content needs.
	plain, err := encodeExternalEnvelope(b, "7", "operator_provided", k8sEntries)
	if err != nil {
		t.Fatal(err)
	}
	upgraded := bytes.Replace(plain, []byte(externalBundleSchema), []byte(externalBundleSchemaRecords), 1)
	if _, err := parseExternalBundle(upgraded, &b); err == nil {
		t.Fatal("a records envelope without records was admitted")
	}
	// Index level and flags.
	var document externalIndexDocument
	if err := json.Unmarshal(index.Bytes, &document); err != nil {
		t.Fatal(err)
	}
	reencode := func(edit func(*externalIndexDocument)) []byte {
		copyDoc := document
		copyDoc.Projects = append([]ExternalIndexEntry(nil), document.Projects...)
		edit(&copyDoc)
		raw, _ := json.Marshal(copyDoc)
		return raw
	}
	if _, err := parseExternalIndex(reencode(func(d *externalIndexDocument) { d.Schema = ExternalIndexSchema }), &b); err == nil {
		t.Fatal("a v1 index listing records targets was admitted")
	}
	noRecords := reencode(func(d *externalIndexDocument) {
		for i := range d.Projects {
			d.Projects[i].Records = false
		}
	})
	if _, err := parseExternalIndex(noRecords, &b); err == nil {
		t.Fatal("a v2 index without a records target was admitted")
	}
	// The kubernetes entry says "no records": its records target is refused.
	unflagged := reencode(func(d *externalIndexDocument) {
		for i := range d.Projects {
			if d.Projects[i].Project == "kubernetes" {
				d.Projects[i].Records = false
			}
		}
	})
	lying, err := parseExternalIndex(unflagged, &b)
	if err != nil {
		t.Fatalf("index with one records target: %v", err)
	}
	if _, err := AdmitExternalProjectTarget(lying, "kubernetes", k8s); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("records target admitted under a no-records entry: %v", err)
	}
}

// TestOldClientsRefuseRecords: what a binary that predates records checks
// refuses both the v2 index and a records envelope. The old parsers compare
// the schema exactly and decode strictly; this pins both properties on the
// new documents.
func TestOldClientsRefuseRecords(t *testing.T) {
	b := recordsBase(t, allRecords(t))
	index, targets := splitAt(t, b, "7")
	type oldEntry struct {
		Project           string `json:"project"`
		TargetPath        string `json:"targetPath"`
		Revision          string `json:"revision"`
		Length            int64  `json:"length"`
		Digest            string `json:"digest"`
		RuleDigest        string `json:"ruleDigest"`
		EvidenceExpiresAt string `json:"evidenceExpiresAt"`
	}
	var old struct {
		Schema                 string     `json:"schema"`
		Revision               string     `json:"revision"`
		Purpose                string     `json:"purpose"`
		EngineCapabilityDigest string     `json:"engineCapabilityDigest"`
		Projects               []oldEntry `json:"projects"`
	}
	if err := strictJSON(index.Bytes, &old); err == nil || old.Schema == ExternalIndexSchema {
		t.Fatalf("an old index parser would admit the v2 index: %v %s", err, old.Schema)
	}
	schema, _ := envelopeOf(t, targets["kubernetes"])
	if schema == externalBundleSchema {
		t.Fatal("a records target under the old envelope schema")
	}
	// The old envelope shape (no record members) refuses it as well.
	if _, err := externalObject(mustMember(t, targets["kubernetes"], "pack"), []string{"schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "entries"}); err == nil {
		t.Fatal("the old envelope shape admits a records pack")
	}
}

func mustMember(t *testing.T, raw []byte, name string) json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object[name]
}

// TestRecordsBindContentAndExpiry: the content digest moves with a record
// alone, and a record expiring before every rule sets the target's expiry.
func TestRecordsBindContentAndExpiry(t *testing.T) {
	a := recordsBase(t, recordSections{ServedAPIs: extServedSection("1.29", "v1 ConfigMap")})
	b := recordsBase(t, recordSections{ServedAPIs: extServedSection("1.29", "v1 ConfigMap", "v1 Secret")})
	_, ta := splitAt(t, a, "7")
	_, tb := splitAt(t, b, "7")
	pa, err := parseExternalBundle(ta["kubernetes"], &a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := parseExternalBundle(tb["kubernetes"], &b)
	if err != nil {
		t.Fatal(err)
	}
	aa, _ := pa.Admission()
	ab, _ := pb.Admission()
	if aa.RuleDigest == ab.RuleDigest {
		t.Fatal("the content digest does not cover the records")
	}
	// A served list expiring before every rule of the pack.
	early := json.RawMessage(strings.Replace(string(extServedSection("1.29", "v1 ConfigMap")), "2026-12-20T00:00:00Z", "2026-10-20T00:00:00Z", 1))
	c := recordsBase(t, recordSections{ServedAPIs: early})
	_, tc := splitAt(t, c, "7")
	pc, err := parseExternalBundle(tc["kubernetes"], &c)
	if err != nil {
		t.Fatal(err)
	}
	ac, _ := pc.Admission()
	plain, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	whole, err := ParseExternalBundle(plain)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := whole.Admission()
	if rules.EvidenceExpiresAt <= "2026-10-20T00:00:00Z" || ac.EvidenceExpiresAt != "2026-10-20T00:00:00Z" {
		t.Fatalf("records target expiry %s (rules %s), want the served list's", ac.EvidenceExpiresAt, rules.EvidenceExpiresAt)
	}
}

// TestDistributionsStayUnpublishable: distribution records have no target;
// the split and both exports refuse a pack holding them.
func TestDistributionsStayUnpublishable(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	base.pack.Distributions = json.RawMessage(`[{}]`)
	same := func(string, func(string) ([]byte, error)) (string, error) { return "7", nil }
	if _, _, err := buildExternalTargets(base, "7", "operator_provided", same); !errors.Is(err, ErrIntegrity) || !errors.Is(err, ErrDistributionsNotPublishable) {
		t.Fatalf("split with distributions: %v", err)
	}
}

// TestRecordOwnersAmbiguous: a component that is the subject of two
// catalog projects has no owner, so its records cannot be split.
func TestRecordOwnersAmbiguous(t *testing.T) {
	projects := []projectIdentity{{Slug: "a", RepositoryURL: "https://github.com/x/y"}, {Slug: "b", RepositoryURL: "https://github.com/x/y"}, {Slug: "c", RepositoryURL: "https://github.com/x/z"}}
	owners := recordOwners(projects)
	if owners["pkg:github/x/y"] != "" || owners["pkg:github/x/z"] != "c" {
		t.Fatalf("owners %v", owners)
	}
	section := json.RawMessage(`[{"component":"pkg:github/x/y"}]`)
	if _, err := splitSection(section, owners); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("ambiguous component split: %v", err)
	}
	// The real catalog has no ambiguous subject component.
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for component, owner := range recordOwners(base.landscape.Projects) {
		if owner == "" {
			t.Fatalf("catalog component %s has two projects", component)
		}
	}
}
