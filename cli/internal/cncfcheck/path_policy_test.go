// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// These tests attach synthetic path-policy records to the embedded pack. The
// embedded pack carries none and stays byte-identical.

const ciliumComponent = "pkg:github/cilium/cilium"

func testPolicyRecord(component, policy string) upgradepath.Record {
	return upgradepath.Record{Component: component, Policy: policy, Evidence: upgradepath.Evidence{
		State: upgradepath.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "upgrade-order", URL: "https://github.com/kubernetes/website/blob/" + syntheticRevision + "/content/en/releases/version-skew-policy.md", Revision: syntheticRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
	}}
}

func policySection(t *testing.T, records ...upgradepath.Record) []byte {
	t.Helper()
	raw, err := upgradepath.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validPolicies(t *testing.T) []byte {
	return policySection(t, testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor), testPolicyRecord(ciliumComponent, upgradepath.PolicyDirect))
}

// featurePack is the embedded pack with schema and raw attestation and
// path-policy sections (nil for none).
func featurePack(t *testing.T, schema string, attestations, policies []byte) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Schema, pack.LineAttestations, pack.PathPolicies = schema, attestations, policies
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEmbeddedPackCarriesNoPathPolicies(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(upgradepath.PackMember)) {
		t.Fatal("the published pack carries path policies")
	}
	status, err := PathPolicyFor(k8sComponent, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || status.Found || status.Policy() != nil {
		t.Fatalf("embedded path policy: %+v %v", status, err)
	}
	components, err := CatalogSubjectComponents()
	if err != nil || !slices.Contains(components, k8sComponent) || !slices.Contains(components, ciliumComponent) || !slices.IsSorted(components) {
		t.Fatalf("catalog subject components: %d %v", len(components), err)
	}
}

func TestPathPolicyPackIsAdmittedAndLookedUp(t *testing.T) {
	b, err := assembleSynthetic(featurePack(t, packSchemaPathPolicies, nil, validPolicies(t)), nil)
	if err != nil {
		t.Fatalf("pack with path policies refused: %v", err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	k8s := b.pathPolicies.Lookup(k8sComponent, now)
	if p := k8s.Policy(); !k8s.Found || p == nil || p.Policy != upgradepath.PolicySequentialMinor || p.Component != k8sComponent {
		t.Fatalf("kubernetes: %+v", k8s)
	}
	if got := b.pathPolicies.Lookup("pkg:github/argoproj/argo-cd", now); got.Found || got.Policy() != nil {
		t.Fatalf("a component without a record: %+v", got)
	}
	// The plan follows the record.
	plan := upgradepath.PlanPath(k8sComponent, "1.24.17", "1.30.4", k8s.Policy())
	if len(plan.Hops) != 6 || plan.Gap != "" {
		t.Fatalf("plan %+v", plan)
	}
	// The policies take no part in the rules the engine sees.
	plain, err := assembleSynthetic(featurePack(t, packSchemaRanged, nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := b.ruleSet("")
	p, _ := plain.ruleSet("")
	da, _ := a.Digest()
	dp, _ := p.Digest()
	if da != dp {
		t.Fatal("path policies changed the engine rule document")
	}
	// The pack digest covers the section.
	other := testPolicyRecord(k8sComponent, upgradepath.PolicyDirect)
	c, err := assembleSynthetic(featurePack(t, packSchemaPathPolicies, nil, policySection(t, other, testPolicyRecord(ciliumComponent, upgradepath.PolicyDirect))), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.packDigest == b.packDigest {
		t.Fatal("the pack digest does not cover the path policies")
	}
}

func TestPathPolicyFreshness(t *testing.T) {
	withdrawn := testPolicyRecord(ciliumComponent, upgradepath.PolicyDirect)
	withdrawn.Evidence.State = upgradepath.StateWithdrawn
	b, err := assembleSynthetic(featurePack(t, packSchemaPathPolicies, nil, policySection(t, testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor), withdrawn)), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		component string
		now       time.Time
		want      string
	}{
		{"current", k8sComponent, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), upgradepath.FreshnessCurrent},
		{"expired", k8sComponent, time.Date(2026, 12, 30, 0, 0, 0, 0, time.UTC), upgradepath.FreshnessStale},
		{"long expired", k8sComponent, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), upgradepath.FreshnessStale},
		{"clock before review", k8sComponent, time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC), upgradepath.FreshnessClockBeforeReview},
		{"withdrawn", ciliumComponent, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), upgradepath.FreshnessWithdrawn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status := b.pathPolicyFor(c.component, c.now)
			if !status.Found || status.Freshness != c.want {
				t.Fatalf("status %+v, want %s", status, c.want)
			}
			current := c.want == upgradepath.FreshnessCurrent
			if (status.Policy() != nil) != current {
				t.Fatalf("policy usable at %s", status.Freshness)
			}
			// A record that exists but is not current is told apart from no
			// record: it is a gap of its own, never a direct hop.
			if status.RecordNotCurrent() == current {
				t.Fatalf("RecordNotCurrent %v at %s", status.RecordNotCurrent(), status.Freshness)
			}
		})
	}
	if absent := b.pathPolicyFor("pkg:github/argoproj/argo-cd", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); absent.Found || absent.RecordNotCurrent() || absent.Policy() != nil {
		t.Fatalf("absent record: %+v", absent)
	}
	// The embedded lookup goes through the same method.
	for _, c := range cases {
		t.Run("embedded "+c.name, func(t *testing.T) {
			if status, err := PathPolicyFor(c.component, c.now); err != nil || status.Found {
				t.Fatalf("embedded pack: %+v %v", status, err)
			}
		})
	}
}

// Every defect in the path-policy section rejects the whole pack.
func TestPathPoliciesStrict(t *testing.T) {
	good := featurePack(t, packSchemaPathPolicies, nil, validPolicies(t))
	if _, err := assembleSynthetic(good, nil); err != nil {
		t.Fatalf("unmutated pack refused: %v", err)
	}
	record := func(mutate func(*upgradepath.Record)) []byte {
		r := testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor)
		mutate(&r)
		raw, _ := json.Marshal([]upgradepath.Record{r})
		return raw
	}
	inOrder := func(records ...upgradepath.Record) []byte {
		raw, _ := json.Marshal(records)
		return raw
	}
	sections := map[string][]byte{
		"unknown record member":   bytes.Replace(validPolicies(t), []byte(`"policy":"direct"`), []byte(`"policy":"direct","default":true`), 1),
		"unknown evidence member": bytes.Replace(validPolicies(t), []byte(`"state":"active"`), []byte(`"state":"active","owner":"x"`), 1),
		"case variant member":     bytes.Replace(validPolicies(t), []byte(`"policy":"direct"`), []byte(`"POLICY":"direct"`), 1),
		"repeated member":         bytes.Replace(validPolicies(t), []byte(`"policy":"direct"`), []byte(`"policy":"sequential_minor","policy":"direct"`), 1),
		"unknown policy":          record(func(r *upgradepath.Record) { r.Policy = "skip_minor" }),
		"duplicate component":     inOrder(testPolicyRecord(k8sComponent, upgradepath.PolicyDirect), testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor)),
		"unsorted":                inOrder(testPolicyRecord(k8sComponent, upgradepath.PolicySequentialMinor), testPolicyRecord(ciliumComponent, upgradepath.PolicyDirect)),
		"non-subject component":   record(func(r *upgradepath.Record) { r.Component = "pkg:github/kubernetes-sigs/kind" }),
		"repository not subject": record(func(r *upgradepath.Record) {
			r.Component = "pkg:github/open-telemetry/opentelemetry-collector-releases"
		}),
		"bad evidence state":  record(func(r *upgradepath.Record) { r.Evidence.State = "draft" }),
		"bad evidence window": record(func(r *upgradepath.Record) { r.Evidence.ValidUntil = "2027-06-01T00:00:00Z" }),
		"bad evidence source": record(func(r *upgradepath.Record) { r.Evidence.Sources[0].Revision = "main" }),
		"bad evidence basis":  record(func(r *upgradepath.Record) { r.Evidence.Basis = "inferred" }),
		"no sources":          record(func(r *upgradepath.Record) { r.Evidence.Sources = []constraintengine.SourceEvidence{} }),
		"null section":        []byte(`null`),
		"empty section":       []byte(`[]`),
		"object section":      []byte(`{}`),
	}
	for name, section := range sections {
		t.Run(name, func(t *testing.T) {
			if _, err := assembleSynthetic(featurePack(t, packSchemaPathPolicies, nil, section), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// Member names of the pack itself are matched exactly.
	variants := map[string][]byte{
		"two spellings": bytes.Replace(good, []byte(`"pathPolicies":`), append(append([]byte(`"pathPolicies":`), policySection(t, testPolicyRecord(k8sComponent, upgradepath.PolicyDirect))...), []byte(`,"PathPolicies":`)...), 1),
		"repeated":      bytes.Replace(good, []byte(`"pathPolicies":`), append(append([]byte(`"pathPolicies":`), policySection(t, testPolicyRecord(k8sComponent, upgradepath.PolicyDirect))...), []byte(`,"pathPolicies":`)...), 1),
	}
	for _, alias := range []string{"PathPolicies", "PATHPOLICIES", "pathPolicieſ"} {
		variants[alias] = bytes.Replace(good, []byte(`"pathPolicies"`), []byte(`"`+alias+`"`), 1)
	}
	for name, raw := range variants {
		t.Run("member "+name, func(t *testing.T) {
			if bytes.Equal(raw, good) {
				t.Fatal("fixture not mutated")
			}
			if _, err := assembleSynthetic(raw, nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("loader accepted: %v", err)
			}
		})
	}
}

// A pack carries exactly the schema of its highest-level feature; a pack
// without path policies keeps its schema and bytes.
func TestPackSchemaLevels(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != embeddedPackSHA256 {
		t.Fatalf("embedded pack changed: %x", sum)
	}
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if b.pack.Schema != packSchemaRanged || b.packDigest != "sha256:"+embeddedPackSHA256 {
		t.Fatalf("embedded pack schema %s digest %s", b.pack.Schema, b.packDigest)
	}
	// Decoding and re-encoding a pack without the new sections adds nothing.
	reencoded, err := json.Marshal(b.pack)
	if err != nil || bytes.Contains(reencoded, []byte(upgradepath.PackMember)) || bytes.Contains(reencoded, []byte("lineAttestations")) {
		t.Fatalf("re-encoded pack gained a section: %v", err)
	}
	if schema, err := requiredPackSchema(b.pack); err != nil || schema != packSchemaRanged {
		t.Fatalf("required schema of the embedded pack %s %v", schema, err)
	}

	policies, attestations := validPolicies(t), validAttestations(t)
	all := []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, "prufyx.io/cncf-source-rule-pack/v1alpha6"}
	for _, c := range []struct {
		name                   string
		attestations, policies []byte
		want                   string
	}{
		{"neither", nil, nil, packSchemaRanged},
		{"attestations", attestations, nil, packSchemaAttested},
		{"path policies", nil, policies, packSchemaPathPolicies},
		{"attestations and path policies", attestations, policies, packSchemaPathPolicies},
	} {
		for _, schema := range all {
			_, err := assembleSynthetic(featurePack(t, schema, c.attestations, c.policies), nil)
			if schema == c.want && err != nil {
				t.Fatalf("%s under %s refused: %v", c.name, schema, err)
			}
			if schema != c.want && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s under %s accepted: %v", c.name, schema, err)
			}
		}
	}
	// A binary that predates path policies rejects such a pack twice: the
	// member is unknown to its pack type, and so is the schema.
	type previousPack struct {
		Schema              string          `json:"schema"`
		Revision            string          `json:"revision"`
		PolicyID            string          `json:"policyId"`
		PolicyDigest        string          `json:"policyDigest"`
		LandscapeFileDigest string          `json:"landscapeFileDigest"`
		RegistryDigest      string          `json:"registryDigest"`
		Entries             []Entry         `json:"entries"`
		LineAttestations    json.RawMessage `json:"lineAttestations,omitempty"`
	}
	var old previousPack
	if err := strictJSON(featurePack(t, packSchemaPathPolicies, nil, policies), &old); err == nil {
		t.Fatal("the previous pack shape admits a pack with path policies")
	}
	if err := strictJSON(featurePack(t, packSchemaRanged, nil, nil), &old); err != nil {
		t.Fatalf("the previous pack shape refuses a pack without path policies: %v", err)
	}
}

func TestExternalRefusesPathPolicies(t *testing.T) {
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(raw); err != nil {
		t.Fatalf("untampered external bundle refused: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
		t.Fatal(err)
	}
	pack[upgradepath.PackMember] = validPolicies(t)
	pack["schema"], _ = json.Marshal(packSchemaPathPolicies)
	envelope["pack"], _ = json.Marshal(pack)
	tampered, _ := json.Marshal(envelope)
	if _, err := ParseExternalBundle(tampered); err == nil {
		t.Fatal("an external bundle with path policies was admitted")
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var value rulePack
	if err := json.Unmarshal(envelope["pack"], &value); err != nil {
		t.Fatal(err)
	}
	if err := validateExternalPack(base, value, "7"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted path policies: %v", err)
	}
	// The same pack value without the section passes the external check, so
	// the refusal above is the section's.
	value.PathPolicies, value.Schema = nil, packSchemaRanged
	if err := validateExternalPack(base, value, "7"); err != nil {
		t.Fatalf("validateExternalPack refused the pack without path policies: %v", err)
	}
}

func TestPathPolicyPackMember(t *testing.T) {
	field, ok := reflect.TypeOf(rulePack{}).FieldByName("PathPolicies")
	if !ok {
		t.Fatal("rulePack has no PathPolicies field")
	}
	if name, _, _ := strings.Cut(field.Tag.Get("json"), ","); name != upgradepath.PackMember {
		t.Fatalf("rulePack path-policy member %q, upgradepath.PackMember %q", name, upgradepath.PackMember)
	}
}

// Project targets carry rule entries only. A source pack with a section they
// cannot carry is refused, never split without it; a pack without one splits
// with each target's schema chosen by the same level table as the loader's.
func TestSplitTargetsRefuseSectionsTheyCannotCarry(t *testing.T) {
	same := func(string, func(string) ([]byte, error)) (string, error) { return "7", nil }
	for name, raw := range map[string][]byte{
		"path policies": featurePack(t, packSchemaPathPolicies, nil, validPolicies(t)),
		"attestations":  featurePack(t, packSchemaAttested, validAttestations(t), nil),
		"both":          featurePack(t, packSchemaPathPolicies, validAttestations(t), validPolicies(t)),
	} {
		base, err := assembleSynthetic(raw, nil)
		if err != nil {
			t.Fatalf("%s: synthetic pack refused: %v", name, err)
		}
		if _, targets, err := buildExternalTargets(base, "7", "operator_provided", same); !errors.Is(err, ErrIntegrity) || targets != nil {
			t.Fatalf("%s: split without the section: %v", name, err)
		}
	}
	base, err := assembleSynthetic(featurePack(t, packSchemaRanged, nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, targets, err := buildExternalTargets(base, "7", "operator_provided", same)
	if err != nil || len(targets) == 0 {
		t.Fatalf("plain pack split: %d %v", len(targets), err)
	}
	for _, target := range targets {
		var envelope struct {
			Pack rulePack `json:"pack"`
		}
		if err := json.Unmarshal(target.Bytes, &envelope); err != nil {
			t.Fatal(err)
		}
		want, err := requiredPackSchema(rulePack{Entries: envelope.Pack.Entries})
		if err != nil || envelope.Pack.Schema != want {
			t.Fatalf("%s: schema %s, want %s (%v)", target.Path, envelope.Pack.Schema, want, err)
		}
	}
}
