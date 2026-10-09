// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// These tests attach a synthetic distribution section to the embedded
// pack. Its statements (OpenShift 4.99 -> Kubernetes 1.99, ...) are test
// data, not knowledge; the embedded pack carries none and stays
// byte-identical.

func testDistributionEvidence() distribution.Evidence {
	return distribution.Evidence{
		State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + syntheticRevision + "/versions.md", Revision: syntheticRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
	}
}

func testDistributionSection() distribution.Section {
	return distribution.Section{
		Records: []distribution.Record{
			{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Evidence: testDistributionEvidence()},
			{Distribution: "openshift", ControlPlane: distribution.ControlPlaneSelfManaged, KubernetesMapping: []distribution.Mapping{{Line: "4.99", Kubernetes: "1.99"}}, Evidence: testDistributionEvidence()},
		},
		Applicability: []distribution.Applicability{
			{Distribution: "eks", Family: distribution.FamilyComponentFlags, Status: distribution.StatusNotApplicable, Evidence: testDistributionEvidence()},
			{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: testDistributionEvidence()},
		},
	}
}

func validDistributions(t *testing.T) []byte {
	t.Helper()
	raw, err := distribution.Marshal(testDistributionSection())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// distributionPack is the embedded pack with schema and raw sections (nil
// for none).
func distributionPack(t *testing.T, schema string, attestations, policies, distributions []byte) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Schema, pack.LineAttestations, pack.PathPolicies, pack.Distributions = schema, attestations, policies, distributions
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEmbeddedPackCarriesNoDistributions(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"`+distribution.PackMember+`"`)) {
		t.Fatal("the published pack carries distribution records")
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, family := range distribution.Families() {
		got, err := DistributionApplicability("eks", family, now)
		if err != nil || got.Status != distribution.LookupAbsent || got.Applies() {
			t.Fatalf("embedded eks %s: %+v %v", family, got, err)
		}
		got, err = DistributionApplicability("official_upstream", family, now)
		if err != nil || !got.Applies() {
			t.Fatalf("embedded upstream %s: %+v %v", family, got, err)
		}
	}
	if m, err := OpenShiftMinor("4.16", now); err != nil || m.Found {
		t.Fatalf("embedded OpenShift mapping: %+v %v", m, err)
	}
	if table, err := OpenShiftTable(now); err != nil || table != nil {
		t.Fatalf("embedded OpenShift table: %v %v", table, err)
	}
}

func TestDistributionPackIsAdmittedAndLookedUp(t *testing.T) {
	b, err := assembleSynthetic(distributionPack(t, packSchemaDistributions, nil, nil, validDistributions(t)), nil)
	if err != nil {
		t.Fatalf("pack with distributions refused: %v", err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got := b.distributions.ApplicabilityFor("eks", distribution.FamilyRemovedServedGVK, now); !got.Applies() {
		t.Fatalf("eks served APIs: %+v", got)
	}
	if got := b.distributions.ApplicabilityFor("eks", distribution.FamilyComponentFlags, now); got.Applies() || got.Status != distribution.LookupNotApplicable {
		t.Fatalf("eks flags: %+v", got)
	}
	if got := b.distributions.ApplicabilityFor("gke", distribution.FamilyRemovedServedGVK, now); got.Applies() || got.Status != distribution.LookupAbsent {
		t.Fatalf("gke without a record: %+v", got)
	}
	table := b.distributions.OpenShiftTable(now)
	v, err := k8sversion.ParseWith("4.99.3", "openshift", table)
	if err != nil || v.Upstream.String() != "1.99" || v.Upstream.PatchKnown {
		t.Fatalf("OpenShift through the pack: %+v %v", v, err)
	}
	// The section takes no part in the rules the engine sees.
	plain, err := assembleSynthetic(distributionPack(t, packSchemaRanged, nil, nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := b.ruleSet("")
	p, _ := plain.ruleSet("")
	da, _ := a.Digest()
	dp, _ := p.Digest()
	if da != dp {
		t.Fatal("distributions changed the engine rule document")
	}
	// The pack digest covers the section.
	other := testDistributionSection()
	other.Applicability[1].Status = distribution.StatusNotApplicable
	otherRaw, err := distribution.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	c, err := assembleSynthetic(distributionPack(t, packSchemaDistributions, nil, nil, otherRaw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.packDigest == b.packDigest || c.packDigest == plain.packDigest {
		t.Fatal("the pack digest does not cover the distribution section")
	}
	if got := c.distributions.ApplicabilityFor("eks", distribution.FamilyRemovedServedGVK, now); got.Applies() {
		t.Fatalf("not_applicable applies: %+v", got)
	}
	// All three sections together.
	if _, err := assembleSynthetic(distributionPack(t, packSchemaDistributions, validAttestations(t), validPolicies(t), validDistributions(t)), nil); err != nil {
		t.Fatalf("pack with every section refused: %v", err)
	}
}

// Every defect in the distribution section rejects the whole pack.
func TestDistributionsStrict(t *testing.T) {
	good := distributionPack(t, packSchemaDistributions, nil, nil, validDistributions(t))
	if _, err := assembleSynthetic(good, nil); err != nil {
		t.Fatalf("unmutated pack refused: %v", err)
	}
	section := func(mutate func(*distribution.Section)) []byte {
		s := testDistributionSection()
		mutate(&s)
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	edit := func(old, new string) []byte {
		raw := validDistributions(t)
		if !bytes.Contains(raw, []byte(old)) {
			t.Fatalf("%q not in the section", old)
		}
		return bytes.Replace(raw, []byte(old), []byte(new), 1)
	}
	sections := map[string][]byte{
		"unknown record member":   edit(`"controlPlane":"managed"`, `"controlPlane":"managed","versionPattern":"^v1"`),
		"unknown evidence member": edit(`"state":"active"`, `"state":"active","owner":"x"`),
		"unknown section member":  edit(`{"records":`, `{"notes":[],"records":`),
		"case variant member":     edit(`"controlPlane"`, `"CONTROLPLANE"`),
		"repeated member":         edit(`"controlPlane":"managed"`, `"controlPlane":"managed","controlPlane":"managed"`),
		"null member":             edit(`"applicability":[`, `"applicability":null,"x":[`),
		"unknown family":          section(func(s *distribution.Section) { s.Applicability[1].Family = "kubernetes.workloads" }),
		"unknown distribution": section(func(s *distribution.Section) {
			s.Records[0].Distribution = "minikube"
			s.Applicability = s.Applicability[:0]
		}),
		"record for upstream": section(func(s *distribution.Section) {
			s.Records[0].Distribution = "kubeadm"
			s.Applicability = []distribution.Applicability{}
		}),
		"unknown status":        section(func(s *distribution.Section) { s.Applicability[1].Status = "partial" }),
		"unknown control plane": section(func(s *distribution.Section) { s.Records[0].ControlPlane = "hosted" }),
		"unsorted records":      section(func(s *distribution.Section) { s.Records[0], s.Records[1] = s.Records[1], s.Records[0] }),
		"unsorted statements": section(func(s *distribution.Section) {
			s.Applicability[0], s.Applicability[1] = s.Applicability[1], s.Applicability[0]
		}),
		"duplicate record":         section(func(s *distribution.Section) { s.Records[1] = s.Records[0] }),
		"duplicate statement":      section(func(s *distribution.Section) { s.Applicability[0] = s.Applicability[1] }),
		"statement without record": section(func(s *distribution.Section) { s.Applicability[1].Distribution = "gke" }),
		"non-Git source": section(func(s *distribution.Section) {
			s.Records[0].Evidence.Sources[0].URL = "https://docs.aws.example/eks/versions.html"
		}),
		"branch source": section(func(s *distribution.Section) {
			s.Records[0].Evidence.Sources[0].URL = "https://github.com/example/docs/blob/main/versions.md"
		}),
		"bad reviewedAt":           section(func(s *distribution.Section) { s.Records[0].Evidence.ReviewedAt = "2026-10-01" }),
		"validUntil before review": section(func(s *distribution.Section) { s.Applicability[0].Evidence.ValidUntil = "2026-09-01T00:00:00Z" }),
		"window over 90 days":      section(func(s *distribution.Section) { s.Applicability[0].Evidence.ValidUntil = "2027-01-01T00:00:00Z" }),
		"mapping not increasing": section(func(s *distribution.Section) {
			s.Records[1].KubernetesMapping = append(s.Records[1].KubernetesMapping, distribution.Mapping{Line: "4.100", Kubernetes: "1.99"})
		}),
		"mapping on eks": section(func(s *distribution.Section) {
			s.Records[0].KubernetesMapping = []distribution.Mapping{{Line: "4.99", Kubernetes: "1.99"}}
		}),
		"empty records":        []byte(`{"records":[],"applicability":[]}`),
		"null section":         []byte(`null`),
		"array section":        []byte(`[]`),
		"empty object section": []byte(`{}`),
		"string section":       []byte(`"distributions"`),
	}
	if len(sections) < 12 {
		t.Fatalf("only %d rows", len(sections))
	}
	for name, raw := range sections {
		t.Run(name, func(t *testing.T) {
			if _, err := assembleSynthetic(distributionPack(t, packSchemaDistributions, nil, nil, raw), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("pack admitted: %v", err)
			}
		})
	}
	// Top-level member spellings other than the exact one are refused.
	for name, raw := range map[string][]byte{
		"Distributions":   bytes.Replace(good, []byte(`"distributions":`), []byte(`"Distributions":`), 1),
		"DISTRIBUTIONS":   bytes.Replace(good, []byte(`"distributions":`), []byte(`"DISTRIBUTIONS":`), 1),
		"folded s":        bytes.Replace(good, []byte(`"distributions":`), []byte(`"distributionſ":`), 1),
		"two spellings":   bytes.Replace(good, []byte(`"distributions":`), []byte(`"Distributions":{},"distributions":`), 1),
		"repeated":        bytes.Replace(good, []byte(`"distributions":`), []byte(`"distributions":{},"distributions":`), 1),
		"trailing member": bytes.Replace(good, []byte(`"distributions":`), []byte(`"distribution":{},"distributions":`), 1),
	} {
		t.Run("member "+name, func(t *testing.T) {
			if _, err := assembleSynthetic(raw, nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("pack admitted: %v", err)
			}
		})
	}
}

func TestPackSchemaLevelDistributions(t *testing.T) {
	// Without the section the embedded pack keeps its schema and digest, and
	// re-encoding adds nothing.
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
	if b.pack.Schema != packSchemaRanged || b.packDigest != "sha256:"+embeddedPackSHA256 || b.distributions.Len() != 0 {
		t.Fatalf("embedded pack schema %s digest %s", b.pack.Schema, b.packDigest)
	}
	reencoded, err := json.Marshal(b.pack)
	if err != nil || bytes.Contains(reencoded, []byte(`"`+distribution.PackMember+`"`)) || !bytes.Equal(reencoded, distributionPack(t, b.pack.Schema, nil, nil, nil)) {
		t.Fatalf("re-encoded pack gained a section: %v", err)
	}
	if schema, err := requiredPackSchema(b.pack); err != nil || schema != packSchemaRanged {
		t.Fatalf("required schema %s %v", schema, err)
	}
	// With the section, exactly the distributions level is admitted, alone
	// or with every lower section.
	all := []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, "prufyx.io/cncf-source-rule-pack/v1alpha10", packSchemaCrossing}
	for _, c := range []struct {
		name                                  string
		attestations, policies, distributions []byte
		want                                  string
	}{
		{"none", nil, nil, nil, packSchemaRanged},
		{"distributions", nil, nil, validDistributions(t), packSchemaDistributions},
		{"policies", nil, validPolicies(t), nil, packSchemaPathPolicies},
		{"every section", validAttestations(t), validPolicies(t), validDistributions(t), packSchemaDistributions},
	} {
		for _, schema := range all {
			_, err := assembleSynthetic(distributionPack(t, schema, c.attestations, c.policies, c.distributions), nil)
			if schema == c.want && err != nil {
				t.Fatalf("%s under %s refused: %v", c.name, schema, err)
			}
			if schema != c.want && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s under %s accepted: %v", c.name, schema, err)
			}
		}
	}
	// The distributions row is followed only by the served-list row and the
	// crossing row.
	if rows := packFeatureLevels; rows[len(rows)-3].schema != packSchemaDistributions || rows[len(rows)-2].schema != packSchemaServedAPIs || rows[len(rows)-1].schema != packSchemaCrossing {
		t.Fatalf("last levels %s %s %s", rows[len(rows)-3].schema, rows[len(rows)-2].schema, rows[len(rows)-1].schema)
	}
	// A binary that predates distributions rejects such a pack twice: the
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
		PathPolicies        json.RawMessage `json:"pathPolicies,omitempty"`
	}
	var old previousPack
	if err := strictJSON(distributionPack(t, packSchemaDistributions, nil, nil, validDistributions(t)), &old); err == nil {
		t.Fatal("the previous pack shape admits a pack with distributions")
	}
}

func TestExternalRefusesDistributions(t *testing.T) {
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
		t.Fatal(err)
	}
	pack[distribution.PackMember] = validDistributions(t)
	pack["schema"], _ = json.Marshal(packSchemaDistributions)
	envelope["pack"], _ = json.Marshal(pack)
	tampered, _ := json.Marshal(envelope)
	if _, err := ParseExternalBundle(tampered); err == nil {
		t.Fatal("an external bundle with distributions was admitted")
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var value rulePack
	if err := json.Unmarshal(envelope["pack"], &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Distributions) == 0 {
		t.Fatal("the section did not decode")
	}
	if err := validateExternalPack(base, value, "7", false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted distributions: %v", err)
	}
	// The same pack value without the section passes, so the refusal above
	// is the section's.
	value.Distributions, value.Schema = nil, packSchemaRanged
	if err := validateExternalPack(base, value, "7", false); err != nil {
		t.Fatalf("validateExternalPack refused the pack without distributions: %v", err)
	}
	// Project targets cannot carry the section either: the split refuses.
	same := func(string, func(string) ([]byte, error)) (string, error) { return "7", nil }
	withSection, err := assembleSynthetic(distributionPack(t, packSchemaDistributions, nil, nil, validDistributions(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, targets, err := buildExternalTargets(withSection, "7", "operator_provided", same); !errors.Is(err, ErrIntegrity) || targets != nil {
		t.Fatalf("split without the section: %v", err)
	}
}

func TestDistributionPackMember(t *testing.T) {
	field, ok := reflect.TypeOf(rulePack{}).FieldByName("Distributions")
	if !ok {
		t.Fatal("rulePack has no Distributions field")
	}
	if name, _, _ := strings.Cut(field.Tag.Get("json"), ","); name != distribution.PackMember {
		t.Fatalf("rulePack distribution member %q, distribution.PackMember %q", name, distribution.PackMember)
	}
	found := false
	for _, m := range lineattest.PackMembers {
		found = found || m == distribution.PackMember
	}
	if !found || upgradepath.PackMember == distribution.PackMember {
		t.Fatal("distribution.PackMember is not a pack member")
	}
}
