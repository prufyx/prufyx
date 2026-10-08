// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/localcollector"
	"github.com/prufyx/prufyx/cli/internal/observation"
)

func TestDecisionPredicateRegistryIsClosedAndNonSecret(t *testing.T) {
	for _, id := range []string{"component.metrics_server.kubernetes_min_minor", "component.metrics_server.metrics_api_group", "component.external_dns.annotation_prefix", "component.external_dns.policy_flag_presence"} {
		if !IsRegisteredPredicate(id) {
			t.Fatalf("expected registered predicate %q", id)
		}
	}
	for _, id := range []string{"component.metrics_server.token", "component.external_dns.credentials"} {
		if IsRegisteredPredicate(id) {
			t.Fatalf("secret predicate registered: %q", id)
		}
	}
}

func TestSyntheticProvenanceIsCanonicalDigestBoundAndReloaded(t *testing.T) {
	root := fixtureRoot(t)
	metadataPath := filepath.Join(root, "demo", "snapshot-metadata.json")
	var metadata map[string]any
	raw, err := os.ReadFile(metadataPath)
	if err != nil || json.Unmarshal(raw, &metadata) != nil {
		t.Fatal("read metadata")
	}
	metadata["syntheticClassification"] = "PUBLIC_SYNTHETIC"
	metadata["syntheticAuthority"] = "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT"
	metadata["syntheticCanary"] = "PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE"
	metadata["syntheticNonAuthoritative"] = true
	writeJSON(t, metadataPath, metadata)
	regenerateManifests(t, root)
	artifact, err := buildTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Bundle.Synthetic == nil || !errors.Is(RejectSyntheticArtifact(artifact), ErrSyntheticEvidence) {
		t.Fatal("synthetic marker was not denied")
	}
	if !bytes.Contains(artifact.Bytes, []byte(`"syntheticProvenance"`)) || !bytes.Contains(artifact.Bytes, []byte("PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE")) {
		t.Fatal("canonical bytes omitted marker")
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteArtifact(path, artifact); err != nil {
		t.Fatal(err)
	}
	reloaded, err := ReadArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Bundle.Synthetic == nil || reloaded.Digest != artifact.Digest || !errors.Is(RejectSyntheticArtifact(reloaded), ErrSyntheticEvidence) {
		t.Fatal("reload detached synthetic provenance")
	}
}

func TestBuildCanonicalSchemaAndPrivacy(t *testing.T) {
	a, err := buildTestPath(t, fixtureRoot(t), Options{CapturedAt: time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC), Now: time.Date(2026, 8, 28, 10, 5, 0, 0, time.UTC), FreshnessPolicy: FreshnessPolicy{ID: "policy-v1", MaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateArtifact(a); err != nil {
		t.Fatal(err)
	}
	if a.Bundle.Assurance.Class != Assurance || a.Bundle.Assurance.EvaluationEligible {
		t.Fatalf("assurance = %#v", a.Bundle.Assurance)
	}
	if a.Bundle.Environment.Kubernetes.Value != "1.33.4" || a.Bundle.Environment.Kubernetes.State != "observed" {
		t.Fatalf("kubernetes = %#v", a.Bundle.Environment.Kubernetes)
	}
	if a.Bundle.Environment.Provider.State != "unknown" || a.Bundle.Environment.ContainerRuntime.State != "unknown" {
		t.Fatalf("missing environment fields were guessed: %#v", a.Bundle.Environment)
	}
	if a.Bundle.Planes.Declared.Status != "not_supplied" || len(a.Bundle.Planes.Declared.Components) != 0 {
		t.Fatalf("declared plane crossed boundary: %#v", a.Bundle.Planes.Declared)
	}
	if a.Bundle.Freshness.State != "fresh" || a.Bundle.Freshness.PolicyID != "policy-v1" {
		t.Fatalf("freshness = %#v", a.Bundle.Freshness)
	}
	if a.Bundle.CapturedAt != "2026-08-28T10:00:00Z" || a.Bundle.BundleDigest == "" {
		t.Fatalf("capture/digest binding = %#v", a.Bundle)
	}
	if a.Disclosure.RawDataRetained || a.Disclosure.SourceCount == 0 {
		t.Fatalf("disclosure = %#v", a.Disclosure)
	}
	if !hasOmission(a.Bundle, "UNSUPPORTED_SURFACES_NOT_PROJECTED") {
		t.Fatal("unsupported source surfaces were not explicit omissions")
	}
	for _, forbidden := range []string{"customer-name", "private.example", "secret-endpoint", "contextHash", "absolutePath", "Secret", "ConfigMap"} {
		if bytes.Contains(a.Bytes, []byte(forbidden)) {
			t.Fatalf("private value %q crossed boundary", forbidden)
		}
	}
}

func TestBuildPartialUnauthorizedObservationPreservesUnknownKubernetes(t *testing.T) {
	root := fixtureRoot(t)
	if err := os.Remove(filepath.Join(root, "demo", "server-version.json")); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "index.json"), map[string]any{
		"schema": "prufyx.io/kubeconfig-api-observation-index/v1alpha1", "generatedAt": "synthetic",
		"contexts": []any{map[string]any{"directory": "demo", "contextHash": "discarded", "collectionStatus": "partial_for_declared_surface", "omissionCount": 0}},
	})
	writeJSON(t, filepath.Join(root, "demo", "snapshot-metadata.json"), map[string]any{
		"schema": "prufyx.io/kubeconfig-api-observation/v1alpha1", "format": "KubeconfigAPIObservation",
		"collectionStatus": "partial_for_declared_surface", "omissionCount": 0,
	})
	regenerateManifests(t, root)
	artifact, err := buildTestPath(t, root, Options{})
	if err != nil {
		t.Fatalf("partial unauthorized observation was rejected: %v", err)
	}
	if artifact.Bundle.Environment.Kubernetes.State != "unknown" || artifact.Bundle.Environment.Kubernetes.Value != "" || !hasOmission(artifact.Bundle, "KUBERNETES_VERSION_UNOBSERVED") {
		t.Fatalf("partial Kubernetes state was not explicit UNKNOWN: %#v", artifact.Bundle.Environment.Kubernetes)
	}
}

func TestBuildFromActualOfflineCollectorOutputs(t *testing.T) {
	for _, mode := range []string{"component-success", "unauthorized", "server-version-boringcrypto", "server-version-clean", "server-version-malicious-suffix", "server-version-malicious-core-suffix", "server-version-malicious-core-suffix-boringcrypto", "server-version-malicious-build-suffix", "server-version-malicious-fourth-segment", "server-version-malicious-boringcrypto-suffix", "server-version-newline", "server-version-nul", "server-version-long"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			kubeconfig := filepath.Join(root, "kubeconfig")
			if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "output")
			for _, name := range testProxyNames {
				t.Setenv(name, "")
			}
			var collectorOut, collectorErr bytes.Buffer
			observationPath, code := (localcollector.Collector{Runner: collectorBridgeRunner{mode: mode}}).Collect(context.Background(), localcollector.Options{
				OutputRoot: output, Kubeconfig: kubeconfig, Contexts: []string{"synthetic-context"}, AcknowledgeExecRisk: true,
				IncludeComponentConfiguration: true, ComponentConfigurationProfile: "v2", AllowPartial: true, Kubectl: os.Args[0],
				ExecEnv: testProxyNames, Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("k", 32)),
			}, &collectorOut, &collectorErr)
			if code != 0 {
				t.Fatalf("offline collector exit=%d stdout=%q stderr=%q", code, collectorOut.String(), collectorErr.String())
			}
			artifact, err := buildTestPath(t, observationPath, Options{})
			invalidGoRuntime := strings.HasPrefix(mode, "server-version-malicious-") || mode == "server-version-newline" || mode == "server-version-nul" || mode == "server-version-long"
			if invalidGoRuntime {
				if !errors.Is(err, observation.ErrInvalid) {
					t.Fatalf("currentbundle error = %v, want observation.ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("currentbundle rejected actual collector output: %v", err)
			}
			if mode == "component-success" {
				foundDeclaredContext := false
				for _, component := range artifact.Bundle.Planes.Observed.Components {
					if component.ComponentID != "pkg:oci/argoproj/argo-workflows" {
						continue
					}
					for _, predicate := range component.Predicates {
						if predicate.ID == "component.argo_workflows.managed_namespace_configured" && predicate.SourceRole == "workflow-controller" && predicate.EvidenceClass == "declared_container_context_v1" && bytes.Equal(predicate.Value, []byte("true")) {
							foundDeclaredContext = true
						}
					}
				}
				if !foundDeclaredContext || bytes.Contains(artifact.Bytes, []byte("synthetic-workflow-controller")) || bytes.Contains(artifact.Bytes, []byte("--managed-namespace")) {
					t.Fatal("collector-shaped declared context was lost or retained a raw workload/argument value")
				}
			}
			if mode == "unauthorized" && artifact.Bundle.Environment.Kubernetes.State != "unknown" {
				t.Fatalf("unauthorized collector output did not remain unknown: %#v", artifact.Bundle.Environment.Kubernetes)
			}
		})
	}
}

var testProxyNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}

type collectorBridgeRunner struct{ mode string }

func (r collectorBridgeRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (localcollector.CommandResult, error) {
	if r.mode == "unauthorized" {
		return localcollector.CommandResult{Exit: 42, Class: "unauthorized"}, nil
	}
	joined := strings.Join(argv, " ")
	var value any = map[string]any{"items": []any{}}
	if strings.Contains(joined, "--raw=/version") {
		goVersion := map[string]string{
			"server-version-boringcrypto": "go1.25.11 X:boringcrypto", "server-version-clean": "go1.25.11",
			"server-version-malicious-suffix": "go1.25.11 X:evil", "server-version-malicious-core-suffix": "go1.25.11evil",
			"server-version-malicious-core-suffix-boringcrypto": "go1.25.11evil X:boringcrypto", "server-version-malicious-build-suffix": "go1.25.11+evil",
			"server-version-malicious-fourth-segment": "go1.25.11.4", "server-version-malicious-boringcrypto-suffix": "go1.25.11 X:boringcrypto:evil",
			"server-version-newline": "go1.25.11\nX:boringcrypto", "server-version-nul": "go1.25.11\x00X:boringcrypto",
		}[r.mode]
		if r.mode == "server-version-long" {
			goVersion = "go1.25.11" + strings.Repeat("a", 4096)
		}
		if goVersion == "" {
			goVersion = "go1.24"
		}
		value = map[string]any{"gitVersion": "v1.34.0", "goVersion": goVersion, "compiler": "gc", "platform": "linux/amd64"}
	} else if strings.Contains(joined, "--raw=/api") {
		if strings.Contains(joined, "customresourcedefinitions") {
			value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
		} else if strings.Contains(joined, "--raw=/apis") {
			value = map[string]any{"groups": []any{}}
		} else {
			value = map[string]any{"versions": []any{"v1"}}
		}
	} else if r.mode == "component-success" && strings.Contains(joined, "get deployments.apps") {
		container := map[string]any{"image": "quay.io/argoproj/workflow-controller:v4.1.2", "args": []any{"--managed-namespace=customer-secret"}}
		value = bridgeWorkload(container)
	}
	raw, _ := json.Marshal(value)
	return localcollector.CommandResult{Stdout: raw, Exit: 0}, nil
}

func bridgeWorkload(container map[string]any) any {
	podSpec := map[string]any{"containers": []any{container}, "initContainers": []any{}}
	template := map[string]any{"spec": podSpec}
	item := map[string]any{"kind": "Deployment", "spec": map[string]any{"template": template}}
	return map[string]any{"items": []any{item}}
}

func TestBuildCanonicalizesKubernetesVendorBuildVersion(t *testing.T) {
	root := fixtureRoot(t)
	writeJSON(t, filepath.Join(root, "demo", "server-version.json"), map[string]any{"gitVersion": "v1.35.6-gke.1710000"})
	regenerateManifests(t, root)
	artifact, err := buildTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := artifact.Bundle.Environment.Kubernetes.Value; got != "1.35.6" {
		t.Fatalf("Kubernetes environment = %q, want canonical core 1.35.6", got)
	}
}

func TestCertManagerProjectionDigestBindsPersistedAdapter(t *testing.T) {
	root := fixtureRoot(t)
	const projectionDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	path := filepath.Join(root, "demo", "component-configuration-surface.json")
	var surface map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &surface); err != nil {
		t.Fatal(err)
	}
	surface["metadata"] = map[string]any{"certManagerProjectionDigest": projectionDigest}
	surface["licenseCopyrightDisposition"] = "metadata_only_derived_predicates"
	surface["omissions"] = []any{map[string]any{"code": "COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE", "reason": "synthetic bounded reason", "requiredForEvaluation": true, "sourceFile": "cert-manager-health.json", "count": 2}}
	writeJSON(t, path, surface)
	regenerateManifests(t, root)
	artifact, err := buildTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAdapter(artifact.Bundle.Adapters, "cert-manager-projection", projectionDigest) {
		t.Fatalf("cert-manager projection adapter binding missing: %#v", artifact.Bundle.Adapters)
	}
	if len(artifact.Bundle.Omissions) == 0 || artifact.Bundle.Omissions[0].Reason != "synthetic bounded reason" || artifact.Bundle.Omissions[0].Count != 2 {
		t.Fatalf("omission provenance was dropped: %#v", artifact.Bundle.Omissions)
	}
	if err := ValidateArtifact(artifact); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalPermutationAndCallerImmutability(t *testing.T) {
	b := CurrentBundle{
		APIVersion: APIVersion, Kind: Kind, Schema: Schema, BundleDigest: "stale", Revision: "r",
		Target: TargetIdentity{Fingerprint: "r", State: "exact"}, Assurance: AssuranceState{Class: Assurance},
		Planes: EvidencePlanes{
			Observed: EvidencePlane{Components: []CanonicalComponent{
				{ComponentID: "z", Roles: []string{"b", "a"}, Predicates: []CanonicalPredicate{{ID: "p", Value: json.RawMessage(`false`)}}},
				{ComponentID: "a", Roles: []string{"z", "a"}},
			}},
			Declared: EvidencePlane{Status: "not_supplied"}, Derived: EvidencePlane{Status: "not_derived"},
		},
		Sources: []SourceBinding{{Digest: "sha256:2", PathClass: "x"}, {Digest: "sha256:1", PathClass: "x"}},
	}
	original := b.Planes.Observed.Components[0].Roles[0]
	first, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if b.BundleDigest != "stale" || b.Planes.Observed.Components[0].Roles[0] != original {
		t.Fatal("Marshal mutated caller")
	}
	b.Planes.Observed.Components[0], b.Planes.Observed.Components[1] = b.Planes.Observed.Components[1], b.Planes.Observed.Components[0]
	second, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("permutation changed canonical bytes")
	}
	d1, _ := Digest(b)
	b.BundleDigest = "other"
	d2, _ := Digest(b)
	if d1 != d2 {
		t.Fatal("bundleDigest affected content digest")
	}
	if bytes.Contains(first, []byte(`"bundleDigest":"stale"`)) == false {
		t.Fatal("full canonical bytes unexpectedly omitted supplied bundle digest")
	}
}

func TestBuildMixedVersionUnknownAndFreshnessUnknown(t *testing.T) {
	root := fixtureRoot(t)
	writeJSON(t, filepath.Join(root, "demo", "statefulset-images.json"), []map[string]any{{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.7", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}})
	regenerateManifests(t, root)
	bundle, err := importTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Freshness.State != "unknown" {
		t.Fatalf("default freshness = %#v", bundle.Freshness)
	}
	for _, c := range bundle.Planes.Observed.Components {
		if c.ComponentID == "pkg:oci/argoproj/argo-cd" && (c.Version.State != "conflict" || c.Version.Value != "") {
			t.Fatalf("version guessed: %#v", c.Version)
		}
	}
	if !hasConflict(bundle, "pkg:oci/argoproj/argo-cd") {
		t.Fatal("mixed version conflict was not explicit")
	}
}

func TestFreshnessIsPolicyDriven(t *testing.T) {
	root := fixtureRoot(t)
	options := Options{CapturedAt: time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC), Now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), FreshnessPolicy: FreshnessPolicy{ID: "policy-v1", MaxAge: time.Hour}}
	bundle, err := importTestPath(t, root, options)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Freshness.State != "stale" {
		t.Fatalf("freshness = %#v", bundle.Freshness)
	}
}

func TestArtifactPersistenceAndLossyProjection(t *testing.T) {
	a, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteArtifact(path, a); err != nil {
		t.Fatal(err)
	}
	got, err := ReadArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes, a.Bytes) || got.Digest != a.Digest {
		t.Fatal("persisted artifact changed")
	}
	p, err := ToEvaluationProjection(got.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Components) == 0 || p.Components[0].SourceDigests == nil {
		t.Fatal("lossy projection lost component provenance")
	}
}

func TestReadArtifactRejectsDuplicateKeysAndInvalidUTF8(t *testing.T) {
	a, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{
			name: "duplicate root key",
			data: func() []byte {
				insert := []byte(`"apiVersion":"prufyx.io/current-bundle/v1alpha1",`)
				at := bytes.IndexByte(a.Bytes, '{') + 1
				return append(append(append([]byte(nil), a.Bytes[:at]...), insert...), a.Bytes[at:]...)
			}(),
			want: ErrIntegrity,
		},
		{
			name: "duplicate nested key",
			data: func() []byte {
				needle := []byte(`"target":{`)
				at := bytes.Index(a.Bytes, needle)
				if at < 0 {
					t.Fatal("target object missing from valid artifact")
				}
				at += len(needle)
				insert := []byte(`"state":"exact",`)
				return append(append(append([]byte(nil), a.Bytes[:at]...), insert...), a.Bytes[at:]...)
			}(),
			want: ErrIntegrity,
		},
		{
			name: "invalid UTF-8",
			data: append(append([]byte(nil), a.Bytes...), 0xff),
			want: ErrInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadArtifact(path); !errors.Is(err, tc.want) {
				t.Fatalf("ReadArtifact error=%v, want errors.Is(%v)", err, tc.want)
			}
		})
	}
}

func TestValidateArtifactRejectsUnknownRegistryAndNonCanonicalScalar(t *testing.T) {
	a, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Bundle.Planes.Observed.Components[0].Predicates[0].ID = "component.unknown.value"
	if err := ValidateArtifact(a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown predicate error = %v", err)
	}
	a, err = buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Bundle.Planes.Observed.Components[0].Predicates[0].Value = json.RawMessage(` true `)
	if err := ValidateArtifact(a); !errors.Is(err, ErrIntegrity) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("noncanonical scalar error = %v", err)
	}
}

func TestValidateArtifactAdversarialBindingsAndOrdering(t *testing.T) {
	base, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Artifact)
		want   error
	}{
		{"empty component digest", func(a *Artifact) { a.Bundle.Planes.Observed.Components[0].Sources[0].Digest = "" }, ErrIntegrity},
		{"empty predicate digest", func(a *Artifact) { a.Bundle.Planes.Observed.Components[0].Predicates[0].Sources[0].Digest = "" }, ErrIntegrity},
		{"omission source on observed field", func(a *Artifact) {
			a.Bundle.Environment.Kubernetes.Source[0].PathClass = "omission:PROVIDER_UNOBSERVED"
			a.Bundle.Environment.Kubernetes.Source[0].Digest = ""
		}, ErrIntegrity},
		{"noncanonical field sources", func(a *Artifact) {
			first := SourceRef{PathClass: "context/projection", Digest: a.Bundle.Sources[1].Digest}
			a.Bundle.Environment.Kubernetes.Source = []SourceRef{first, a.Bundle.Environment.Kubernetes.Source[0]}
		}, ErrIntegrity},
		{"noncanonical conflict values", func(a *Artifact) {
			a.Bundle.Conflicts = []Conflict{{ComponentID: a.Bundle.Planes.Observed.Components[0].ComponentID, Kind: "version_or_predicate", Values: []string{"3.4.6", "1.0.0"}}}
		}, ErrIntegrity},
		{"unlinked unknown", func(a *Artifact) {
			a.Bundle.Planes.Unknown.Components = []UnknownValue{{ComponentID: "pkg:oci/prometheus/prometheus", Reasons: []string{"VERSION_NOT_EXACT"}}}
		}, ErrIntegrity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			a.Bundle = cloneBundle(base.Bundle)
			tc.mutate(&a)
			if err := ValidateArtifact(a); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateArtifactCountsEnvironmentReferences(t *testing.T) {
	a, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	const sourceCount = 2048
	digests := make([]string, sourceCount)
	a.Bundle.Sources = make([]SourceBinding, sourceCount)
	for i := range a.Bundle.Sources {
		digests[i] = DigestBytes([]byte(fmt.Sprintf("synthetic-source-%d", i)))
		a.Bundle.Sources[i] = SourceBinding{PathClass: "context/projection", Digest: digests[i]}
	}
	sort.Strings(digests)
	revisionBytes, _ := json.Marshal(digests)
	a.Bundle.Revision = DigestBytes(revisionBytes)
	a.Bundle.Target.Fingerprint = a.Bundle.Revision
	refList := sourceRefs(digests)
	a.Bundle.Environment.Provider.Source = refList
	a.Bundle.Environment.Distribution.Source = refList
	a.Bundle.Environment.Kubernetes.Source = refList
	a.Bundle.Environment.NodeOS.Source = refList
	a.Bundle.Environment.Kernel.Source = refList
	a.Bundle.Environment.Architecture.Source = refList
	a.Bundle.Environment.ContainerRuntime.Source = refList
	for i := range a.Bundle.Planes.Observed.Components {
		a.Bundle.Planes.Observed.Components[i].Sources = []SourceRef{refList[0]}
		for j := range a.Bundle.Planes.Observed.Components[i].Predicates {
			a.Bundle.Planes.Observed.Components[i].Predicates[j].Sources = []SourceRef{refList[0]}
		}
	}
	for i := range a.Bundle.Omissions {
		a.Bundle.Omissions[i].Sources = []string{digests[0]}
	}
	if err := ValidateArtifact(a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestToEvaluationProjectionRejectsLossyUnknowns(t *testing.T) {
	root := fixtureRoot(t)
	writeJSON(t, filepath.Join(root, "demo", "statefulset-images.json"), []map[string]any{{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.7", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}})
	regenerateManifests(t, root)
	bundle, err := importTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ToEvaluationProjection(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func hasOmission(bundle CurrentBundle, code string) bool {
	for _, omission := range bundle.Omissions {
		if omission.Code == code {
			return true
		}
	}
	return false
}

func hasConflict(bundle CurrentBundle, id string) bool {
	for _, conflict := range bundle.Conflicts {
		if conflict.ComponentID == id {
			return true
		}
	}
	return false
}

func TestBuildRejectsTamperTraversalSymlinkHardlinkDuplicateOversizeAndPrivate(t *testing.T) {
	t.Run("tamper", func(t *testing.T) {
		root := fixtureRoot(t)
		os.WriteFile(filepath.Join(root, "demo", "server-version.json"), []byte(`{"gitVersion":"v1.33.5"}`), 0o600)
		if _, err := buildTestPath(t, root, Options{}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("traversal", func(t *testing.T) {
		root := fixtureRoot(t)
		os.WriteFile(filepath.Join(root, "demo", "unexpected.json"), []byte(`{}`), 0o600)
		if _, err := buildTestPath(t, root, Options{}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := fixtureRoot(t)
		p := filepath.Join(root, "demo", "server-version.json")
		out := filepath.Join(t.TempDir(), "out")
		os.WriteFile(out, []byte(`{"gitVersion":"v1.33.4"}`), 0o600)
		os.Remove(p)
		os.Symlink(out, p)
		if _, err := buildTestPath(t, root, Options{}); err == nil {
			t.Fatal("accepted symlink")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		root := fixtureRoot(t)
		p := filepath.Join(root, "demo", "server-version.json")
		out := filepath.Join(t.TempDir(), "out")
		os.WriteFile(out, []byte(`{"gitVersion":"v1.33.4"}`), 0o600)
		os.Remove(p)
		if err := os.Link(out, p); err != nil {
			t.Skip(err)
		}
		if _, err := buildTestPath(t, root, Options{}); err == nil {
			t.Fatal("accepted hardlink")
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		root := fixtureRoot(t)
		os.WriteFile(filepath.Join(root, "demo", "server-version.json"), []byte(`{"gitVersion":"v1.33.4","gitVersion":"v1.33.4"}`), 0o600)
		regenerateManifests(t, root)
		if _, err := buildTestPath(t, root, Options{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		root := fixtureRoot(t)
		for i := 0; i < 4097; i++ {
			os.WriteFile(filepath.Join(root, "demo", fmt.Sprintf("extra-%04d", i)), []byte("x"), 0o600)
		}
		if _, err := buildTestPath(t, root, Options{}); err == nil {
			t.Fatal("accepted oversized tree")
		}
	})
	t.Run("private", func(t *testing.T) {
		root := fixtureRoot(t)
		os.WriteFile(filepath.Join(root, "demo", "component-configuration-surface.json"), []byte(`{"apiVersion":"prufyx.io/configuration-surface/v1alpha1","kind":"ComponentConfigurationSurface","components":[],"omissions":[],"secret":"secret-endpoint"}`), 0o600)
		regenerateManifests(t, root)
		if _, err := buildTestPath(t, root, Options{}); err == nil {
			t.Fatal("accepted private field")
		}
	})
}

func BenchmarkBuild(b *testing.B) {
	root := fixtureRoot(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := buildTestPath(b, root, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func fixtureRoot(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	ctx := filepath.Join(root, "demo")
	if err := os.MkdirAll(ctx, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "index.json"), map[string]any{"schema": "prufyx.io/kubeconfig-api-observation-index/v1alpha1", "generatedAt": "synthetic", "contexts": []any{map[string]any{"directory": "demo", "contextHash": "discarded", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0}}})
	writeJSON(t, filepath.Join(ctx, "snapshot-metadata.json"), map[string]any{"schema": "prufyx.io/kubeconfig-api-observation/v1alpha1", "format": "KubeconfigAPIObservation", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0})
	writeJSON(t, filepath.Join(ctx, "server-version.json"), map[string]any{"gitVersion": "v1.33.4"})
	writeJSON(t, filepath.Join(ctx, "deployment-images.json"), []map[string]any{{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.6", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}})
	writeJSON(t, filepath.Join(ctx, "component-configuration-surface.json"), map[string]any{"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface", "components": []any{map[string]any{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.6", "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false, "predicates": map[string]any{"component.argo_cd.insecure_server_enabled": false}}}, "omissions": []any{}})
	if err := os.WriteFile(filepath.Join(ctx, "omissions.tsv"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	regenerateManifests(t, root)
	return root
}

func writeJSON(t testing.TB, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func regenerateManifests(t testing.TB, root string) {
	t.Helper()
	writeManifest(t, filepath.Join(root, "demo"), filepath.Join(root, "demo", "MANIFEST.sha256"))
	writeManifest(t, root, filepath.Join(root, "MANIFEST.sha256"))
}
func writeManifest(t testing.TB, base, manifest string) {
	t.Helper()
	var paths []string
	if err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Clean(path) == filepath.Clean(manifest) {
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var out strings.Builder
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		out.WriteString(hex.EncodeToString(sum[:]) + "  ./" + rel + "\n")
	}
	if err := os.WriteFile(manifest, []byte(out.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
