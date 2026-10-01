// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/observation"
)

func TestCurrentBundle_ProducerV3PrometheusIdentity_UsesRegistryV2AndAdapterV3(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version, imageDigest string
		agentMode                  bool
	}{
		{name: "prometheus-2.55.1-agent", version: "2.55.1", imageDigest: mustPrometheusDigest("2.55.1"), agentMode: true},
		{name: "prometheus-3.1.0-server", version: "3.1.0", imageDigest: mustPrometheusDigest("3.1.0"), agentMode: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := fixtureRoot(t)
			writeCurrentBundleProducerV3(t, root, tc.version, tc.imageDigest, tc.agentMode)
			artifact, err := buildTestPath(t, root, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Bundle.PredicateRegistryVersion != PredicateRegistryVersionV2 || !containsAdapter(artifact.Bundle.Adapters, "observation-to-current-bundle", currentBundleAdapterV3) {
				t.Fatalf("v3 authority binding missing: registry=%q adapters=%#v", artifact.Bundle.PredicateRegistryVersion, artifact.Bundle.Adapters)
			}
			component := findCanonicalComponent(t, artifact.Bundle, prometheusID)
			mode := findCanonicalPredicate(t, component, prometheusAgentModePredicate)
			image := findCanonicalPredicate(t, component, prometheusImageDigestPredicate)
			if mode.SourceRole != "server" || image.SourceRole != "server" || mode.EvidenceClass != "declared_container_context_v1" || image.EvidenceClass != "declared_container_context_v1" {
				t.Fatalf("declared source binding missing: mode=%#v image=%#v", mode, image)
			}
			if string(mode.Value) != boolJSON(tc.agentMode) || string(image.Value) != `"`+tc.imageDigest+`"` {
				t.Fatalf("predicate values = %s, %s", mode.Value, image.Value)
			}
			if err := ValidateArtifact(artifact); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCurrentBundle_ProducerV3PrometheusIdentity_RejectsCanonicalMutations(t *testing.T) {
	t.Parallel()
	root := fixtureRoot(t)
	writeCurrentBundleProducerV3(t, root, "3.1.0", mustPrometheusDigest("3.1.0"), true)
	artifact, err := buildTestPath(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*CurrentBundle)
	}{
		{name: "forged-old-registry-and-adapter", mutate: func(bundle *CurrentBundle) {
			bundle.PredicateRegistryVersion = PredicateRegistryVersion
			setObservationAdapter(bundle, currentBundleAdapterV2)
		}},
		{name: "registry-adapter-mismatch", mutate: func(bundle *CurrentBundle) {
			setObservationAdapter(bundle, currentBundleAdapterV2)
		}},
		{name: "component-swap", mutate: func(bundle *CurrentBundle) {
			component := mutableCanonicalComponent(t, bundle, prometheusID)
			component.ComponentID = "pkg:oci/argoproj/argo-workflows"
			component.Artifact.Value = component.ComponentID
		}},
		{name: "role-swap", mutate: func(bundle *CurrentBundle) {
			component := mutableCanonicalComponent(t, bundle, prometheusID)
			component.Roles = []string{"controller"}
			for i := range component.Predicates {
				component.Predicates[i].SourceRole = "controller"
			}
		}},
		{name: "version-digest-swap", mutate: func(bundle *CurrentBundle) {
			mutableCanonicalComponent(t, bundle, prometheusID).Version.Value = "2.55.1"
		}},
		{name: "unapproved-image-digest", mutate: func(bundle *CurrentBundle) {
			component := mutableCanonicalComponent(t, bundle, prometheusID)
			mutableCanonicalPredicate(t, component, prometheusImageDigestPredicate).Value = json.RawMessage(`"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
		}},
		{name: "missing-image-pair", mutate: func(bundle *CurrentBundle) {
			component := mutableCanonicalComponent(t, bundle, prometheusID)
			filtered := component.Predicates[:0]
			for _, predicate := range component.Predicates {
				if predicate.ID != prometheusImageDigestPredicate {
					filtered = append(filtered, predicate)
				}
			}
			component.Predicates = filtered
		}},
		{name: "different-source-row", mutate: func(bundle *CurrentBundle) {
			component := mutableCanonicalComponent(t, bundle, prometheusID)
			image := mutableCanonicalPredicate(t, component, prometheusImageDigestPredicate)
			for _, source := range bundle.Sources {
				if source.Digest != image.Sources[0].Digest {
					image.Sources = []SourceRef{{PathClass: source.PathClass, Digest: source.Digest}}
					return
				}
			}
			panic("fixture needs a distinct bound source")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundle := cloneBundle(artifact.Bundle)
			tc.mutate(&bundle)
			if err := validateBundle(bundle); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("mutation error = %v, want invalid or integrity rejection", err)
			}
		})
	}
}

func TestCurrentBundle_OldProducerPreservesRegistryV1AndAdapterV2(t *testing.T) {
	t.Parallel()
	artifact, err := buildTestPath(t, fixtureRoot(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Bundle.PredicateRegistryVersion != PredicateRegistryVersion || !containsAdapter(artifact.Bundle.Adapters, "observation-to-current-bundle", currentBundleAdapterV2) {
		t.Fatalf("old producer output changed: registry=%q adapters=%#v", artifact.Bundle.PredicateRegistryVersion, artifact.Bundle.Adapters)
	}
	if IsRegisteredPredicate(prometheusAgentModePredicate) == false || IsRegisteredPredicate(prometheusImageDigestPredicate) == false {
		t.Fatal("new closed predicates are not registered")
	}
	for _, component := range artifact.Bundle.Planes.Observed.Components {
		for _, predicate := range component.Predicates {
			if predicate.ID == prometheusAgentModePredicate || predicate.ID == prometheusImageDigestPredicate {
				t.Fatal("old producer gained producer-v3 predicates")
			}
		}
	}
}

func writeCurrentBundleProducerV3(t *testing.T, root, version, imageDigest string, agentMode bool) {
	t.Helper()
	ctx := filepath.Join(root, "demo")
	d := func(value byte) string { return "sha256:" + string(repeatByte(value, 64)) }
	metadata := map[string]any{
		"schemaVersion": "1.1.0", "adapterVersion": configurationAdapterV3, "registryVersion": "v3",
		"registryDigest": d('a'), "filterDigest": d('b'), "aggregateDigest": d('c'), "strictJsonDigest": d('d'),
		"kubectlStderrClassifierDigest": d('e'), "kubectlBoundedRunnerDigest": d('f'),
		"kubectlStderrClassifierTaxonomyVersion": "kubectl-stderr-taxonomy-v1", "kubectlStderrClassifierAuthority": "heuristic_local_diagnostic_not_proof",
	}
	writeJSON(t, filepath.Join(ctx, "snapshot-metadata.json"), map[string]any{
		"schema": observation.ObservationSchema, "format": "KubeconfigAPIObservation", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0,
		"includeComponentConfiguration": true, "componentConfigurationAdapterVersion": configurationAdapterV3, "componentConfigurationRegistryVersion": "v3",
		"componentConfigurationRegistryDigest": d('a'), "componentConfigurationFilterDigest": d('b'), "componentConfigurationAggregateDigest": d('c'), "componentConfigurationStrictJsonDigest": d('d'),
	})
	writeJSON(t, filepath.Join(ctx, "component-configuration-surface.json"), map[string]any{
		"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface", "metadata": metadata,
		"components": []any{map[string]any{
			"componentId": prometheusID, "observedVersion": version, "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false,
			"roles": []any{"server"}, "predicates": map[string]any{prometheusAgentModePredicate: agentMode, prometheusImageDigestPredicate: imageDigest},
			"predicateEvidence": []any{
				map[string]any{"predicateId": prometheusAgentModePredicate, "state": "observed", "sourceRole": "server", "evidenceClass": "declared_container_context_v1"},
				map[string]any{"predicateId": prometheusImageDigestPredicate, "state": "observed", "sourceRole": "server", "evidenceClass": "declared_container_context_v1"},
			},
		}},
		"omissions": []any{}, "licenseCopyrightDisposition": "metadata_only_derived_predicates",
	})
	writeJSON(t, filepath.Join(ctx, "statefulset-images.json"), []map[string]any{{"componentId": prometheusID, "observedVersion": version, "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}})
	regenerateManifests(t, root)
}

func mustPrometheusDigest(version string) string {
	digest, ok := observation.ApprovedPrometheusImageDigest(version)
	if !ok {
		panic("unapproved test version")
	}
	return digest
}

func repeatByte(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func findCanonicalComponent(t *testing.T, bundle CurrentBundle, id string) CanonicalComponent {
	t.Helper()
	for _, component := range bundle.Planes.Observed.Components {
		if component.ComponentID == id {
			return component
		}
	}
	t.Fatalf("component %q not found", id)
	return CanonicalComponent{}
}

func mutableCanonicalComponent(t *testing.T, bundle *CurrentBundle, id string) *CanonicalComponent {
	t.Helper()
	for i := range bundle.Planes.Observed.Components {
		if bundle.Planes.Observed.Components[i].ComponentID == id {
			return &bundle.Planes.Observed.Components[i]
		}
	}
	t.Fatalf("component %q not found", id)
	return nil
}

func findCanonicalPredicate(t *testing.T, component CanonicalComponent, id string) CanonicalPredicate {
	t.Helper()
	for _, predicate := range component.Predicates {
		if predicate.ID == id {
			return predicate
		}
	}
	t.Fatalf("predicate %q not found", id)
	return CanonicalPredicate{}
}

func mutableCanonicalPredicate(t *testing.T, component *CanonicalComponent, id string) *CanonicalPredicate {
	t.Helper()
	for i := range component.Predicates {
		if component.Predicates[i].ID == id {
			return &component.Predicates[i]
		}
	}
	t.Fatalf("predicate %q not found", id)
	return nil
}

func setObservationAdapter(bundle *CurrentBundle, version string) {
	for i := range bundle.Adapters {
		if bundle.Adapters[i].Name == "observation-to-current-bundle" {
			bundle.Adapters[i].Version = version
		}
	}
}
