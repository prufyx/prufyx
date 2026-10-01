// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	prometheus255Digest = "sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
	prometheus310Digest = "sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2"
)

func TestImport_ProducerV3PrometheusIdentity_IsVersionRoleAndEvidenceBound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version, imageDigest string
		agentMode                  bool
	}{
		{name: "prometheus-2.55.1-agent", version: "2.55.1", imageDigest: prometheus255Digest, agentMode: true},
		{name: "prometheus-3.1.0-server", version: "3.1.0", imageDigest: prometheus310Digest, agentMode: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := syntheticRoot(t)
			writeProducerV3Observation(t, root, tc.version, tc.imageDigest, tc.agentMode, prometheusID, "server", true)
			bundle, err := importTestPath(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if bundle.ConfigurationAdapterVersion != configurationAdapterV3 {
				t.Fatalf("ConfigurationAdapterVersion = %q", bundle.ConfigurationAdapterVersion)
			}
			var foundMode, foundDigest bool
			for _, component := range bundle.Components {
				if component.ComponentID != prometheusID {
					continue
				}
				for _, predicate := range component.Predicates {
					switch predicate.ID {
					case prometheusAgentModePredicate:
						foundMode = predicate.State == "observed" && predicate.Role == "server" && predicate.EvidenceClass == "declared_container_context_v1" && string(predicate.Value) == jsonBool(tc.agentMode)
					case prometheusImageDigestPredicate:
						foundDigest = predicate.State == "observed" && predicate.Role == "server" && predicate.EvidenceClass == "declared_container_context_v1" && string(predicate.Value) == `"`+tc.imageDigest+`"`
					}
				}
			}
			if !foundMode || !foundDigest {
				t.Fatalf("producer-v3 predicates missing or unbound: %#v", bundle.Components)
			}
			data, err := Marshal(bundle)
			if err != nil || json.Valid(data) == false {
				t.Fatalf("marshal = %q, %v", data, err)
			}
			if string(data) == "" || containsJSONField(data, "ConfigurationAdapterVersion") || containsJSONField(data, "configurationAdapterVersion") {
				t.Fatalf("internal producer identity leaked into public JSON: %s", data)
			}
		})
	}
}

func TestImport_ProducerV3PrometheusIdentity_RejectsAuthorityMutations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		version     string
		imageDigest string
		componentID string
		role        string
		evidence    bool
		mutate      func(map[string]any, map[string]any)
	}{
		{name: "unsupported-version", version: "3.1.1", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true},
		{name: "version-digest-swap", version: "2.55.1", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true},
		{name: "component-swap", version: "3.1.0", imageDigest: prometheus310Digest, componentID: "pkg:oci/argoproj/argo-workflows", role: "server", evidence: true},
		{name: "role-swap", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "controller", evidence: true},
		{name: "missing-same-row-evidence", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: false},
		{name: "old-producer", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true, mutate: func(surface, snapshot map[string]any) {
			metadata := surface["metadata"].(map[string]any)
			metadata["schemaVersion"], metadata["adapterVersion"], metadata["registryVersion"] = "1.0.0", configurationAdapterV2, "v2"
			snapshot["componentConfigurationAdapterVersion"], snapshot["componentConfigurationRegistryVersion"] = configurationAdapterV2, "v2"
		}},
		{name: "wrong-v3-schema", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true, mutate: func(surface, _ map[string]any) {
			surface["metadata"].(map[string]any)["schemaVersion"] = "1.0.0"
		}},
		{name: "wrong-version-scheme", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true, mutate: func(surface, _ map[string]any) {
			surface["components"].([]any)[0].(map[string]any)["versionScheme"] = "digest"
		}},
		{name: "collection-profile-not-enabled", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true, mutate: func(_ map[string]any, snapshot map[string]any) {
			snapshot["includeComponentConfiguration"] = false
		}},
		{name: "snapshot-surface-digest-mismatch", version: "3.1.0", imageDigest: prometheus310Digest, componentID: prometheusID, role: "server", evidence: true, mutate: func(_ map[string]any, snapshot map[string]any) {
			snapshot["componentConfigurationRegistryDigest"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := syntheticRoot(t)
			surface, snapshot := producerV3Documents(tc.version, tc.imageDigest, true, tc.componentID, tc.role, tc.evidence)
			if tc.mutate != nil {
				tc.mutate(surface, snapshot)
			}
			writeProducerV3Documents(t, root, tc.version, surface, snapshot)
			_, err := importTestPath(t, root)
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("mutation error = %v, want invalid or integrity rejection", err)
			}
		})
	}
}

func TestImport_ProducerV3PrometheusIdentity_RejectsMissingOrDuplicateSurface(t *testing.T) {
	t.Parallel()
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		root := syntheticRoot(t)
		surface, snapshot := producerV3Documents("3.1.0", prometheus310Digest, true, prometheusID, "server", true)
		writeProducerV3Documents(t, root, "3.1.0", surface, snapshot)
		if err := os.Remove(filepath.Join(root, "demo", "component-configuration-surface.json")); err != nil {
			t.Fatal(err)
		}
		regenerateManifests(t, root)
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v, want ErrIntegrity", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()
		root := syntheticRoot(t)
		surface, snapshot := producerV3Documents("3.1.0", prometheus310Digest, true, prometheusID, "server", true)
		writeProducerV3Documents(t, root, "3.1.0", surface, snapshot)
		alternate := filepath.Join(root, "demo", "alternate")
		if err := os.Mkdir(alternate, 0o700); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, filepath.Join(alternate, "component-configuration-surface.json"), surface)
		regenerateManifests(t, root)
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v, want ErrIntegrity", err)
		}
	})
}

func TestImport_ProducerV3ConfigurationOmissionSource_IsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, code, source string
		wantErr            bool
	}{
		{name: "aggregate ambiguity", code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", source: "component-configuration-aggregate"},
		{name: "cert-manager projection", code: "COMPONENT_CONFIGURATION_API_UNAVAILABLE", source: "cert-manager-derived-predicates"},
		{name: "wrong aggregate code", code: "COMPONENT_CONFIGURATION_API_UNAVAILABLE", source: "component-configuration-aggregate", wantErr: true},
		{name: "unknown sentinel", code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", source: "component-configuration-other", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := syntheticRoot(t)
			surface, snapshot := producerV3Documents("3.1.0", prometheus310Digest, true, prometheusID, "server", true)
			surface["omissions"] = []any{map[string]any{
				"code": tc.code, "reason": "Bounded synthetic omission.", "requiredForEvaluation": true,
				"sourceFile": tc.source, "count": 1,
			}}
			writeProducerV3Documents(t, root, "3.1.0", surface, snapshot)
			_, err := importTestPath(t, root)
			if tc.wantErr && !errors.Is(err, ErrInvalid) || !tc.wantErr && err != nil {
				t.Fatalf("error = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func writeProducerV3Observation(t *testing.T, root, version, imageDigest string, agentMode bool, componentID, role string, evidence bool) {
	t.Helper()
	surface, snapshot := producerV3Documents(version, imageDigest, agentMode, componentID, role, evidence)
	writeProducerV3Documents(t, root, version, surface, snapshot)
}

func producerV3Documents(version, imageDigest string, agentMode bool, componentID, role string, evidence bool) (map[string]any, map[string]any) {
	metadata := map[string]any{
		"schemaVersion": "1.1.0", "adapterVersion": configurationAdapterV3, "registryVersion": "v3",
		"registryDigest": digestLiteral('a'), "filterDigest": digestLiteral('b'), "aggregateDigest": digestLiteral('c'), "strictJsonDigest": digestLiteral('d'),
		"kubectlStderrClassifierDigest": digestLiteral('e'), "kubectlBoundedRunnerDigest": digestLiteral('f'),
		"kubectlStderrClassifierTaxonomyVersion": "kubectl-stderr-taxonomy-v1", "kubectlStderrClassifierAuthority": "heuristic_local_diagnostic_not_proof",
	}
	predicateEvidence := []any{}
	if evidence {
		predicateEvidence = []any{
			map[string]any{"predicateId": prometheusAgentModePredicate, "state": "observed", "sourceRole": role, "evidenceClass": "declared_container_context_v1"},
			map[string]any{"predicateId": prometheusImageDigestPredicate, "state": "observed", "sourceRole": role, "evidenceClass": "declared_container_context_v1"},
		}
	}
	surface := map[string]any{
		"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface", "metadata": metadata,
		"components": []any{map[string]any{
			"componentId": componentID, "observedVersion": version, "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false,
			"roles": []any{role}, "predicates": map[string]any{prometheusAgentModePredicate: agentMode, prometheusImageDigestPredicate: imageDigest}, "predicateEvidence": predicateEvidence,
		}},
		"omissions": []any{}, "licenseCopyrightDisposition": "metadata_only_derived_predicates",
	}
	snapshot := map[string]any{
		"schema": ObservationSchema, "format": "KubeconfigAPIObservation", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0,
		"includeComponentConfiguration": true, "componentConfigurationAdapterVersion": configurationAdapterV3, "componentConfigurationRegistryVersion": "v3",
		"componentConfigurationRegistryDigest": digestLiteral('a'), "componentConfigurationFilterDigest": digestLiteral('b'), "componentConfigurationAggregateDigest": digestLiteral('c'), "componentConfigurationStrictJsonDigest": digestLiteral('d'),
	}
	return surface, snapshot
}

func writeProducerV3Documents(t *testing.T, root, version string, surface, snapshot map[string]any) {
	t.Helper()
	ctx := filepath.Join(root, "demo")
	writeJSON(t, filepath.Join(ctx, "snapshot-metadata.json"), snapshot)
	writeJSON(t, filepath.Join(ctx, "component-configuration-surface.json"), surface)
	writeJSON(t, filepath.Join(ctx, "statefulset-images.json"), []map[string]any{{"componentId": prometheusID, "observedVersion": version, "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}})
	regenerateManifests(t, root)
}

func digestLiteral(value byte) string { return "sha256:" + string(makeBytes(value, 64)) }

func makeBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func jsonBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func containsJSONField(data []byte, field string) bool {
	var value map[string]any
	return json.Unmarshal(data, &value) == nil && value[field] != nil
}
