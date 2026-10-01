// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestImportSyntheticFourComponentBundle(t *testing.T) {
	root := syntheticRoot(t)
	bundle, err := importTestPath(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.KubernetesVersion != "1.33.4" || len(bundle.Components) != 4 {
		t.Fatalf("bundle = %#v", bundle)
	}
	if bundle.Components[0].ComponentID != "pkg:oci/argoproj/argo-cd" {
		t.Fatalf("components are not canonicalized: %#v", bundle.Components)
	}
	rootManifest, err := os.ReadFile(filepath.Join(root, "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	rootDigest := digest(rootManifest)
	if !contains(bundle.SourceDigests, rootDigest) || !contains(bundle.Components[0].SourceDigests, rootDigest) {
		t.Fatalf("root manifest digest missing from source digests: %q", rootDigest)
	}
	encoded, err := Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private.example", "secret-endpoint", "customer-name", "contextHash", "absolutePath"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("forbidden field survived projection: %q in %s", forbidden, encoded)
		}
	}
	second, err := importTestPath(t, root)
	if err != nil {
		t.Fatal(err)
	}
	secondEncoded, err := Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, secondEncoded) {
		t.Fatal("identical synthetic input produced different bytes")
	}
}

func TestImportRequiresPredicateEvidenceRoleInSameComponentRow(t *testing.T) {
	workflowRow := func(roles []string, withEvidence bool) map[string]any {
		row := map[string]any{
			"componentId": "pkg:oci/argoproj/argo-workflows", "observedVersion": "4.0.9", "versionScheme": "tag",
			"observationState": "observed", "observationCount": 1, "versionConflict": false,
			"roles": roles, "predicates": map[string]any{"component.argo_workflows.managed_namespace_configured": true},
		}
		if withEvidence {
			row["predicateEvidence"] = []any{map[string]any{
				"predicateId": "component.argo_workflows.managed_namespace_configured", "state": "observed",
				"sourceRole": "workflow-controller", "evidenceClass": "",
			}}
		}
		return row
	}
	writeRows := func(t *testing.T, rows []any) string {
		t.Helper()
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "component-configuration-surface.json")
		writeJSON(t, path, map[string]any{
			"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface",
			"components": rows, "omissions": []any{},
		})
		regenerateManifests(t, root)
		return root
	}

	t.Run("missing same-row role", func(t *testing.T) {
		root := writeRows(t, []any{workflowRow(nil, true)})
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v, want ErrIntegrity", err)
		}
	})
	t.Run("duplicate same-row role", func(t *testing.T) {
		root := writeRows(t, []any{workflowRow([]string{"workflow-controller", "workflow-controller"}, true)})
		if _, err := importTestPath(t, root); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v, want ErrInvalid", err)
		}
	})
	t.Run("role cannot be borrowed across rows", func(t *testing.T) {
		root := writeRows(t, []any{workflowRow(nil, true), workflowRow([]string{"workflow-controller"}, false)})
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("error = %v, want ErrIntegrity", err)
		}
	})
	t.Run("coherent repeated rows", func(t *testing.T) {
		root := writeRows(t, []any{workflowRow([]string{"workflow-controller"}, true), workflowRow([]string{"workflow-controller"}, true)})
		if _, err := importTestPath(t, root); err != nil {
			t.Fatalf("coherent rows rejected: %v", err)
		}
	})
}

func TestImportRejectsDeterministicDescriptorReadMutation(t *testing.T) {
	root := syntheticRoot(t)
	targetRel := "demo/server-version.json"
	target := filepath.Join(root, filepath.FromSlash(targetRel))
	mutated := false
	hooks := &importReadHooks{afterStableStat: func(path string) error {
		if path != targetRel || mutated {
			return nil
		}
		mutated = true
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		if _, err := file.Write([]byte(" ")); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}}
	_, err := importPathWithReadHooks(t, root, hooks)
	if !mutated {
		t.Fatal("descriptor-read mutation hook was not reached")
	}
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "changed during read") {
		t.Fatalf("descriptor mutation error = %v, want stable-file ErrIntegrity", err)
	}
}

func TestImportRejectsUnknownObservationContractFields(t *testing.T) {
	root := syntheticRoot(t)
	path := filepath.Join(root, "demo", "server-version.json")
	if err := os.WriteFile(path, []byte(`{"gitVersion":"v1.33.4","privateEndpoint":"https://private.invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	regenerateManifests(t, root)
	if _, err := importTestPath(t, root); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown observation field error = %v, want ErrInvalid", err)
	} else if !strings.Contains(err.Error(), "privateEndpoint") {
		// Internal tests retain the exact contract field for diagnosis; the
		// command-layer error path intentionally exposes only a sanitized class.
		t.Fatalf("strict importer error lost precise contract field: %v", err)
	}
}

func TestImportAcceptsCollectorServerVersionProjection(t *testing.T) {
	root := syntheticRoot(t)
	writeJSON(t, filepath.Join(root, "demo", "server-version.json"), map[string]any{
		"gitVersion": "v1.33.4", "gitCommit": "synthetic", "gitTreeState": "clean",
		"buildDate": "2026-01-01T00:00:00Z", "goVersion": "go1.24", "compiler": "gc", "platform": "linux/amd64",
	})
	regenerateManifests(t, root)
	if _, err := importTestPath(t, root); err != nil {
		t.Fatalf("actual collector server-version projection was rejected: %v", err)
	}
}

func TestImportServerVersionGoRuntimeGrammar(t *testing.T) {
	tests := []struct {
		name      string
		goVersion string
		wantValid bool
	}{
		{name: "boringcrypto runtime", goVersion: "go1.25.11 X:boringcrypto", wantValid: true},
		{name: "clean runtime", goVersion: "go1.25.11", wantValid: true},
		{name: "malicious suffix", goVersion: "go1.25.11 X:evil", wantValid: false},
		{name: "arbitrary core suffix", goVersion: "go1.25.11evil", wantValid: false},
		{name: "arbitrary core suffix with boringcrypto", goVersion: "go1.25.11evil X:boringcrypto", wantValid: false},
		{name: "arbitrary build suffix", goVersion: "go1.25.11+evil", wantValid: false},
		{name: "fourth numeric segment", goVersion: "go1.25.11.4", wantValid: false},
		{name: "evil boringcrypto suffix", goVersion: "go1.25.11 X:boringcrypto:evil", wantValid: false},
		{name: "newline", goVersion: "go1.25.11\nX:boringcrypto", wantValid: false},
		{name: "NUL", goVersion: "go1.25.11\x00X:boringcrypto", wantValid: false},
		{name: "long runtime", goVersion: "go1.25.11" + strings.Repeat("a", maxStringBytes), wantValid: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := syntheticRoot(t)
			writeJSON(t, filepath.Join(root, "demo", "server-version.json"), map[string]any{
				"gitVersion": "v1.33.4", "goVersion": tc.goVersion,
			})
			regenerateManifests(t, root)
			bundle, err := importTestPath(t, root)
			if tc.wantValid {
				if err != nil {
					t.Fatalf("importTestPath(t, ) rejected reviewed Go runtime form: %v", err)
				}
				encoded, marshalErr := Marshal(bundle)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if bytes.Contains(encoded, []byte("goVersion")) || bytes.Contains(encoded, []byte(tc.goVersion)) {
					t.Fatalf("projected bundle retained raw Go runtime value: %s", encoded)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("importTestPath(t, ) error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestImportCanonicalizesKubernetesVendorBuildVersion(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{name: "reviewed GKE build", input: "v1.35.6-gke.1710000", want: "1.35.6"},
		{name: "Kubernetes prerelease", input: "v1.35.0-rc.1", want: "1.35.0-rc.1"},
		{name: "unreviewed provider suffix", input: "v1.35.6-evil", want: "1.35.6-evil"},
		{name: "build metadata", input: "v1.35.6+build.7", want: "1.35.6+build.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := syntheticRoot(t)
			writeJSON(t, filepath.Join(root, "demo", "server-version.json"), map[string]any{"gitVersion": tc.input})
			regenerateManifests(t, root)
			bundle, err := importTestPath(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if bundle.KubernetesVersion != tc.want {
				t.Fatalf("KubernetesVersion = %q, want %q", bundle.KubernetesVersion, tc.want)
			}
		})
	}
}

func TestImportPartialWithoutServerVersionIsExplicitUnknown(t *testing.T) {
	root := syntheticRoot(t)
	if err := os.Remove(filepath.Join(root, "demo", "server-version.json")); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "index.json"), map[string]any{
		"schema": IndexSchema, "generatedAt": "synthetic-demo-only",
		"contexts": []any{map[string]any{"directory": "demo", "contextHash": "discarded-synthetic-token", "collectionStatus": "partial_for_declared_surface", "omissionCount": 0}},
	})
	writeJSON(t, filepath.Join(root, "demo", "snapshot-metadata.json"), map[string]any{
		"schema": ObservationSchema, "format": "KubeconfigAPIObservation",
		"collectionStatus": "partial_for_declared_surface", "omissionCount": 0,
	})
	regenerateManifests(t, root)
	bundle, err := importTestPath(t, root)
	if err != nil {
		t.Fatalf("partial unauthorized projection was rejected: %v", err)
	}
	if bundle.KubernetesVersion != "" || !containsOmission(bundle.Omissions, "KUBERNETES_VERSION_UNOBSERVED") {
		t.Fatalf("partial projection did not preserve Kubernetes UNKNOWN: %#v", bundle)
	}
}

func containsOmission(omissions []Omission, code string) bool {
	for _, omission := range omissions {
		if omission.Code == code {
			return true
		}
	}
	return false
}

func TestValidateSnapshotMetadataRejectsUntypedOrHugePaginationNumbers(t *testing.T) {
	base := map[string]any{
		"version": "crd-pagination-policy-v1", "endpoint": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "profile": "raw-v1-continue",
		"pageLimit": 50, "maxPages": 64, "maxItems": 10000, "maxVersions": 100000, "maxProjectedBytes": 4194304, "overallTimeoutSeconds": 120,
		"localJsonStageDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"pageProjectionDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"finalMergeDigest":     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	for name, value := range map[string]any{"string-page-limit": "50", "huge-page-limit": int64(9223372036854775807), "fractional-page-limit": 1.5} {
		t.Run(name, func(t *testing.T) {
			policy := map[string]any{}
			for key, item := range base {
				policy[key] = item
			}
			policy["pageLimit"] = value
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSnapshotMetadata(metadataFile{CRDPaginationPolicy: raw}); err == nil {
				t.Fatal("accepted untyped or out-of-bounds pagination integer")
			}
		})
	}
}

func TestImportRejectsNonActiveOrMismatchedVersionEvidence(t *testing.T) {
	cases := []struct {
		name, file, raw string
		wantErr         bool
	}{
		{name: "historical workload", file: "deployment-images.json", raw: `[{"componentId":"pkg:oci/argoproj/argo-cd","observedVersion":"3.4.6","versionScheme":"tag","observationState":"historical","observationCount":1,"versionConflict":false}]`, wantErr: true},
		{name: "declared workload", file: "deployment-images.json", raw: `[{"componentId":"pkg:oci/argoproj/argo-cd","observedVersion":"3.4.6","versionScheme":"tag","observationState":"declared","observationCount":1,"versionConflict":false}]`},
		{name: "digest with version", file: "deployment-images.json", raw: `[{"componentId":"pkg:oci/argoproj/argo-cd","observedVersion":"3.4.6","versionScheme":"digest","observationState":"active","observationCount":1,"versionConflict":false}]`},
		{name: "stale configuration", file: "component-configuration-surface.json", raw: `{"apiVersion":"prufyx.io/configuration-surface/v1alpha1","kind":"ComponentConfigurationSurface","components":[{"componentId":"pkg:oci/prometheus/prometheus","observedVersion":"3.13.1","versionScheme":"tag","observationState":"historical","observationCount":1,"versionConflict":false,"predicates":{"component.prometheus.mode":true}}],"omissions":[]}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := syntheticRoot(t)
			path := filepath.Join(root, "demo", tc.file)
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.wantErr {
				config := `{"apiVersion":"prufyx.io/configuration-surface/v1alpha1","kind":"ComponentConfigurationSurface","components":[{"componentId":"pkg:oci/argoproj/argo-cd","observedVersion":null,"versionScheme":"unknown","observationState":"observed","observationCount":1,"versionConflict":false,"predicates":{}}],"omissions":[]}`
				if err := os.WriteFile(filepath.Join(root, "demo", "component-configuration-surface.json"), []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
				statefulset := `[{"componentId":"pkg:oci/prometheus/prometheus","observedVersion":"3.13.1","versionScheme":"tag","observationState":"active","observationCount":1,"versionConflict":false}]`
				if err := os.WriteFile(filepath.Join(root, "demo", "statefulset-images.json"), []byte(statefulset), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			regenerateManifests(t, root)
			bundle, err := importTestPath(t, root)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("evidence state/scheme error = %v, want ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, component := range bundle.Components {
				if component.ComponentID == "pkg:oci/argoproj/argo-cd" && component.Version != "" {
					t.Fatalf("non-active evidence became current version: %#v", component)
				}
			}
		})
	}
}

// TestImportExternalObservation is an opt-in, read-only compatibility probe for
// an operator-supplied observation directory. It never logs projected content
// and is skipped in normal Community test runs.
func TestImportExternalObservation(t *testing.T) {
	root := os.Getenv("PRUFYX_TEST_OBSERVATION_ROOT")
	if root == "" {
		t.Skip("PRUFYX_TEST_OBSERVATION_ROOT is not set")
	}
	bundle, err := importTestPath(t, root)
	if err != nil {
		t.Fatal("importTestPath(t, external observation) failed: operator-only sanitized failure")
	}
	if bundle.APIVersion != APIVersion || bundle.Kind != Kind || bundle.KubernetesVersion == "" {
		t.Fatal("external observation did not produce a valid closed bundle")
	}
}

func TestImportRejectsTamperMissingAndUnlistedFiles(t *testing.T) {
	t.Run("tamper", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "server-version.json")
		if err := os.WriteFile(path, []byte(`{"gitVersion":"v1.33.5"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("importTestPath(t, ) error = %v, want integrity error", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		root := syntheticRoot(t)
		if err := os.Remove(filepath.Join(root, "demo", "server-version.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted a missing declared file")
		}
	})
	t.Run("unlisted", func(t *testing.T) {
		root := syntheticRoot(t)
		if err := os.WriteFile(filepath.Join(root, "demo", "unexpected.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("importTestPath(t, ) error = %v, want integrity error", err)
		}
	})
}

func TestImportRejectsSymlinkDuplicateUnsafeDeepAndAmbiguous(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := syntheticRoot(t)
		original := filepath.Join(root, "demo", "server-version.json")
		outside := filepath.Join(t.TempDir(), "version.json")
		if err := os.WriteFile(outside, []byte(`{"gitVersion":"v1.33.4"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(original); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, original); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted a symlink")
		}
	})
	t.Run("duplicate JSON key", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "server-version.json")
		if err := os.WriteFile(path, []byte(`{"gitVersion":"v1.33.4","gitVersion":"v1.33.4"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		regenerateManifests(t, root)
		if _, err := importTestPath(t, root); !strings.Contains(errString(err), "duplicate JSON key") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsafe number", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "snapshot-metadata.json")
		if err := os.WriteFile(path, []byte(`{"schema":"`+ObservationSchema+`","format":"KubeconfigAPIObservation","omissionCount":9007199254740992}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted an unsafe number")
		}
	})
	t.Run("safe integer boundary", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "snapshot-metadata.json")
		if err := os.WriteFile(path, []byte(`{"schema":"`+ObservationSchema+`","format":"KubeconfigAPIObservation","omissionCount":9007199254740991}`), 0o600); err != nil {
			t.Fatal(err)
		}
		regenerateManifests(t, root)
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted inconsistent omission metadata")
		}
	})
	t.Run("deep JSON", func(t *testing.T) {
		root := syntheticRoot(t)
		deep := strings.Repeat(`[`, maxJSONDepth+4) + `null` + strings.Repeat(`]`, maxJSONDepth+4)
		path := filepath.Join(root, "demo", "snapshot-metadata.json")
		if err := os.WriteFile(path, []byte(deep), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted deeply nested JSON")
		}
	})
	t.Run("deep path", func(t *testing.T) {
		root := syntheticRoot(t)
		deep := filepath.Join(root, "demo", strings.Repeat("nested/", maxPathDepth+2))
		if err := os.MkdirAll(deep, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deep, "extra.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("importTestPath(t, ) accepted a deeply nested path")
		}
	})
	t.Run("ambiguous contexts", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "index.json")
		if err := os.WriteFile(path, []byte(`{"schema":"`+IndexSchema+`","generatedAt":"synthetic","contexts":[{"directory":"demo","contextHash":"discarded","collectionStatus":"complete_for_declared_surface","omissionCount":0},{"directory":"demo","contextHash":"discarded","collectionStatus":"complete_for_declared_surface","omissionCount":0}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		regenerateRootManifest(t, root)
		if _, err := importTestPath(t, root); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("error = %v, want ambiguity", err)
		}
	})
}

func TestImportReportsConflictingVersions(t *testing.T) {
	root := syntheticRoot(t)
	path := filepath.Join(root, "demo", "deployment-images.json")
	data := []map[string]any{{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.99", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false}}
	writeJSON(t, path, data)
	regenerateManifests(t, root)
	bundle, err := importTestPath(t, root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, conflict := range bundle.Conflicts {
		if conflict.ComponentID == "pkg:oci/argoproj/argo-cd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bundle did not report version conflict: %#v", bundle)
	}
}

func TestImporterBoundsAndNormalizesUntrustedFields(t *testing.T) {
	t.Run("strict semantic version", func(t *testing.T) {
		for _, tc := range []struct {
			input string
			want  string
			ok    bool
		}{
			{"v1.2.3-alpha.1+build.7", "1.2.3-alpha.1+build.7", true},
			{"v1.2.3-rc.1", "1.2.3-rc.1", true},
			{"vv1.2.3", "", false},
			{"1.2.3-01", "", false},
			{"1.2.3-", "", false},
			{"1.2.3+", "", false},
		} {
			got, ok := normalizeVersion(tc.input)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("normalizeVersion(%q) = %q, %v; want %q, %v", tc.input, got, ok, tc.want, tc.ok)
			}
		}
	})
	t.Run("omission parser is typed and bounded", func(t *testing.T) {
		if _, err := parseOmissions([]byte("file\tbad\textra\n")); err == nil {
			t.Fatal("accepted malformed omission code")
		} else {
			var typed *OmissionParseError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %T, want OmissionParseError", err)
			}
		}
		if _, err := parseOmissions([]byte("file\tAPI_READ_FAILED\treason\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := parseOmissions([]byte("file\tAPI_READ_FAILED\treason\nother\tAPI_READ_FAILED\treason\n")); err == nil {
			t.Fatal("accepted duplicate omission code")
		}
	})
	t.Run("recursive string bound", func(t *testing.T) {
		payload := `{"outer":{"inner":"` + strings.Repeat("x", maxStringBytes+1) + `"}}`
		if err := decodeJSON([]byte(payload), &map[string]any{}); err == nil {
			t.Fatal("accepted oversized nested string")
		}
	})
}

func TestImportRejectsHardlinksOversizedTreesAndManifestAliases(t *testing.T) {
	t.Run("repeated surface omission is projected once", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "component-configuration-surface.json")
		var surface map[string]any
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &surface); err != nil {
			t.Fatal(err)
		}
		surface["omissions"] = []any{
			map[string]any{"code": "API_READ_FAILED"},
			map[string]any{"code": "API_READ_FAILED"},
		}
		writeJSON(t, path, surface)
		regenerateManifests(t, root)
		bundle, err := importTestPath(t, root)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, omission := range bundle.Omissions {
			if omission.Code == "API_READ_FAILED" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("surface omission projection count = %d, want 1", count)
		}
	})
	t.Run("duplicate omission evidence", func(t *testing.T) {
		root := syntheticRoot(t)
		if err := os.WriteFile(filepath.Join(root, "demo", "omissions.tsv"), []byte("api.json\tAPI_READ_FAILED\tfirst\nother.json\tAPI_READ_FAILED\tsecond\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		regenerateManifests(t, root)
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("Import accepted duplicate omission evidence")
		} else {
			var typed *OmissionParseError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %T, want OmissionParseError", err)
			}
		}
	})
	t.Run("hardlink outside root", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "server-version.json")
		outside := filepath.Join(t.TempDir(), "outside.json")
		if err := os.WriteFile(outside, []byte(`{"gitVersion":"1.33.4"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, path); err != nil {
			t.Skipf("hardlinks unavailable: %v", err)
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("Import accepted hardlink-backed observation file")
		}
	})
	t.Run("tree entry bound", func(t *testing.T) {
		root := syntheticRoot(t)
		for i := 0; i <= maxFiles; i++ {
			name := filepath.Join(root, "demo", fmt.Sprintf("extra-%04d", i))
			if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := importTestPath(t, root); err == nil {
			t.Fatal("Import accepted oversized observation tree")
		}
	})
	t.Run("manifest traversal aliases", func(t *testing.T) {
		for _, path := range []string{"./000/file.json", "./server-version.json", "./a/../b", "a/./b", "../b", ".//b", "././b", "./././b", "server-version.json"} {
			_, ok := normalizeManifestPath(path)
			want := path == "./000/file.json" || path == "./server-version.json" || path == "server-version.json"
			if ok != want {
				t.Fatalf("normalizeManifestPath(%q) accepted=%v, want %v", path, ok, want)
			}
		}
	})
}

func TestImportDescriptorRace(t *testing.T) {
	t.Run("replacement never escapes root", func(t *testing.T) {
		root := syntheticRoot(t)
		path := filepath.Join(root, "demo", "server-version.json")
		outside := filepath.Join(t.TempDir(), "outside.json")
		if err := os.WriteFile(outside, []byte(`{"gitVersion":"9.9.9"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		stop := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = os.Rename(path, path+".race")
				_ = os.Symlink(outside, path)
				_ = os.Remove(path)
				_ = os.Rename(path+".race", path)
			}
		}()
		for i := 0; i < 20; i++ {
			_, _ = importTestPath(t, root)
		}
		close(stop)
		wg.Wait()
	})
}

func syntheticRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	ctx := filepath.Join(root, "demo")
	if err := os.MkdirAll(ctx, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "index.json"), map[string]any{
		"schema": IndexSchema, "generatedAt": "synthetic-demo-only",
		"contexts": []any{map[string]any{"directory": "demo", "contextHash": "discarded-synthetic-token", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0}},
	})
	writeJSON(t, filepath.Join(ctx, "snapshot-metadata.json"), map[string]any{"schema": ObservationSchema, "format": "KubeconfigAPIObservation", "collectionStatus": "complete_for_declared_surface", "omissionCount": 0})
	writeJSON(t, filepath.Join(ctx, "server-version.json"), map[string]any{"gitVersion": "v1.33.4"})
	writeJSON(t, filepath.Join(ctx, "deployment-images.json"), []map[string]any{
		{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.6", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false},
		{"componentId": "pkg:oci/argoproj/argo-workflows", "observedVersion": "4.0.9", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false},
		{"componentId": "pkg:oci/cert-manager/cert-manager", "observedVersion": "1.20.3", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false},
	})
	writeJSON(t, filepath.Join(ctx, "statefulset-images.json"), []map[string]any{
		{"componentId": "pkg:oci/prometheus/prometheus", "observedVersion": "3.13.1", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false},
		{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.6", "versionScheme": "tag", "observationState": "active", "observationCount": 1, "versionConflict": false},
	})
	writeJSON(t, filepath.Join(ctx, "component-configuration-surface.json"), map[string]any{
		"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface",
		"components": []any{
			map[string]any{"componentId": "pkg:oci/prometheus/prometheus", "observedVersion": "3.13.1", "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false, "predicates": map[string]any{"component.prometheus.web_admin_api_enabled": true, "component.prometheus.web_lifecycle_enabled": false}},
			map[string]any{"componentId": "pkg:oci/argoproj/argo-cd", "observedVersion": "3.4.6", "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false, "predicates": map[string]any{"component.argo_cd.insecure_server_enabled": false}},
			map[string]any{"componentId": "pkg:oci/argoproj/argo-workflows", "observedVersion": "4.0.9", "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false, "predicates": map[string]any{"component.argo_workflows.namespaced_mode": true}},
			map[string]any{"componentId": "pkg:oci/cert-manager/cert-manager", "observedVersion": "1.20.3", "versionScheme": "tag", "observationState": "observed", "observationCount": 1, "versionConflict": false, "predicates": map[string]any{"component.cert_manager.owner_ref_enabled": true}},
		},
		"omissions": []any{},
	})
	if err := os.WriteFile(filepath.Join(ctx, "omissions.tsv"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	regenerateManifests(t, root)
	return root
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func regenerateManifests(t *testing.T, root string) {
	t.Helper()
	regenerateContextManifest(t, filepath.Join(root, "demo"))
	regenerateRootManifest(t, root)
}

func regenerateContextManifest(t *testing.T, ctx string) {
	t.Helper()
	writeManifest(t, ctx, filepath.Join(ctx, "MANIFEST.sha256"))
}
func regenerateRootManifest(t *testing.T, root string) {
	t.Helper()
	writeManifest(t, root, filepath.Join(root, "MANIFEST.sha256"))
}

func writeManifest(t *testing.T, base, manifest string) {
	t.Helper()
	var paths []string
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
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
	})
	if err != nil {
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

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
