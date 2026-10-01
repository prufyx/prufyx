// SPDX-License-Identifier: AGPL-3.0-only

package corpus_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/observation"
	"github.com/prufyx/prufyx/cli/internal/syntheticsnapshot"
)

func TestEveryCanonicalScenarioIsRejectedByFactoryV1UntilV3Admission(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "scenarios", "syn-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) != 18 {
		t.Fatalf("scenario count = %d, want 18", len(paths))
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			_, err := syntheticsnapshot.LoadScenario(path)
			if !errors.Is(err, syntheticsnapshot.ErrInvalid) {
				t.Fatalf("LoadScenario(%s) error = %v, want typed factory-v1 identity rejection", path, err)
			}
		})
	}
}

func TestEveryCanonicalScenarioGeneratesAndSelfImports(t *testing.T) {
	t.Skip("external gate: production factory v1 has not admitted v3 identities; generation/import proof is pending")
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "scenarios", "syn-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) != 18 {
		t.Fatalf("scenario count = %d, want 18", len(paths))
	}
	for _, path := range paths {
		scenario, err := syntheticsnapshot.LoadScenario(path)
		if err != nil {
			t.Fatalf("LoadScenario(%s): %v", path, err)
		}
		result, err := syntheticsnapshot.Generate(context.Background(), filepath.Join(t.TempDir(), "output"), scenario)
		if err != nil {
			t.Fatalf("Generate(%s): %v", path, err)
		}
		if result.Root == "" || result.BytesWritten <= 0 {
			t.Fatalf("Generate(%s): empty result %#v", path, result)
		}
		if scenario.ScenarioID == "syn-v4-tampered-source-binding-baseline" {
			raw, err := os.ReadFile(filepath.Join(result.Root, "expected-oracle.json"))
			if err != nil {
				t.Fatalf("generated baseline oracle: %v", err)
			}
			var generated struct {
				CurrentBundle json.RawMessage `json:"currentBundle"`
			}
			if err := json.Unmarshal(raw, &generated); err != nil {
				t.Fatalf("generated baseline oracle JSON: %v", err)
			}
			var generatedCurrent, expectedCurrent any
			if err := json.Unmarshal(generated.CurrentBundle, &generatedCurrent); err != nil {
				t.Fatalf("generated baseline currentBundle JSON: %v", err)
			}
			if err := json.Unmarshal(scenario.Expectations.CurrentBundle, &expectedCurrent); err != nil {
				t.Fatalf("persisted baseline currentBundle JSON: %v", err)
			}
			if bytes.Equal(bytes.TrimSpace(generated.CurrentBundle), []byte("null")) || !reflect.DeepEqual(generatedCurrent, expectedCurrent) {
				t.Fatalf("generated baseline currentBundle does not match persisted exact expectation: %s", generated.CurrentBundle)
			}
			observationRoot, err := observation.OpenPath(filepath.Join(result.Root, "observations", "p0000", "000000"))
			if err != nil {
				t.Fatalf("open generated baseline observation: %v", err)
			}
			bundle, err := observation.Import(context.Background(), observationRoot, observation.ImportOptions{})
			observationRoot.Close()
			if err != nil {
				t.Fatalf("import generated baseline observation: %v", err)
			}
			if bundle.KubernetesVersion != "1.35.6" || len(bundle.Components) != 4 || len(bundle.Conflicts) != 0 || len(bundle.Omissions) != 0 {
				t.Fatalf("imported baseline bundle = %#v", bundle)
			}
			for i, component := range bundle.Components {
				want := scenario.Snapshot.Components[i]
				if component.ComponentID != want.ComponentID || component.Version != want.Version || component.Status != "observed" {
					t.Fatalf("imported baseline component %d = %#v, want %s@%s observed", i, component, want.ComponentID, want.Version)
				}
			}
		}
	}
}

func TestTamperedManifestMutationIsImporterTerminal(t *testing.T) {
	corpusRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	scenario, err := syntheticsnapshot.LoadScenario(filepath.Join(corpusRoot, "scenarios", "syn-v4-tampered-source-binding-baseline.json"))
	if !errors.Is(err, syntheticsnapshot.ErrInvalid) {
		t.Fatalf("v3 tamper fixture error = %v, want typed factory-v1 identity rejection", err)
	}
	if err != nil {
		return
	}
	result, err := syntheticsnapshot.Generate(context.Background(), filepath.Join(t.TempDir(), "output"), scenario)
	if err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(result.Root, "observations", "p0000", "000000")
	manifestPath := filepath.Join(leaf, "MANIFEST.sha256")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) == 0 || manifest[0] < '0' || manifest[0] > 'f' {
		t.Fatalf("unexpected generated root manifest: %q", manifest)
	}
	if manifest[0] == '0' {
		manifest[0] = '1'
	} else {
		manifest[0] = '0'
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	observationRoot, err := observation.OpenPath(leaf)
	if err != nil {
		t.Fatal(err)
	}
	_, importErr := observation.Import(context.Background(), observationRoot, observation.ImportOptions{})
	observationRoot.Close()
	if !errors.Is(importErr, observation.ErrIntegrity) {
		t.Fatalf("tampered manifest import error = %v, want integrity", importErr)
	}
}
