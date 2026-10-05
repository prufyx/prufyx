// SPDX-License-Identifier: AGPL-3.0-only

package inventory_test

import (
	"context"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/inventory"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sfeaturegates"
)

// fake is an extractor whose proof the test chooses, to reach the guards
// that a real extractor's output never trips: a complete-looking but empty
// proof is not an inventory.
type fake struct {
	id    string
	repo  string
	proof any
}

func (f fake) ID() string                                       { return f.id }
func (f fake) Version() string                                  { return "1.0.0" }
func (f fake) Applies(extract.RepoRef) bool                     { return true }
func (f fake) Pairs(extract.ReleaseIndex) []extract.VersionPair { return nil }
func (f fake) Extract(context.Context, extract.PinnedReader, extract.VersionPair) (extract.Extraction, error) {
	return extract.Extraction{Proof: f.proof}, nil
}

func buildFake(t *testing.T, id, repo string, proof any) ([]byte, error) {
	t.Helper()
	r, err := extract.ParseRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Build(context.Background(), fake{id: id, repo: repo, proof: proof}, extract.FixtureReader{Root: t.TempDir()}, r, strings.Repeat("a", 40))
}

func TestInventoryRefusesEmptyOrUnreadableProofs(t *testing.T) {
	gate := func(declared, names []string, fromOK, toOK bool) map[string]any {
		return map[string]any{
			"from": map[string]any{"complete": fromOK, "declared": declared},
			"to":   map[string]any{"complete": toOK, "names": names},
		}
	}
	crd := func(complete bool, crds []any) map[string]any {
		return map[string]any{"target": "x", "from": map[string]any{"complete": complete, "crds": crds}}
	}
	one := []any{map[string]any{"name": "a.b", "group": "b", "kind": "A", "versions": []any{}}}
	for _, tc := range []struct {
		name, id, repo string
		proof          any
		wantOK         bool
	}{
		{"gates: complete and non-empty", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", gate([]string{"A"}, []string{"A"}, true, true), true},
		{"gates: nothing declared", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", gate(nil, []string{"A"}, true, true), false},
		{"gates: no names found", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", gate([]string{"A"}, nil, true, true), false},
		{"gates: from incomplete", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", gate([]string{"A"}, []string{"A"}, false, true), false},
		{"gates: to incomplete", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", gate([]string{"A"}, []string{"A"}, true, false), false},
		{"gates: proof without the sides", k8sfeaturegates.ID, "github.com/kubernetes/kubernetes", map[string]any{}, false},
		{"crds: complete and non-empty", crdversions.IDPrefix + "strimzi", "github.com/strimzi/strimzi-kafka-operator", crd(true, one), true},
		{"crds: none", crdversions.IDPrefix + "strimzi", "github.com/strimzi/strimzi-kafka-operator", crd(true, nil), false},
		{"crds: incomplete", crdversions.IDPrefix + "strimzi", "github.com/strimzi/strimzi-kafka-operator", crd(false, one), false},
		{"crds: no from side", crdversions.IDPrefix + "strimzi", "github.com/strimzi/strimzi-kafka-operator", map[string]any{"target": "x"}, false},
	} {
		doc, err := buildFake(t, tc.id, tc.repo, tc.proof)
		if tc.wantOK {
			if err != nil || len(doc) == 0 {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if _, ok := inventory.IsIncomplete(err); !ok || doc != nil {
			t.Fatalf("%s: doc %d bytes, err %v", tc.name, len(doc), err)
		}
	}
}
