// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func foreignCRD(group, kind, plural string) string {
	return `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ` + plural + "." + group + `
spec:
  group: ` + group + `
  names:
    kind: ` + kind + `
    plural: ` + plural + `
  scope: Namespaced
  versions:
  - name: v1
    served: true
    storage: true
`
}

// A definition whose group the reviewed table assigns to another project is
// left out of the inventory and named in Foreign; the project's own groups,
// and groups the table does not list, stay.
func TestReadDefinitionsIgnoresGroupsOfOtherProjects(t *testing.T) {
	const commit = "c1"
	src := memReader{
		commit + ":crds/own.yaml":      []byte(foreignCRD("projectcontour.io", "HTTPProxy", "httpproxies")),
		commit + ":crds/foreign.yaml":  []byte(foreignCRD("gateway.networking.k8s.io", "Gateway", "gateways")),
		commit + ":crds/unlisted.yaml": []byte(foreignCRD("unlisted.example.org", "Thing", "things")),
	}
	files := []string{"crds/own.yaml", "crds/foreign.yaml", "crds/unlisted.yaml"}
	read := func(project string) *Inventory {
		t.Helper()
		inv := &Inventory{Commit: commit, Paths: []PathRecord{}, Files: []FileRecord{}, CRDs: []CRD{}}
		if _, err := readDefinitions(src, extract.RepoRef{}, commit, slices.Clone(files), inv, nil, project); err != nil {
			t.Fatal(err)
		}
		return inv
	}
	names := func(inv *Inventory) string {
		var n []string
		for _, c := range inv.CRDs {
			n = append(n, c.Name)
		}
		return strings.Join(n, ",")
	}

	inv := read("contour")
	if got, want := names(inv), "httpproxies.projectcontour.io,things.unlisted.example.org"; got != want {
		t.Fatalf("contour CRDs %q, want %q", got, want)
	}
	if got, want := strings.Join(inv.Foreign, ","), "gateways.gateway.networking.k8s.io"; got != want {
		t.Fatalf("contour foreign %q, want %q", got, want)
	}
	if len(inv.Files) != 3 {
		t.Fatalf("%d file records: the file of a foreign definition is still read", len(inv.Files))
	}

	inv = read("gateway-api")
	if got, want := names(inv), "gateways.gateway.networking.k8s.io,things.unlisted.example.org"; got != want {
		t.Fatalf("gateway-api CRDs %q, want %q", got, want)
	}
	if got, want := strings.Join(inv.Foreign, ","), "httpproxies.projectcontour.io"; got != want {
		t.Fatalf("gateway-api foreign %q, want %q", got, want)
	}
}

// A foreign definition does not collide with the project's own.
func TestForeignDefinitionIsNotADuplicate(t *testing.T) {
	const commit = "c1"
	src := memReader{
		commit + ":a/gw.yaml":  []byte(foreignCRD("gateway.networking.k8s.io", "Gateway", "gateways")),
		commit + ":b/gw.yaml":  []byte(foreignCRD("gateway.networking.k8s.io", "Gateway", "gateways")),
		commit + ":b/own.yaml": []byte(foreignCRD("projectcontour.io", "HTTPProxy", "httpproxies")),
	}
	inv := &Inventory{Commit: commit, Paths: []PathRecord{}, Files: []FileRecord{}, CRDs: []CRD{}}
	if _, err := readDefinitions(src, extract.RepoRef{}, commit, []string{"a/gw.yaml", "b/gw.yaml", "b/own.yaml"}, inv, nil, "contour"); err != nil {
		t.Fatal(err)
	}
	if len(inv.CRDs) != 1 || len(inv.Foreign) != 2 {
		t.Fatalf("crds %d, foreign %v", len(inv.CRDs), inv.Foreign)
	}
}
