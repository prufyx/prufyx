// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdschema"
)

// The catalog registers exactly the reviewed pilots whose target the mapper
// accepts, and never a refused one. The allow-list is empty while its only
// pilot carries exclusion entries, which the mapper refuses.
func TestCatalogListsTheCRDSchemaPilots(t *testing.T) {
	cat := Catalog()
	n := 0
	for id := range cat {
		if strings.HasPrefix(id, crdschema.IDPrefix) {
			n++
		}
	}
	if n != len(crdschema.CatalogProjects) {
		t.Fatalf("%d crd.schema-removal ids, want %d", n, len(crdschema.CatalogProjects))
	}
	for _, p := range []string{"argo-cd", "cert-manager", "kuma", "mariadb-operator", "istio", "strimzi"} {
		if _, ok := cat[crdschema.IDPrefix+p]; ok {
			t.Errorf("%s must not be registered", p)
		}
	}
	// A pilot the catalog registers attests nothing, gets a fresh extractor
	// per run, has no oracle.
	for _, p := range crdschema.CatalogProjects {
		spec, ok := cat[crdschema.IDPrefix+p]
		if !ok {
			t.Fatalf("pilot %s is not registered", p)
		}
		a, b := spec.New(1), spec.New(1)
		if a == b {
			t.Fatal("New returned a shared extractor")
		}
		if l, ok := a.(interface{ AttestedFamilies() []string }); !ok || len(l.AttestedFamilies()) != 0 {
			t.Fatal("the catalog extractor attests a family")
		}
		if spec.Oracle != nil {
			t.Fatal("unexpected oracle")
		}
		if code, _, errs := run("oracle", "--extractor", spec.ID, "--out", t.TempDir(), "--expected", "x"); code != 2 || errs == "" {
			t.Fatalf("oracle: %d %q", code, errs)
		}
	}
}
