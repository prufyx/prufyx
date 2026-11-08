// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdschema"
)

func TestCatalogListsTheCRDSchemaPilots(t *testing.T) {
	cat := Catalog()
	spec, ok := cat["crd.schema-removal.argo-cd"]
	if !ok || spec.Repo != "github.com/argoproj/argo-cd" || spec.ID != "crd.schema-removal.argo-cd" {
		t.Fatalf("argo-cd: %+v %v", spec, ok)
	}
	n := 0
	for id := range cat {
		if strings.HasPrefix(id, crdschema.IDPrefix) {
			n++
		}
	}
	if n != len(crdschema.CatalogProjects) {
		t.Fatalf("%d crd.schema-removal ids, want %d", n, len(crdschema.CatalogProjects))
	}
	for _, p := range []string{"cert-manager", "kuma", "mariadb-operator", "istio", "strimzi"} {
		if _, ok := cat[crdschema.IDPrefix+p]; ok {
			t.Errorf("%s must not be registered", p)
		}
	}
	// The extractor attests nothing, and a run gets a fresh one.
	a, b := spec.New(1), spec.New(1)
	if a == b {
		t.Fatal("New returned a shared extractor")
	}
	if l, ok := a.(interface{ AttestedFamilies() []string }); !ok || len(l.AttestedFamilies()) != 0 {
		t.Fatal("the catalog extractor attests a family")
	}
	// No oracle: the oracle command refuses it.
	if spec.Oracle != nil {
		t.Fatal("unexpected oracle")
	}
	if code, _, errs := run("oracle", "--extractor", spec.ID, "--out", t.TempDir(), "--expected", "x"); code != 2 || errs == "" {
		t.Fatalf("oracle: %d %q", code, errs)
	}
}
