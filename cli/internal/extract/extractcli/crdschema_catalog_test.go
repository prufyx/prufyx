// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"path/filepath"
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

// The factory runs `extract run` and `extract verify` for every registered id
// that applies to a repository, and treats a non-zero exit as an error. The
// new id must exit 0 with no rule, whatever its ledger holds, and `list` must
// print the same repository string as the crd.version-removal id of the project.
func TestCRDSchemaRunExitsZeroWithoutCandidates(t *testing.T) {
	const id, fx = "crd.schema-removal.argo-cd", "../crdversions/testdata/fixture"
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errs := run("run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", "2026-10-04T00:00:00Z", "--wants-out", filepath.Join(t.TempDir(), "wants.json"))
	t.Logf("run: %d %s %s", code, out, errs)
	if code != 0 || !strings.Contains(out, "0 rules, 0 vectors") {
		t.Fatalf("run: %d %s %s", code, out, errs)
	}
	if code, out, errs := run("verify", "--extractor", id, "--fixture", fx, "--out", dir); code != 0 {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}
	_, list, _ := run("list")
	var a, b string
	for _, l := range strings.Split(list, "\n") {
		if id2, repo, ok := strings.Cut(l, "\t"); ok {
			switch id2 {
			case id:
				a = repo
			case "crd.version-removal.argo-cd":
				b = repo
			}
		}
	}
	if a == "" || a != b {
		t.Fatalf("list repos %q vs %q", a, b)
	}
}
