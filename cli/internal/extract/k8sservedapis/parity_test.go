// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/inventory"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
)

// The inventory package keeps its own copy of the extractor's OpenAPI parse
// (the extractor must not change). The two must agree on every document:
// the same kinds, and the same refusals.
func compare(t *testing.T, name string, doc []byte) {
	t.Helper()
	theirs, err1 := k8sservedapis.ParseSpecForTest("swagger.json", doc)
	ours, err2 := inventory.ParseSpec(doc)
	if (err1 != nil) != (err2 != nil) {
		t.Fatalf("%s: extractor error %v, inventory error %v", name, err1, err2)
	}
	if err1 != nil {
		return
	}
	var a, b []string
	for g := range theirs {
		a = append(a, g.Group+"/"+g.Version+"/"+g.Kind)
	}
	for _, g := range ours {
		b = append(b, g.Group+"/"+g.Version+"/"+g.Kind)
	}
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		t.Fatalf("%s: %d kinds vs %d", name, len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s: %q vs %q", name, a[i], b[i])
		}
	}
}

func TestInventoryParsesEveryFixtureSpecLikeTheExtractor(t *testing.T) {
	files, err := filepath.Glob("testdata/fixture/github.com/kubernetes/kubernetes/commits/*/api/openapi-spec/swagger.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixture specifications: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		compare(t, f, raw)
	}
}

func TestInventoryParsesDeformedSpecsLikeTheExtractor(t *testing.T) {
	gvk := func(g, v, k string) string {
		return `{"x-kubernetes-group-version-kind":[{"group":"` + g + `","version":"` + v + `","kind":"` + k + `"}]}`
	}
	doc := func(swagger string, defs ...string) []byte {
		s := `{"swagger":"` + swagger + `","definitions":{`
		for i, d := range defs {
			if i > 0 {
				s += ","
			}
			s += `"d` + string(rune('a'+i)) + `":` + d
		}
		return []byte(s + `}}`)
	}
	for name, raw := range map[string][]byte{
		"valid":              doc("2.0", gvk("apps", "v1", "Deployment")),
		"core group":         doc("2.0", gvk("", "v1", "Pod")),
		"empty version":      doc("2.0", gvk("apps", "", "Deployment")),
		"empty kind":         doc("2.0", gvk("apps", "v1", "")),
		"empty group only":   doc("2.0", gvk("", "v1", "Pod"), gvk("apps", "v1", "Deployment")),
		"one bad of two":     doc("2.0", gvk("apps", "v1", "Deployment"), gvk("apps", "", "X")),
		"missing swagger":    doc("", gvk("apps", "v1", "Deployment")),
		"no definitions":     []byte(`{"swagger":"2.0"}`),
		"empty definitions":  doc("2.0"),
		"definition w/o gvk": doc("2.0", `{"type":"object"}`),
		"duplicate gvk":      doc("2.0", gvk("apps", "v1", "Deployment"), gvk("apps", "v1", "Deployment")),
		"not json":           []byte(`{`),
		"array":              []byte(`[]`),
		"null":               []byte(`null`),
	} {
		compare(t, name, raw)
	}
}
