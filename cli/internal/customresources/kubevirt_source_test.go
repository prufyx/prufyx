// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"strings"
	"testing"
)

func TestKubeVirtConstructorSourceHasClosedIdentity(t *testing.T) {
	source := "https://github.com/kubevirt/kubevirt/blob/" + strings.Repeat("a", 40) + "/pkg/virt-operator/resource/generate/components/crds.go"
	base := Project{Slug: "kubevirt", Catalog: CatalogCNCF, FactProject: "kubevirt", Component: "pkg:github/kubevirt/kubevirt", Groups: []Group{{Name: "export.kubevirt.io", Source: source}}}
	if !validate([]Project{base}, nil) {
		t.Fatal("official pinned constructor source refused")
	}
	for _, tc := range []struct{ name, source, component string }{
		{"wrong repository", strings.Replace(source, "github.com/kubevirt/kubevirt/", "github.com/other/kubevirt/", 1), base.Component},
		{"wrong path", strings.Replace(source, "components/crds.go", "components/other.go", 1), base.Component},
		{"mutable ref", strings.Replace(source, strings.Repeat("a", 40), "main", 1), base.Component},
		{"release tag", strings.Replace(source, strings.Repeat("a", 40), "v1.9.1", 1), base.Component},
		{"foreign component", source, "pkg:github/other/kubevirt"},
		{"query", source + "?ref=other", base.Component},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.Component = tc.component
			p.Groups = []Group{{Name: "export.kubevirt.io", Source: tc.source}}
			if validate([]Project{p}, nil) {
				t.Fatal("noncanonical constructor provenance accepted")
			}
		})
	}
	foreign := base
	foreign.Slug = "other"
	foreign.FactProject = "other"
	if validate([]Project{foreign}, nil) {
		t.Fatal("another project accepted Go constructor provenance")
	}
	ordinary := base
	ordinary.Slug = "other"
	ordinary.FactProject = "other"
	ordinary.Component = "pkg:github/other/project"
	ordinary.Groups = []Group{{Name: "other.example.io", Source: "https://github.com/other/project/blob/" + strings.Repeat("a", 40) + "/crds/a.yaml"}}
	if !validate([]Project{ordinary}, nil) {
		t.Fatal("ordinary pinned YAML source changed behavior")
	}
}
