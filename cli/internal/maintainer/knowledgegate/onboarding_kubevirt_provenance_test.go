// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

type constructorBudgetStub struct {
	budgetStub
	entries []extract.TreeEntry
}

func (s *constructorBudgetStub) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return s.entries, nil
}

func TestOnboardingKubeVirtConstructorCitationRequiresProfile(t *testing.T) {
	const source = "pkg/virt-operator/resource/generate/components/crds.go"
	st := &budgetStub{}
	// Listing the source must not turn a stripped profile into a YAML reader.
	target := crdversions.Target{Project: "kubevirt", Repo: "github.com/kubevirt/kubevirt", Paths: []crdversions.PathSpec{{Path: source}}}
	row := customresources.Project{Groups: []customresources.Group{{Name: "kubevirt.io", Source: "https://github.com/kubevirt/kubevirt/blob/" + obTo + "/" + source}}}
	err := checkGroupSources(st, target, row, obTo)
	if err == nil || !strings.Contains(err.Error(), "unsupported KubeVirt constructor citation") {
		t.Fatalf("stripped profile source citation: %v", err)
	}
}

func TestOnboardingKubeVirtConstructorCitationKeepsBudget(t *testing.T) {
	const source = "pkg/virt-operator/resource/generate/components/crds.go"
	target := crdversions.Target{Project: "kubevirt", Repo: "github.com/kubevirt/kubevirt", Catalog: crdversions.CatalogCNCF, Component: "pkg:github/kubevirt/kubevirt", FactProject: "kubevirt", ConstructorProfile: "kubevirt-v1"}
	grant := crdversions.SourceGrant{}
	for _, path := range []string{"pkg/virt-operator/resource/generate/components", "pkg/virt-operator/resource/generate/install", "pkg", "tools", "cmd", "staging/src/kubevirt.io/api", "staging/src/kubevirt.io/client-go", "vendor", "kubevirtci"} {
		grant.Trees = append(grant.Trees, crdversions.SourceTreePin{Path: path, SHA1: strings.Repeat("a", 40)})
	}
	for _, path := range []string{"go.mod", "go.sum", "go.work", "go.work.sum", "staging/src/kubevirt.io/api/go.mod", "staging/src/kubevirt.io/api/go.sum", "staging/src/kubevirt.io/client-go/go.mod", "staging/src/kubevirt.io/client-go/go.sum", "vendor/modules.txt", source, "pkg/virt-operator/resource/generate/components/virttemplate.go", "pkg/virt-operator/resource/generate/install/strategy.go"} {
		grant.Files = append(grant.Files, crdversions.SourceFilePin{Path: path, SHA256: "sha256:" + strings.Repeat("a", 64)})
	}
	target.SourceGrants = []crdversions.SourceGrant{grant}
	row := customresources.Project{Groups: []customresources.Group{{Name: "kubevirt.io", Source: "https://github.com/kubevirt/kubevirt/blob/" + obTo + "/" + source}}}
	for _, name := range []string{"read", "list", "rest"} {
		t.Run(name, func(t *testing.T) {
			st := &constructorBudgetStub{}
			for _, pin := range grant.Trees {
				st.entries = append(st.entries, extract.TreeEntry{Path: pin.Path, Mode: "040000", Type: "tree", SHA: pin.SHA1})
			}
			for _, pin := range grant.Files {
				st.entries = append(st.entries, extract.TreeEntry{Path: pin.Path, Mode: "100644", Type: "blob", SHA: strings.Repeat("a", 40)})
			}
			b := &budgetSource{src: st, stats: st}
			switch name {
			case "read":
				b.reads = OnboardingReadBudget
			case "list":
				b.lists = OnboardingListBudget
			case "rest":
				st.api = OnboardingRESTBudget
			}
			if err := checkGroupSources(b, target, row, obTo); err == nil || !b.over || !strings.Contains(err.Error(), "budget") {
				t.Fatalf("constructor citation escaped %s budget: err=%v over=%v", name, err, b.over)
			}
		})
	}
}
