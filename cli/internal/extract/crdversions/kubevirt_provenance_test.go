// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubeVirtConstructorGroupProvenance(t *testing.T) {
	for _, name := range []string{"defined", "unknown", "comment only", "stripped profile", "wrong identity", "wrong source", "wrong commit", "cmd mutation", "routing mutation", "helper mutation"} {
		t.Run(name, func(t *testing.T) {
			r, repo, commit, base := kvFixture(t)
			core := `
func NewKubeVirtCrd() (*extv1.CustomResourceDefinition,error) {
 crd:=newBlankCrd()
 crd.Name="kubevirts.kubevirt.io"
 crd.Spec=extv1.CustomResourceDefinitionSpec{
  Group:"kubevirt.io",Scope:extv1.NamespaceScoped,
  Names:extv1.CustomResourceDefinitionNames{Kind:"KubeVirt",Plural:"kubevirts"},
  Versions:[]extv1.CustomResourceDefinitionVersion{{Name:"v1",Served:true,Storage:true}},
 }
 return crd,nil
}
`
			content := kvTestConstructor + core
			if name == "comment only" {
				content += "\nconst misleading = `\ngroup: spoof.example.io\n`\n"
			}
			must(t, os.WriteFile(filepath.Join(base, kvConstructors), []byte(content), 0644))
			caller := "package install\nimport components \"kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/components\"\nimport extv1 \"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1\"\nvar constructors=[]func()(*extv1.CustomResourceDefinition,error){components.NewExportCrd}\n"
			must(t, os.WriteFile(filepath.Join(base, kvInstall, "strategy.go"), []byte(caller), 0644))
			target := Target{Project: "kubevirt", Repo: repo.Key, Catalog: CatalogCNCF, Component: "pkg:github/kubevirt/kubevirt", FactProject: "kubevirt", ConstructorProfile: kubevirtProfile, SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, commit)}}
			group, sourcePath := "export.kubevirt.io", kvConstructors
			switch name {
			case "unknown":
				group = "unknown.example.io"
			case "comment only":
				group = "spoof.example.io"
			case "stripped profile":
				target.ConstructorProfile = ""
			case "wrong identity":
				target.Project = "other"
			case "wrong source":
				sourcePath = kvComponents + "/other.go"
			case "wrong commit":
				commit = strings.Repeat("b", 40)
			case "cmd mutation":
				must(t, os.WriteFile(filepath.Join(base, "cmd", "virt-operator", "init.go"), []byte("package main\nfunc init() {}\n"), 0644))
			case "routing mutation":
				must(t, os.WriteFile(filepath.Join(base, "go.work"), []byte("go 1.24.0\nuse ./alternate\n"), 0644))
			case "helper mutation":
				must(t, os.WriteFile(filepath.Join(base, kvComponents, "helper.go"), []byte("package components\n"), 0644))
			}
			err := VerifyKubeVirtConstructorGroups(r, target, commit, sourcePath, []string{group})
			if name == "defined" && err != nil {
				t.Fatalf("granted constructor group refused: %v", err)
			}
			if name != "defined" && err == nil {
				t.Fatal("unproved constructor group accepted")
			}
		})
	}
}
