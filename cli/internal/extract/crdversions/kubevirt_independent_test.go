// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentKubeVirtRegistryVersionProvenance(t *testing.T) {
	r, repo, commit, base := kvFixture(t)
	source := strings.Replace(kvTestConstructor, `[]extv1.CustomResourceDefinitionVersion{{Name:exportv1alpha1.SchemeGroupVersion.Version,Served:true,Storage:false},{Name:"v1",Served:true,Storage:true}}`, `newCRDVersions()`, 1)
	if source == kvTestConstructor {
		t.Fatal("fixture version expression not found")
	}
	must(t, os.WriteFile(filepath.Join(base, kvConstructors), []byte(source), 0644))
	k := &kvReader{r: r, repo: repo, commit: commit, fset: token.NewFileSet(), packages: map[string]*kvPackage{}, records: map[string]FileRecord{}}
	p, err := k.load(kvComponents)
	must(t, err)
	for _, decl := range p.files[kvConstructors].Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewExportCrd" {
			continue
		}
		got, err := k.constructor(fn)
		must(t, err)
		wantPath := kvAPI + "/core/v1/register.go"
		if got.VersionsPath != wantPath || len(got.Versions) != 1 || got.Versions[0].SourcePath != wantPath || got.Versions[0].StartLine != 3 || got.Versions[0].ServedLine != 3 || got.Versions[0].StorageLine != 3 {
			t.Fatalf("registry source provenance: %+v", got)
		}
		return
	}
	t.Fatal("constructor missing")
}

func TestIndependentKubeVirtGrantRejectsHelperAndCallerChanges(t *testing.T) {
	for _, tc := range []struct{ name, path, initial, changed string }{
		{"helper", kvComponents + "/helper.go", "package components\nfunc adjust() {}\n", "package components\nfunc adjust() { mutate() }\n"},
		{"caller", kvInstall + "/strategy.go", "package install\nfunc install() { add() }\n", "package install\nfunc install() {}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, repo, commit, base := kvFixture(t)
			p := filepath.Join(base, tc.path)
			must(t, os.WriteFile(p, []byte(tc.initial), 0644))
			target := Target{SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, commit)}}
			must(t, kvGrant(r, repo, commit, target))
			must(t, os.WriteFile(p, []byte(tc.changed), 0644))
			if err := kvGrant(r, repo, commit, target); err == nil {
				t.Fatal("changed closure member retained its grant")
			}
		})
	}
}
