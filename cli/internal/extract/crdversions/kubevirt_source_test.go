// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func kvFixture(t *testing.T) (extract.FixtureReader, extract.RepoRef, string, string) {
	t.Helper()
	root := t.TempDir()
	repo, err := extract.ParseRepo("github.com/kubevirt/kubevirt")
	must(t, err)
	commit := strings.Repeat("a", 40)
	base := filepath.Join(root, repo.Key, "commits", commit)
	files := map[string]string{
		kvComponents + "/virttemplate.go":      "package components\n",
		"kubevirtci/keep.yaml":                 "kind: ConfigMap\n",
		"tools/util/marker.go":                 "package util\n",
		"go.mod":                               "module kubevirt.io/kubevirt\ngo 1.24.0\nreplace kubevirt.io/api => ./staging/src/kubevirt.io/api\nreplace kubevirt.io/client-go => ./staging/src/kubevirt.io/client-go\n",
		"go.sum":                               "",
		"go.work":                              "go 1.24.0\nuse (\n.\n./staging/src/kubevirt.io/api\n./staging/src/kubevirt.io/client-go\n)\n",
		"go.work.sum":                          "",
		kvAPI + "/go.mod":                      "module kubevirt.io/api\ngo 1.24.0\n",
		kvClient + "/go.mod":                   "module kubevirt.io/client-go\ngo 1.24.0\n",
		"vendor/modules.txt":                   "# kubevirt.io/api v1.8.0 => ./staging/src/kubevirt.io/api\n",
		kvConstructors:                         kvTestConstructor,
		kvInstall + "/strategy.go":             "package install\n",
		kvAPI + "/export/v1alpha1/register.go": "package v1alpha1\nimport \"k8s.io/apimachinery/pkg/runtime/schema\"\nvar SchemeGroupVersion = schema.GroupVersion{Group: \"export.kubevirt.io\", Version: \"v1alpha1\"}\n",
		kvAPI + "/core/v1/register.go":         "package v1\nimport extv1 \"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1\"\nvar ApiSupportedVersions=[]extv1.CustomResourceDefinitionVersion{{Name:\"v1\", Served:true, Storage:true}}\n",
	}
	for p, b := range files {
		full := filepath.Join(base, p)
		must(t, os.MkdirAll(filepath.Dir(full), 0755))
		must(t, os.WriteFile(full, []byte(b), 0644))
	}
	return extract.FixtureReader{Root: root}, repo, commit, base
}

func kvFixtureGrant(t *testing.T, r extract.PinnedReader, repo extract.RepoRef, c string) SourceGrant {
	t.Helper()
	var g SourceGrant
	for _, p := range kvTrees {
		e, err := kvEntry(r, repo, c, p)
		must(t, err)
		g.Trees = append(g.Trees, SourceTreePin{Path: p, SHA1: e.SHA})
	}
	for _, p := range kvPinnedFiles {
		b, err := r.Read(repo, c, p)
		if isNotFound(err) {
			g.Files = append(g.Files, SourceFilePin{Path: p, SHA256: "absent"})
			continue
		}
		must(t, err)
		s := sha256.Sum256(b)
		g.Files = append(g.Files, SourceFilePin{Path: p, SHA256: "sha256:" + hex.EncodeToString(s[:])})
	}
	return g
}

func TestKubeVirtGrantRejectsRoutingAndSourceMutants(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"module route to alternate served-false API", "go.mod", "module kubevirt.io/kubevirt\ngo 1.24.0\nreplace kubevirt.io/api => ./alternate-api\n"},
		{"workspace route only", "go.work", "go 1.24.0\nuse (\n.\n./alternate-api\n)\n"},
		{"vendor route only", "vendor/modules.txt", "# kubevirt.io/api v1.8.0 => ./alternate-api\n"},
		{"new routing input", kvAPI + "/go.sum", "changed\n"},
		{"hidden constructor", kvComponents + "/hidden.go", "package components\nfunc hidden() {}\n"},
		{"init mutator", kvComponents + "/init.go", "package components\nfunc init() {}\n"},
		{"constructor served mutation", kvConstructors, strings.Replace(kvTestConstructor, "Served:true", "Served:false", 1)},
		{"registry served mutation", kvAPI + "/core/v1/register.go", "package v1\nvar ApiSupportedVersions=[]Version{{Name:\"v1\",Served:false,Storage:false}}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, repo, c, base := kvFixture(t)
			tg := Target{SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, c)}}
			must(t, kvGrant(r, repo, c, tg))
			p := filepath.Join(base, tc.path)
			must(t, os.MkdirAll(filepath.Dir(p), 0755))
			must(t, os.WriteFile(p, []byte(tc.content), 0644))
			if err := kvGrant(r, repo, c, tg); err == nil {
				t.Fatal("mutated source/routing retained its grant")
			}
		})
	}
}

const kvTestConstructor = `package components
import extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
import exportv1alpha1 "kubevirt.io/api/export/v1alpha1"
func NewExportCrd() (*extv1.CustomResourceDefinition,error) {
 crd:=newBlankCrd()
 crd.Name="exports."+exportv1alpha1.SchemeGroupVersion.Group
 crd.Spec=extv1.CustomResourceDefinitionSpec{
  Group:exportv1alpha1.SchemeGroupVersion.Group,Scope:extv1.NamespaceScoped,
  Names:extv1.CustomResourceDefinitionNames{Kind:"Export",Plural:"exports"},
  Versions:[]extv1.CustomResourceDefinitionVersion{{Name:exportv1alpha1.SchemeGroupVersion.Version,Served:true,Storage:false},{Name:"v1",Served:true,Storage:true}},
 }
 return crd,nil
}
`

func TestKubeVirtProjectionReadsServedFromSource(t *testing.T) {
	for _, served := range []bool{true, false} {
		t.Run(map[bool]string{true: "served", false: "unserved"}[served], func(t *testing.T) {
			r, repo, c, base := kvFixture(t)
			if !served {
				must(t, os.WriteFile(filepath.Join(base, kvConstructors), []byte(strings.Replace(kvTestConstructor, "Served:true", "Served:false", 1)), 0644))
			}
			k := &kvReader{r: r, repo: repo, commit: c, fset: token.NewFileSet(), packages: map[string]*kvPackage{}, records: map[string]FileRecord{}}
			p, err := k.load(kvComponents)
			must(t, err)
			var fn *ast.FuncDecl
			for _, d := range p.files[kvConstructors].Decls {
				if f, ok := d.(*ast.FuncDecl); ok {
					fn = f
				}
			}
			got, err := k.constructor(fn)
			must(t, err)
			if got.Group != "export.kubevirt.io" || got.Kind != "Export" || got.Versions[0].Name != "v1alpha1" || got.Versions[0].Served != served || got.StorageVersion != "v1" {
				t.Fatalf("wrong source projection: %+v", got)
			}
		})
	}
}

func TestKubeVirtUnsupportedRoutingWithUpdatedPin(t *testing.T) {
	r, repo, c, base := kvFixture(t)
	must(t, os.WriteFile(filepath.Join(base, "go.mod"), []byte("module kubevirt.io/kubevirt\ngo 1.24.0\nreplace kubevirt.io/api => ./alternate-api\n"), 0644))
	tg := Target{SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, c)}}
	if err := kvGrant(r, repo, c, tg); err == nil {
		t.Fatal("an updated pin authorized an alternate API route")
	}
}

func TestKubeVirtUnknownCRDTypeImportRefused(t *testing.T) {
	r, repo, c, base := kvFixture(t)
	source := strings.Replace(kvTestConstructor, "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1", "other.example.io/fake-crd", 1)
	must(t, os.WriteFile(filepath.Join(base, kvConstructors), []byte(source), 0644))
	k := &kvReader{r: r, repo: repo, commit: c, fset: token.NewFileSet(), packages: map[string]*kvPackage{}, records: map[string]FileRecord{}}
	p, err := k.load(kvComponents)
	must(t, err)
	for _, d := range p.files[kvConstructors].Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			if _, err := k.constructor(fn); err == nil {
				t.Fatal("alternate CRD type import was projected")
			}
			return
		}
	}
	t.Fatal("missing test constructor")
}

func TestKubeVirtForeignAbsenceRequiresGrantAndNoInstallReference(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		ordinary, noGrant, reference bool
	}{
		{name: "proved absence"}, {name: "ordinary missing still void", ordinary: true}, {name: "unproved absence", noGrant: true}, {name: "missing but referenced", reference: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, repo, c, base := kvFixture(t)
			p := "kubevirtci/foreign.yaml"
			g := kvFixtureGrant(t, r, repo, c)
			g.AbsentForeign = []string{p}
			tg := Target{Project: "kubevirt", Repo: repo.Key, ConstructorProfile: kubevirtProfile, SourceGrants: []SourceGrant{g}, Exclude: []Exclusion{{Path: p, Foreign: &ForeignBundle{IdentityOnly: !tc.ordinary, Groups: []string{"foreign.example.io"}, SHA256: []string{pbDigest(foreignIdentityFixture)}}}}}
			inv := &Inventory{Complete: true, ConstructorProfile: kubevirtProfile, CRDs: []CRD{{Group: "kubevirt.io"}}}
			must(t, kvCheckGrant(r, repo, c, tg, &inv.ConstructorGrant))
			if tc.noGrant {
				inv.ConstructorGrant = nil
			}
			if tc.reference {
				file := filepath.Join(base, "deploy/kustomization.yaml")
				must(t, os.MkdirAll(filepath.Dir(file), 0755))
				must(t, os.WriteFile(file, []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- ../"+p+"\n"), 0644))
			}
			var blobs []extract.TreeEntry
			var walk func(string)
			walk = func(dir string) {
				es, err := r.List(repo, c, dir)
				must(t, err)
				for _, e := range es {
					if e.Type == "tree" {
						walk(e.Path)
					} else {
						blobs = append(blobs, e)
					}
				}
			}
			walk("")
			_, void, err := New(tg).guard(context.Background(), r, repo, c, blobs, nil, inv)
			must(t, err)
			wantVoid := tc.ordinary || tc.noGrant || tc.reference
			if void[p] != wantVoid {
				t.Fatalf("void=%v want=%v", void, wantVoid)
			}
		})
	}
}

func TestKubeVirtAbsentGrantCannotHideReplacement(t *testing.T) {
	r, repo, c, base := kvFixture(t)
	g := kvFixtureGrant(t, r, repo, c)
	p := "kubevirtci/foreign.yaml"
	g.AbsentForeign = []string{p}
	tg := Target{ConstructorProfile: kubevirtProfile, SourceGrants: []SourceGrant{g}}
	inv := &Inventory{Complete: true, ConstructorProfile: kubevirtProfile, ConstructorGrant: &g}
	e := Exclusion{Path: p, Foreign: &ForeignBundle{IdentityOnly: true}}
	x := New(tg)
	if !x.constructorForeignAbsent(e, nil, inv) {
		t.Fatal("expected absence proof")
	}
	file := filepath.Join(base, p)
	must(t, os.WriteFile(file, []byte("kind: CustomResourceDefinition\nspec: {group: kubevirt.io}\n"), 0644))
	if err := kvGrant(r, repo, c, tg); err == nil {
		t.Fatal("replacement retained source-tree grant")
	}
	updated := kvFixtureGrant(t, r, repo, c)
	updated.AbsentForeign = []string{p}
	if err := kvGrant(r, repo, c, Target{SourceGrants: []SourceGrant{updated}}); err == nil {
		t.Fatal("new source pin authorized a false absence claim")
	}
	entry, err := kvEntry(r, repo, c, p)
	must(t, err)
	if x.constructorForeignAbsent(e, []extract.TreeEntry{entry}, inv) {
		t.Fatal("existing bytes were treated as absent")
	}
	must(t, os.Remove(file))
	must(t, os.Symlink("keep.yaml", file))
	if err := kvGrant(r, repo, c, tg); err == nil {
		t.Fatal("symlink retained source-tree grant")
	}
	entry = extract.TreeEntry{Path: p, Type: "blob", Mode: "120000"}
	if x.constructorForeignAbsent(e, []extract.TreeEntry{entry}, inv) {
		t.Fatal("symlink was treated as absent")
	}
}
