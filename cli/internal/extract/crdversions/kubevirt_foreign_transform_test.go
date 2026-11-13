// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

const kvMultusKustFixture = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- multus.yaml
images:
- name: ghcr.io/k8snetworkplumbingwg/multus-cni
  newTag: v3.8
patchesJson6902:
- path: patch-args.yaml
  target:
    group: apps
    version: v1
    kind: DaemonSet
    name: kube-multus-ds
`
const kvMultusPatchFixture = `- op: add
  path: /spec/template/spec/containers/0/args/-
  value: "--multus-log-level=debug"
- op: add
  path: /spec/template/spec/containers/0/args/-
  value: "--multus-log-file=/var/log/multus.log"
`

func TestKubeVirtForeignTransformHasLiteralNonCRDTarget(t *testing.T) {
	for _, tc := range []struct {
		name, kust, patch string
		want              bool
	}{
		{"literal logging patch", kvMultusKustFixture, kvMultusPatchFixture, true},
		{"CRD selector", strings.Replace(kvMultusKustFixture, "kind: DaemonSet", "kind: CustomResourceDefinition", 1), kvMultusPatchFixture, false},
		{"wildcard selector", strings.Replace(kvMultusKustFixture, "name: kube-multus-ds", "name: .*", 1), kvMultusPatchFixture, false},
		{"unknown namespace", kvMultusKustFixture + "    namespace: default\n", kvMultusPatchFixture, false},
		{"group selector", strings.Replace(kvMultusKustFixture, "group: apps", "group: apiextensions.k8s.io", 1), kvMultusPatchFixture, false},
		{"group mutation", kvMultusKustFixture, strings.Replace(kvMultusPatchFixture, "/spec/template/spec/containers/0/args/-", "/spec/group", 1), false},
		{"name mutation", kvMultusKustFixture, strings.Replace(kvMultusPatchFixture, "/spec/template/spec/containers/0/args/-", "/metadata/name", 1), false},
		{"version mutation", kvMultusKustFixture, strings.Replace(kvMultusPatchFixture, "/spec/template/spec/containers/0/args/-", "/spec/versions/0/served", 1), false},
		{"patch operation", kvMultusKustFixture, strings.Replace(kvMultusPatchFixture, "op: add", "op: replace", 1), false},
		{"new argument", kvMultusKustFixture, strings.Replace(kvMultusPatchFixture, "--multus-log-level=debug", "--other-behavior", 1), false},
		{"configuration", kvMultusKustFixture + "configurations: [fields.yaml]\n", kvMultusPatchFixture, false},
		{"generator", kvMultusKustFixture + "generators: [generator.yaml]\n", kvMultusPatchFixture, false},
		{"replacement", kvMultusKustFixture + "replacements: []\n", kvMultusPatchFixture, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, repo, c, base := kvFixture(t)
			dir := path.Dir(kvMultusBundle)
			for name, data := range map[string]string{"kustomization.yaml": tc.kust, "patch-args.yaml": tc.patch, "multus.yaml": foreignIdentityFixture} {
				p := filepath.Join(base, dir, name)
				must(t, os.MkdirAll(filepath.Dir(p), 0755))
				must(t, os.WriteFile(p, []byte(data), 0644))
			}
			tg := Target{Project: "kubevirt", Repo: repo.Key, ConstructorProfile: kubevirtProfile, SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, c)}}
			inv := &Inventory{Complete: true, ConstructorProfile: kubevirtProfile}
			must(t, kvCheckGrant(r, repo, c, tg, &inv.ConstructorGrant))
			by := path.Join(dir, "kustomization.yaml")
			infos := map[string]*surfaceInfo{by: {plain: false}}
			e := Exclusion{Path: kvMultusBundle, Foreign: &ForeignBundle{IdentityOnly: true}}
			got := New(tg).kubevirtForeignChain(r, repo, c, by, e, infos, nil, inv)
			if got != tc.want {
				t.Fatalf("transform accepted=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestKubeVirtForeignTransformRejectsUnresolvedAncestors(t *testing.T) {
	r, repo, c, base := kvFixture(t)
	dir := path.Dir(kvMultusBundle)
	for name, data := range map[string]string{"kustomization.yaml": kvMultusKustFixture, "patch-args.yaml": kvMultusPatchFixture} {
		p := filepath.Join(base, dir, name)
		must(t, os.MkdirAll(filepath.Dir(p), 0755))
		must(t, os.WriteFile(p, []byte(data), 0644))
	}
	tg := Target{Project: "kubevirt", Repo: repo.Key, ConstructorProfile: kubevirtProfile, SourceGrants: []SourceGrant{kvFixtureGrant(t, r, repo, c)}}
	inv := &Inventory{Complete: true, ConstructorProfile: kubevirtProfile}
	must(t, kvCheckGrant(r, repo, c, tg, &inv.ConstructorGrant))
	by := path.Join(dir, "kustomization.yaml")
	infos := map[string]*surfaceInfo{by: {plain: false}}
	e := Exclusion{Path: kvMultusBundle, Foreign: &ForeignBundle{IdentityOnly: true}}
	x := New(tg)
	if x.kubevirtForeignChain(r, repo, c, by, e, infos, map[string][]string{by: {"kubevirtci/missing/kustomization.yaml"}}, inv) {
		t.Fatal("unresolved ancestor accepted")
	}
	if x.kubevirtForeignChain(r, repo, c, by, e, infos, map[string][]string{by: {by}}, inv) {
		t.Fatal("cyclic ancestor accepted")
	}
	e.Foreign.IdentityOnly = false
	if x.kubevirtForeignChain(r, repo, c, by, e, infos, nil, inv) {
		t.Fatal("ordinary foreign chain changed behavior")
	}
}
