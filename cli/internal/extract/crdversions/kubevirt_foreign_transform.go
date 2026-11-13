// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"path"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const kvMultusBundle = "kubevirtci/cluster-up/cluster/kind-sriov/sriov-components/manifests/multus/multus.yaml"

// kubevirtForeignChain admits one closed foreign-only transform shape. It
// never renders a manifest: the exact selector cannot select a CRD, and the
// two literal patches change only the DaemonSet's logging arguments.
func (x *Extractor) kubevirtForeignChain(r extract.PinnedReader, repo extract.RepoRef, commit, by string, e Exclusion, info map[string]*surfaceInfo, parents map[string][]string, inv *Inventory) bool {
	if x.target.ConstructorProfile != kubevirtProfile || x.target.Project != "kubevirt" || x.target.Repo != "github.com/kubevirt/kubevirt" || e.Foreign == nil || !e.Foreign.IdentityOnly || e.Path != kvMultusBundle || inv == nil || !inv.Complete || inv.ConstructorProfile != kubevirtProfile || inv.ConstructorGrant == nil {
		return false
	}
	// The verified grant includes the complete source tree of every caller.
	granted := false
	for _, p := range inv.ConstructorGrant.Trees {
		granted = granted || p.Path == "kubevirtci"
	}
	if !granted {
		return false
	}
	state := map[string]int{}
	var visit func(string, int) bool
	visit = func(p string, depth int) bool {
		if depth > 64 || state[p] == 1 {
			return false
		}
		if state[p] == 2 {
			return true
		}
		state[p] = 1
		i := info[p]
		if i == nil || !strings.HasPrefix(p, "kubevirtci/") || !isKustomizationName(path.Base(p)) {
			return false
		}
		if !i.plain {
			if p != path.Join(path.Dir(kvMultusBundle), "kustomization.yaml") || !kubevirtMultusTransform(r, repo, commit, p) {
				return false
			}
		}
		for _, parent := range parents[p] {
			if !visit(parent, depth+1) {
				return false
			}
		}
		state[p] = 2
		return true
	}
	return visit(by, 0)
}

func kvExactFields(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}

func kvReadYAML(r extract.PinnedReader, repo extract.RepoRef, c, p string) ([]any, bool) {
	e, err := kvEntry(r, repo, c, p)
	if err != nil || e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
		return nil, false
	}
	b, err := r.Read(repo, c, p)
	if err != nil || len(b) > maxForeignBytes {
		return nil, false
	}
	_, v, err := decodeStrict(b)
	return v, err == nil
}

func kubevirtMultusTransform(r extract.PinnedReader, repo extract.RepoRef, c, p string) bool {
	docs, ok := kvReadYAML(r, repo, c, p)
	if !ok || len(docs) != 1 {
		return false
	}
	m, ok := docs[0].(map[string]any)
	if !ok || !kvExactFields(m, "apiVersion", "kind", "resources", "images", "patchesJson6902") || m["apiVersion"] != "kustomize.config.k8s.io/v1beta1" || m["kind"] != "Kustomization" {
		return false
	}
	resources, ok := m["resources"].([]any)
	if !ok || len(resources) != 1 || resources[0] != "multus.yaml" {
		return false
	}
	images, ok := m["images"].([]any)
	if !ok || len(images) != 1 {
		return false
	}
	image, ok := images[0].(map[string]any)
	if !ok || !kvExactFields(image, "name", "newTag") || image["name"] != "ghcr.io/k8snetworkplumbingwg/multus-cni" || image["newTag"] != "v3.8" {
		return false
	}
	patches, ok := m["patchesJson6902"].([]any)
	if !ok || len(patches) != 1 {
		return false
	}
	patch, ok := patches[0].(map[string]any)
	if !ok || !kvExactFields(patch, "path", "target") || patch["path"] != "patch-args.yaml" {
		return false
	}
	target, ok := patch["target"].(map[string]any)
	if !ok || !kvExactFields(target, "group", "version", "kind", "name") || target["group"] != "apps" || target["version"] != "v1" || target["kind"] != "DaemonSet" || target["name"] != "kube-multus-ds" {
		return false
	}
	docs, ok = kvReadYAML(r, repo, c, path.Join(path.Dir(p), "patch-args.yaml"))
	if !ok || len(docs) != 1 {
		return false
	}
	ops, ok := docs[0].([]any)
	if !ok || len(ops) != 2 {
		return false
	}
	for i, v := range []string{"--multus-log-level=debug", "--multus-log-file=/var/log/multus.log"} {
		op, ok := ops[i].(map[string]any)
		if !ok || !kvExactFields(op, "op", "path", "value") || op["op"] != "add" || op["path"] != "/spec/template/spec/containers/0/args/-" || op["value"] != v {
			return false
		}
	}
	return true
}
