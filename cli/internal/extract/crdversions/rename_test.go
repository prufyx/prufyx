// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// crdIn renders crd(kind, versions...) under another group.
func crdIn(group, kind string, versions ...string) string {
	return strings.ReplaceAll(crd(kind, versions...), synthGroup, group)
}

// A kustomization patch given inline as a string is read like a patch
// file: a JSON 6902 list that only touches metadata labels is schema-only;
// one that adds a version, a strategic merge string (whose embedded
// manifest is a reference) and a mapping stay references, and a templated
// file is unread.
func TestInlineKustomizationPatch(t *testing.T) {
	kust := func(patch string) string {
		return "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- generated/a.yaml\npatches:\n- target:\n    group: apiextensions.k8s.io\n    version: v1\n    kind: CustomResourceDefinition\n    name: alphas.synth.example.io\n# a comment between the keys\n  patch: " + patch
	}
	for _, tc := range []struct {
		name, patch, class, detail string
	}{
		{"labels", "|-\n    - op: add\n      path: \"/metadata/labels\"\n      value:\n        app.kubernetes.io/name: pgo\n", ClassSchemaPatch, ""},
		{"a version added", "|-\n    - op: add\n      path: /spec/versions/-\n      value: {name: v1alpha1, served: false, storage: false}\n", ClassReference, `inline patch 1: operation 0 path "/spec/versions/-" is outside`},
		{"a strategic merge string", "|-\n    apiVersion: apiextensions.k8s.io/v1\n    kind: CustomResourceDefinition\n    metadata:\n      name: alphas.synth.example.io\n", ClassReference, "holds the CustomResourceDefinition kind but defines none at the top level"},
		{"not a list", "|-\n    op: add\n", ClassReference, "inline patch 1: not a JSON 6902 operation list"},
		{"a mapping", "\n    op: add\n", ClassReference, "a CustomResourceDefinition patch is inline or names no file"},
		{"templated", "|-\n    - op: add\n      path: /metadata/labels/v\n      value: {{ .Version }}\n", ClassUnread, "a template expression outside metadata"},
	} {
		_, _, f := quietPair(t, "build/crd/alphas/kustomization.yaml", kust(tc.patch))
		if f == nil || f.Class != tc.class || !strings.Contains(f.Detail, tc.detail) {
			t.Errorf("%s: %+v", tc.name, f)
		}
	}
	// A path and an inline patch in one entry are not read.
	_, _, f := quietPair(t, "build/crd/alphas/kustomization.yaml", strings.Replace(kust("|-\n    - op: add\n      path: /metadata/labels/x\n      value: y\n"), "  patch:", "  path: p.yaml\n  patch:", 1))
	if f == nil || f.Class != ClassReference || f.Detail != "a CustomResourceDefinition patch is inline or names no file" {
		t.Errorf("path and patch: %+v", f)
	}
}

// A definition moved to another API group (Percona's PostgreSQL operator
// v3.0.0: postgres-operator.crunchydata.com to upstream.pgv2.percona.com)
// is recorded as removed with its successor, never as a rule, and the pair
// is not attestable.
func TestGroupRenameSuccessor(t *testing.T) {
	const upstream = "upstream.synth.example.io"
	run := func(from, to map[string]string) (extract.PairRecord, PairProof) {
		s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
		return pairOf(t, runSynth(t, synthTarget(), s), "1.0.0", "1.1.0")
	}
	from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": crdIn(upstream, "Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1")}
	p, proof := run(from, to)
	if p.Status != extract.PairDerived || len(p.Rules) != 0 || proof.Completeness.Attestable || len(proof.Removals) != 0 {
		t.Fatalf("%s %q rules %v %+v", p.Status, p.Reason, p.Rules, proof.Completeness)
	}
	if len(proof.DefinitionsRemoved) != 1 || proof.DefinitionsRemoved[0].CRD != "alphas."+synthGroup || proof.DefinitionsRemoved[0].Successor != "alphas."+upstream {
		t.Fatalf("removed %+v", proof.DefinitionsRemoved)
	}
	if !strings.Contains(strings.Join(proof.Completeness.Reasons, "\n"), "v1.1.0 no longer defines alphas.synth.example.io: whether an upgraded cluster keeps the old definition or deletes it with its objects depends on the install method and is not established; a definition of kind Alpha exists as alphas.upstream.synth.example.io; whether objects are converted is not established") {
		t.Fatalf("reasons %v", proof.Completeness.Reasons)
	}
	// Two definitions of the kind and plural under other groups: none is
	// named.
	to["deploy/crds/c.yaml"] = crdIn("other.synth.example.io", "Alpha", "v1")
	if _, proof = run(from, to); len(proof.DefinitionsRemoved) != 1 || proof.DefinitionsRemoved[0].Successor != "" {
		t.Fatalf("two successors %+v", proof.DefinitionsRemoved)
	}
	delete(to, "deploy/crds/c.yaml")
	// The new group already defined in the earlier line: not a successor.
	from["deploy/crds/c.yaml"] = crdIn(upstream, "Alpha", "v1")
	if _, proof = run(from, to); len(proof.DefinitionsRemoved) != 1 || proof.DefinitionsRemoved[0].Successor != "" {
		t.Fatalf("earlier %+v", proof.DefinitionsRemoved)
	}
	delete(from, "deploy/crds/c.yaml")
	// Another plural is not the same resource.
	if _, proof = run(from, map[string]string{"deploy/crds/a.yaml": strings.ReplaceAll(crdIn(upstream, "Alpha", "v1"), "alphas", "alphae"), "deploy/crds/b.yaml": crd("Beta", "v1")}); len(proof.DefinitionsRemoved) != 1 || proof.DefinitionsRemoved[0].Successor != "" {
		t.Fatalf("other plural %+v", proof.DefinitionsRemoved)
	}
	// An opaque file in the open tree: the old definition is not
	// established to be gone, and the pair is withheld.
	to["other/crds.yaml"] = "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\n"
	if p, _ = run(from, to); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "a removed definition cannot be told from a moved one") {
		t.Fatalf("opaque: %s %q", p.Status, p.Reason)
	}
}
