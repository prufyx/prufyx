// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The layout of Elastic Cloud on Kubernetes, in small: controller-gen
// writes config/resources, and config/patches renders it (with an unserved
// v1alpha1 added to Alpha and a schema removed from Beta) into the listed
// bundle deploy/crds/a.yaml.
const (
	prePatchDir  = "config/resources/"
	prePatchKust = "config/patches/kustomization.yaml"
)

func prePatchExclusion() Exclusion {
	return Exclusion{Path: prePatchDir, Reason: "controller-gen output rendered into the listed bundle", Evidence: "the Makefile renders the bundle with kubectl kustomize config/patches", PrePatch: prePatchKust}
}

func prePatchTarget(name string) string {
	return "  - target:\n      group: apiextensions.k8s.io\n      version: v1\n      kind: CustomResourceDefinition\n      name: " + name + "\n"
}

const addUnservedV1alpha1 = "# keep v1alpha1 in status.storedVersions working\n- op: add\n  path: /spec/versions/-\n  value:\n    name: v1alpha1\n    served: false\n    storage: false\n    schema:\n      openAPIV3Schema:\n        type: object\n"

// prePatchFiles is one release of the layout: alpha lists the versions of
// Alpha before the patches (v1alpha1 is added, unserved, by the patch).
func prePatchFiles(alpha ...string) map[string]string {
	bundle := crd("Alpha", append([]string{"v1alpha1:off"}, alpha...)...) + "---\n" + crd("Beta", "v1")
	return map[string]string{
		"deploy/crds/a.yaml":                  bundle,
		"config/resources/alphas.yaml":        crd("Alpha", alpha...),
		"config/resources/betas.yaml":         crd("Beta", "v1"),
		"config/resources/kustomization.yaml": "resources:\n  - alphas.yaml\n  - betas.yaml\n",
		prePatchKust: "resources:\n  - ../resources\n\npatches:\n" +
			prePatchTarget("alphas."+synthGroup) + "    path: add-v1alpha1.yaml\n" +
			prePatchTarget("betas."+synthGroup) + "    path: schema.yaml\n",
		"config/patches/add-v1alpha1.yaml": addUnservedV1alpha1,
		"config/patches/schema.yaml":       "- op: remove\n  path: /spec/versions/0/schema/openAPIV3Schema/properties\n- op: add\n  path: /metadata/labels/x\n  value: y\n",
	}
}

// prePatchPair runs Alpha v1beta1 -> v1beta1 unserved with the layout at
// both releases, each changed by edit.
func prePatchPair(t *testing.T, edit func(files map[string]string), exclude ...Exclusion) (extract.PairRecord, PairProof) {
	t.Helper()
	from, to := prePatchFiles("v1beta1", "v1"), prePatchFiles("v1beta1:off", "v1")
	if edit != nil {
		edit(from)
		edit(to)
	}
	if exclude == nil {
		exclude = []Exclusion{prePatchExclusion()}
	}
	s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
	return pairOf(t, runSynth(t, synthTarget(exclude...), s), "1.0.0", "1.1.0")
}

// An accepted rendering: the resource files are pre-patch copies and the
// patches kustomization is class pre-patch; neither blocks, and the rule
// holds for the whole lines.
func TestPrePatchAccepted(t *testing.T) {
	p, proof := prePatchPair(t, nil)
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable || !proof.To.Scan.Clean() {
		t.Fatalf("%s %q %+v %+v", p.Status, p.Reason, proof.Completeness, proof.To.Scan.Findings)
	}
	for _, sc := range []*ScanRecord{proof.From.Scan, proof.To.Scan} {
		if len(sc.Copies) != 0 {
			t.Fatalf("copies %v", sc.Copies)
		}
		a, b, k := findingOf(sc, "config/resources/alphas.yaml"), findingOf(sc, "config/resources/betas.yaml"), findingOf(sc, prePatchKust)
		if a == nil || a.Class != ClassPrePatchCopy || a.Location != prePatchDir || !slices.Equal(a.CRDs, []string{"alphas." + synthGroup}) || a.SHA256 == "" {
			t.Fatalf("alphas %+v", a)
		}
		if !strings.Contains(a.Detail, "alphas.synth.example.io: adds unserved v1alpha1") || !strings.Contains(a.Detail, prePatchKust) {
			t.Fatalf("alphas detail %q", a.Detail)
		}
		if b == nil || b.Class != ClassPrePatchCopy || b.Detail != "with the patches of "+prePatchKust+" applied (betas.synth.example.io: 2 schema-only operations), a copy of the listed paths" {
			t.Fatalf("betas %+v", b)
		}
		if k == nil || k.Class != ClassPrePatch || k.Location != "" || k.SHA256 == "" {
			t.Fatalf("kustomization %+v", k)
		}
		for _, f := range []*Finding{a, b, k} {
			if f.blocks() || f.opaque() || f.unreadable() {
				t.Fatalf("effects of %+v", f)
			}
		}
	}
	if !slices.Equal(proof.From.Scan.Findings[1].Served, []string{synthGroup + "/v1/Alpha", synthGroup + "/v1beta1/Alpha"}) {
		t.Fatalf("served %+v", proof.From.Scan.Findings[1])
	}
	// The same files with no exclusion: the resource that lacks v1alpha1
	// is a conflict in the open tree and withholds the pair.
	p, _ = prePatchPair(t, nil, Exclusion{Path: "other/", Reason: "unrelated test fixtures", Evidence: "read only by the tests of the project"})
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "config/resources/alphas.yaml defines alphas.synth.example.io differently") {
		t.Fatalf("no exclusion: %s %q", p.Status, p.Reason)
	}
}

// Every shape the reader does not accept refuses the whole entry: the
// files keep their classes (the resource that lacks v1alpha1 stays a
// conflict and withholds the rule) and the kustomization stays a reference
// that says why.
func TestPrePatchRefusals(t *testing.T) {
	addWith := func(value string) func(map[string]string) {
		return func(f map[string]string) {
			f["config/patches/add-v1alpha1.yaml"] = "- op: add\n  path: /spec/versions/-\n  value:\n" + value
		}
	}
	kust := func(f map[string]string, old, new string) {
		if !strings.Contains(f[prePatchKust], old) {
			panic(old)
		}
		f[prePatchKust] = strings.Replace(f[prePatchKust], old, new, 1)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]string)
		want string
		// conflict: the resource that lacks v1alpha1 is still there.
		conflict bool
	}{
		{"served true", addWith("    name: v1alpha1\n    served: true\n    storage: false\n"), "adds version v1alpha1 without served: false and storage: false", true},
		{"served as a string", addWith("    name: v1alpha1\n    served: \"false\"\n    storage: false\n"), "without served: false and storage: false", true},
		{"no storage", addWith("    name: v1alpha1\n    served: false\n"), "without served: false and storage: false", true},
		{"another key", addWith("    name: v1alpha1\n    served: false\n    storage: false\n    deprecated: true\n"), `adds a version with key "deprecated"`, true},
		{"add of an existing version", func(f map[string]string) {
			f["config/patches/add-v1alpha1.yaml"] = strings.Replace(addUnservedV1alpha1, "name: v1alpha1", "name: v1", 1)
		}, "adds version v1, which alphas.synth.example.io already lists", true},
		{"remove a version", func(f map[string]string) {
			f["config/patches/add-v1alpha1.yaml"] = "- op: remove\n  path: /spec/versions/0\n"
		}, `operation 0 is op "remove"`, true},
		{"replace served", func(f map[string]string) {
			f["config/patches/schema.yaml"] = "- op: replace\n  path: /spec/versions/1/served\n  value: false\n"
		}, `operation 0 is op "replace"`, true},
		{"add elsewhere", func(f map[string]string) {
			f["config/patches/add-v1alpha1.yaml"] = strings.Replace(addUnservedV1alpha1, "/spec/versions/-", "/spec/versions/0", 1)
		}, `adds at "/spec/versions/0"`, true},
		{"regex target name", func(f map[string]string) {
			kust(f, "name: alphas.synth.example.io", "name: alphas.synth.example.i.")
		}, `target name "alphas.synth.example.i." is not a literal definition name`, true},
		{"wildcard target name", func(f map[string]string) {
			kust(f, "name: alphas.synth.example.io", "name: alpha.*")
		}, "is not a literal definition name", true},
		{"target name selecting two definitions", func(f map[string]string) {
			other := strings.ReplaceAll(crd("Alpha", "v1"), "synth.example.io", "synth-example.io")
			f["config/resources/other.yaml"] = other
			f["config/resources/kustomization.yaml"] += "  - other.yaml\n"
			f["deploy/crds/a.yaml"] += "---\n" + other
		}, "the patch target alphas.synth.example.io also selects alphas.synth-example.io", true},
		{"target name no resource defines", func(f map[string]string) {
			kust(f, "name: betas.synth.example.io", "name: gammas.synth.example.io")
		}, "a patch targets gammas.synth.example.io, which no resource defines", true},
		{"other target kind", func(f map[string]string) {
			kust(f, "      version: v1\n", "      version: v1beta1\n")
		}, "target is not group apiextensions.k8s.io, version v1", true},
		{"target namespace", func(f map[string]string) {
			kust(f, "      version: v1\n", "      version: v1\n      namespace: x\n")
		}, `target has key "namespace"`, true},
		{"inline patch", func(f map[string]string) {
			kust(f, "    path: add-v1alpha1.yaml\n", "    patch: |-\n      - op: add\n        path: /spec/versions/-\n        value: {name: v1alpha1, served: false, storage: false}\n")
		}, `has key "patch" (only target and path are read)`, true},
		{"commonLabels", func(f map[string]string) {
			f[prePatchKust] += "commonLabels:\n  app: x\n"
		}, `has key "commonLabels" (only resources and patches are read)`, true},
		{"namePrefix", func(f map[string]string) {
			f[prePatchKust] += "namePrefix: x-\n"
		}, `has key "namePrefix"`, true},
		{"patchesStrategicMerge", func(f map[string]string) {
			f[prePatchKust] += "patchesStrategicMerge:\n- smp.yaml\n"
		}, `has key "patchesStrategicMerge"`, true},
		{"patch path outside the directory", func(f map[string]string) {
			kust(f, "path: schema.yaml", "path: ../x.yaml")
			f["config/x.yaml"] = f["config/patches/schema.yaml"]
		}, `path "../x.yaml" is not a file inside config/patches`, true},
		{"missing patch file", func(f map[string]string) {
			delete(f, "config/patches/schema.yaml")
		}, "config/patches/schema.yaml does not exist", true},
		{"templated patch", func(f map[string]string) {
			f["config/patches/add-v1alpha1.yaml"] = strings.Replace(addUnservedV1alpha1, "name: v1alpha1", "name: {{ .Version }}", 1)
		}, "add-v1alpha1.yaml: templated", true},
		{"two resources", func(f map[string]string) {
			kust(f, "  - ../resources\n", "  - ../resources\n  - ../other\n")
		}, "does not have exactly one resource", true},
		{"resource elsewhere", func(f map[string]string) {
			kust(f, "  - ../resources\n", "  - ../generated\n")
		}, "does not have exactly one resource, the entry directory config/resources", true},
		{"a resources file not listed", func(f map[string]string) {
			f["config/resources/kustomization.yaml"] = "resources:\n  - alphas.yaml\n"
		}, "config/resources/betas.yaml names the CustomResourceDefinition kind and is not a resource of config/resources/kustomization.yaml", true},
		{"a CRD file in a subdirectory", func(f map[string]string) {
			f["config/resources/old/gammas.yaml"] = crd("Gamma", "v1")
		}, "config/resources/old/gammas.yaml names the CustomResourceDefinition kind and is not a resource", true},
		{"a listed resource without a definition", func(f map[string]string) {
			f["config/resources/kustomization.yaml"] += "  - ns.yaml\n"
			f["config/resources/ns.yaml"] = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"
		}, "resource config/resources/ns.yaml of config/resources/kustomization.yaml does not define", true},
		{"a resource with another document", func(f map[string]string) {
			f["config/resources/betas.yaml"] += "---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"
		}, "resource config/resources/betas.yaml is not strictly read as apiextensions.k8s.io/v1 definitions only", true},
		{"resources kustomization with another key", func(f map[string]string) {
			f["config/resources/kustomization.yaml"] += "namespace: x\n"
		}, `config/resources/kustomization.yaml has key "namespace"`, true},
		{"no resources kustomization", func(f map[string]string) {
			delete(f, "config/resources/kustomization.yaml")
		}, "config/resources/kustomization.yaml does not exist", true},
		{"a resource missing from the bundle", func(f map[string]string) {
			f["config/resources/gammas.yaml"] = crd("Gamma", "v1")
			f["config/resources/kustomization.yaml"] += "  - gammas.yaml\n"
		}, "the listed paths do not define gammas.synth.example.io", true},
		{"bundle with an extra CRD", func(f map[string]string) {
			f["deploy/crds/a.yaml"] += "---\n" + crd("Gamma", "v1")
		}, "the listed paths define gammas.synth.example.io, which no resource does", true},
		{"patched versions differ from the bundle", func(f map[string]string) {
			f["config/resources/betas.yaml"] = crd("Beta", "v1beta1", "v1")
		}, "betas.synth.example.io: versions v1:served,v1beta1:served once patched, v1:served in deploy/crds/a.yaml", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, proof := prePatchPair(t, tc.edit)
			if tc.conflict && (p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "config/resources/alphas.yaml is conflict")) {
				t.Fatalf("%s %q", p.Status, p.Reason)
			}
			for _, sc := range []*ScanRecord{proof.To.Scan} {
				if sc.Clean() {
					t.Fatal("clean scan")
				}
				a, k := findingOf(sc, "config/resources/alphas.yaml"), findingOf(sc, prePatchKust)
				if a == nil || a.Class != ClassConflict || a.Location != prePatchDir {
					t.Fatalf("alphas %+v", a)
				}
				if b := findingOf(sc, "config/resources/betas.yaml"); b != nil && b.Class == ClassPrePatchCopy {
					t.Fatalf("betas %+v", b)
				}
				if k == nil || k.Class != ClassReference || !strings.Contains(k.Detail, prePatchRefused) || !strings.Contains(k.Detail, tc.want) {
					t.Fatalf("kustomization %+v, want %q", k, tc.want)
				}
			}
		})
	}
	// With an existing v1alpha1 in the resource the file is a copy; the
	// add is still refused, and only attestation is blocked.
	p, proof := prePatchPair(t, func(f map[string]string) {
		f["config/resources/alphas.yaml"] = strings.Replace(f["deploy/crds/a.yaml"], "---\n"+crd("Beta", "v1"), "", 1)
	})
	k := findingOf(proof.To.Scan, prePatchKust)
	if p.Status != extract.PairDerived || proof.Completeness.Attestable || !slices.Contains(proof.To.Scan.Copies, "config/resources/alphas.yaml") || k == nil || !strings.Contains(k.Detail, "adds version v1alpha1, which alphas.synth.example.io already lists") {
		t.Fatalf("%s %q %+v %+v", p.Status, p.Reason, proof.Completeness, k)
	}
}

// The loader: prePatch excludes copies, names a kustomization outside the
// entry and the listed paths, and is given on a directory prefix only.
// Such an entry may lie under a CRD directory: its claim is checked.
func TestPrePatchLoader(t *testing.T) {
	entry := func(p, prePatch string, copies bool) string {
		return fmt.Sprintf(`{"path":%q,"repo":"github.com/o/p","reason":"controller-gen output of the bundle","evidence":"the Makefile renders the listed bundle from it with kubectl kustomize","copies":%v,"prePatch":%q}`, p, copies, prePatch)
	}
	if _, err := LoadTarget("target-p.json", testTargetsJSON(entry("config/crds/v1/resources/", "config/crds/v1/patches/kustomization.yaml", false))); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ ej, want string }{
		"copies and prePatch":   {entry("config/crds/v1/resources/", "config/crds/v1/patches/kustomization.yaml", true), "copies and prePatch exclude each other"},
		"a file":                {entry("config/crds/v1/resources/a.yaml", "config/crds/v1/patches/kustomization.yaml", false), "directory prefix"},
		"a pattern":             {entry("config/crds/v1/resources/*.yaml", "config/crds/v1/patches/kustomization.yaml", false), "directory prefix"},
		"unclean kustomization": {entry("config/crds/v1/resources/", "config/crds/v1/../patches/kustomization.yaml", false), "clean repository path of a kustomization"},
		"not a kustomization":   {entry("config/crds/v1/resources/", "config/crds/v1/patches/render.yaml", false), "clean repository path of a kustomization"},
		"under the entry":       {entry("config/crds/v1/resources/", "config/crds/v1/resources/patches/kustomization.yaml", false), "lies under the entry"},
		"under a listed path":   {entry("config/crds/v1/resources/", "crds/a.yaml/kustomization.yaml", false), "lies under the listed path crds/a.yaml"},
		"copies alone":          {entry("config/crds/v1/resources/", "", false), "never excluded"},
	} {
		if _, err := LoadTarget("target-p.json", testTargetsJSON(tc.ej)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// The reviewed entry of Elastic Cloud on Kubernetes.
	tg, ok := TargetFor("eck-operator")
	if !ok || len(tg.Exclude) != 1 || tg.Exclude[0].PrePatch != "config/crds/v1/patches/kustomization.yaml" || tg.Exclude[0].Path != "config/crds/v1/resources/" || tg.Exclude[0].Copies {
		t.Fatalf("eck-operator %+v", tg.Exclude)
	}
	// The install-surface guard does not void a pre-patch entry, like a
	// declared copy: its claim is checked instead.
	if !tg.Exclude[0].checked() {
		t.Fatal("not checked")
	}
}
