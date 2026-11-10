// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The generation declaration (Target.Generation): the real kubevela files
// (testdata/kubevela, byte for byte from the public tags v1.8.0 and v1.9.0,
// where they are identical) under a tree whose listed definition is
// synthetic.

func kvFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kubevela/" + rel)
	must(t, err)
	return string(b)
}

func TestKubevelaFilesAreTheRealBytes(t *testing.T) {
	for rel, want := range map[string]string{
		"config/crd/kustomization.yaml":                       "0bfb0de4814b7d8077f3c813b553166057f2acbc3ac02542c7f1fe3f6943a8f1",
		"config/crd/patches/cainjection_in_applications.yaml": "59ad96c87fc71e776796c0d4e25d6b94e4af41fb063b6d1054606fffaf865925",
		"config/crd/patches/webhook_in_applications.yaml":     "33c7bf7b6b176ddafe41b97e3ebd8d7ec988d0a8ab5e08e3f6a97460ff260cdf",
	} {
		sum := sha256.Sum256([]byte(kvFile(t, rel)))
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s is not the upstream file", rel)
		}
	}
}

// kvCRD renders a core.oam.dev definition (versions as in crd()).
func kvCRD(kind string, versions ...string) string {
	plural := strings.ToLower(kind) + "s"
	var b strings.Builder
	b.WriteString("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + plural + ".core.oam.dev\nspec:\n  group: core.oam.dev\n  names:\n    kind: " + kind + "\n    plural: " + plural + "\n  scope: Namespaced\n  versions:\n")
	for i, v := range versions {
		b.WriteString("  - name: " + v + "\n    served: true\n    storage: " + map[bool]string{true: "true", false: "false"}[i == len(versions)-1] + "\n    schema:\n      openAPIV3Schema:\n        type: object\n")
	}
	return b.String()
}

// kvTree is the tree of one release: the listed definition, the real
// kustomization and the two real fragments; edit changes it.
func kvTree(versions []string, edit func(map[string]string)) map[string]string {
	m := map[string]string{
		"charts/vela-core/crds/core.oam.dev_applications.yaml": kvCRD("Application", versions...),
	}
	for _, rel := range []string{"config/crd/kustomization.yaml", "config/crd/patches/cainjection_in_applications.yaml", "config/crd/patches/webhook_in_applications.yaml"} {
		b, err := os.ReadFile("testdata/kubevela/" + rel)
		if err != nil {
			panic(err)
		}
		m[rel] = string(b)
	}
	if edit != nil {
		edit(m)
	}
	return m
}

// kvTargetFile is the target data these tests exercise: the reviewed
// kubevela target with its generation declaration and pinned template. It
// is not in the package's own target table yet: the knowledge gate loads the
// target files of a change with the code of the base, which does not know the
// new members.
const kvTargetFile = "testdata/kubevela/target-kubevela.json"

func kvReviewedTarget(t *testing.T) Target {
	t.Helper()
	raw, err := os.ReadFile(kvTargetFile)
	must(t, err)
	tg, err := LoadTarget(TargetFileName("kubevela"), raw)
	must(t, err)
	return tg
}

func kvTarget(t *testing.T, edit func(*Target)) Target {
	t.Helper()
	tg := kvReviewedTarget(t)
	if edit != nil {
		edit(&tg)
	}
	return tg
}

// kvRun derives 1.8.0 -> 1.9.0 where 1.9.0 drops v1alpha2 of Application.
func kvRun(t *testing.T, tg Target, from, to func(map[string]string)) (extract.PairRecord, PairProof) {
	t.Helper()
	s := newSynth(
		release{"v1.8.0", kvTree([]string{"v1alpha2", "v1beta1"}, from)},
		release{"v1.9.0", kvTree([]string{"v1beta1"}, to)},
	)
	out := runSynth(t, tg, s)
	return pairOf(t, out, "1.8.0", "1.9.0")
}

func kvFinding(inv *Inventory, p string) *Finding {
	for i, f := range inv.Scan.Findings {
		if f.Path == p {
			return &inv.Scan.Findings[i]
		}
	}
	return nil
}

const (
	kvCain    = "config/crd/patches/cainjection_in_applications.yaml"
	kvWebhook = "config/crd/patches/webhook_in_applications.yaml"
	kvKust    = "config/crd/kustomization.yaml"
)

// With the declaration the two real fragments are crd-patch findings
// (Reason patch-fragment) at both tags and the pair is derived: one
// removal rule, the version-level one.
func TestGenerationDeclaresTheRealKustomization(t *testing.T) {
	p, proof := kvRun(t, kvTarget(t, nil), nil, nil)
	if p.Status != extract.PairDerived || len(p.Rules) != 1 {
		t.Fatalf("pair %s %q rules %v", p.Status, p.Reason, p.Rules)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		for _, f := range []string{kvCain, kvWebhook} {
			got := kvFinding(inv, f)
			if got == nil || got.Class != ClassCRDPatch || got.Reason != ReasonFragment || got.blocks() {
				t.Errorf("%s %s: %+v", inv.Tag, f, got)
			}
		}
		for _, f := range inv.Scan.Findings {
			// The tree has no adopt template: the pinned entry of the
			// target is void there (see pinnedsource_test.go).
			if f.Path != kvKust && f.Class != ClassVoided && f.blocks() {
				t.Errorf("%s: unexpected blocking finding %+v", inv.Tag, f)
			}
		}
	}
}

// The same tree without the declaration (nothing else changed): both
// fragments are unread outside a declared directory and the pair is
// withheld, as before. This is what every other target keeps.
func TestWithoutGenerationTheFragmentsStayUnread(t *testing.T) {
	tg := kvTarget(t, func(tg *Target) { tg.Generation = nil })
	p, _ := kvRun(t, tg, nil, nil)
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "is unread") {
		t.Fatalf("pair %s %q", p.Status, p.Reason)
	}
}

// Each of these keeps a file unread (or the kustomization undeclared) and
// withholds the pair; the Reason code of the finding names why.
func TestGenerationNegatives(t *testing.T) {
	webhook := kvFile(t, "config/crd/patches/webhook_in_applications.yaml")
	cases := []struct {
		name   string
		edit   func(m map[string]string)
		target func(*Target)
		path   string
		reason string
	}{
		{name: "fragment with spec.versions", path: kvCain, reason: ReasonPatchNotStrict, edit: func(m map[string]string) {
			m[kvCain] += "\nspec:\n  versions:\n  - name: v1alpha2\n    served: false\n"
		}},
		{name: "conversion with spec.names", path: kvWebhook, reason: ReasonPatchNotStrict, edit: func(m map[string]string) {
			m[kvWebhook] = webhook + "\n  names:\n    kind: Other\n"
		}},
		{name: "JSON6902 list replacing /spec", path: kvCain, reason: ReasonPatchNotStrict, edit: func(m map[string]string) {
			m[kvCain] = "- op: replace\n  path: /spec\n  value:\n    kind: CustomResourceDefinition\n"
		}},
		{name: "fragment of an unlisted definition", path: kvCain, reason: ReasonPatchNameNotListed, edit: func(m map[string]string) {
			m[kvCain] = strings.Replace(m[kvCain], "applications.core.oam.dev", "gammas.core.oam.dev", 1)
		}},
		{name: "tab-indented non-YAML", path: kvCain, reason: ReasonUndecodable, edit: func(m map[string]string) {
			m[kvCain] = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n\tname: applications.core.oam.dev\n"
		}},
		{name: "binary file", path: kvCain, reason: ReasonUndecodable, edit: func(m map[string]string) {
			m[kvCain] = "kind: CustomResourceDefinition\n\x00\x01\xff"
		}},
		{name: "kustomization with a remote resource", path: kvCain, reason: ReasonPatchNotUnderDir, edit: func(m map[string]string) {
			m[kvKust] = strings.Replace(m[kvKust], "  - base/core.oam.dev_applications.yaml\n", "  - base/core.oam.dev_applications.yaml\n  - https://example.invalid/base?ref=v1\n", 1)
		}},
		{name: "kustomization with an unfollowable configurations list", path: kvCain, reason: ReasonPatchNotUnderDir, edit: func(m map[string]string) {
			m[kvKust] = strings.Replace(m[kvKust], "#configurations:\n#  - kustomizeconfig.yaml", "configurations: nope", 1)
		}},
		{name: "kustomization that is not strict YAML", path: kvCain, reason: ReasonPatchNotUnderDir, edit: func(m map[string]string) {
			m[kvKust] += "resources: []\n"
		}},
		{name: "patch file in another directory", path: "deploy/patches/cainjection_in_applications.yaml", reason: ReasonPatchNotUnderDir, edit: func(m map[string]string) {
			m["deploy/patches/cainjection_in_applications.yaml"] = m[kvCain]
		}},
		{name: "declaration for another kustomization", path: kvCain, reason: ReasonPatchNotUnderDir, target: func(tg *Target) {
			tg.Generation[0].Kustomization = "config/other/kustomization.yaml"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tg := kvTarget(t, func(tg *Target) {
				tg.Generation = append([]Generation(nil), tg.Generation...)
				if tc.target != nil {
					tc.target(tg)
				}
			})
			p, proof := kvRun(t, tg, tc.edit, tc.edit)
			if p.Status != extract.PairWithheld {
				t.Fatalf("pair %s %q, want withheld", p.Status, p.Reason)
			}
			if proof.To == nil {
				return
			}
			if f := kvFinding(proof.To, tc.path); f == nil || f.Class != ClassUnread || !strings.Contains(f.Reason, tc.reason) {
				t.Fatalf("finding %+v, want unread %s (pair %s %q)", f, tc.reason, p.Status, p.Reason)
			}
		})
	}
}

// The declared kustomization missing at one tag: its fragments are unread
// there and the pair is withheld.
func TestGenerationKustomizationAbsentAtOneTag(t *testing.T) {
	for _, side := range []string{"from", "to"} {
		drop := func(m map[string]string) { delete(m, kvKust) }
		var from, to func(map[string]string)
		if side == "from" {
			from = drop
		} else {
			to = drop
		}
		p, proof := kvRun(t, kvTarget(t, nil), from, to)
		// Only the later tag withholds; an earlier tag's unread file
		// leaves the pair derived and not attestable.
		if side == "to" && p.Status != extract.PairWithheld {
			t.Fatalf("%s: pair %s %q, want withheld", side, p.Status, p.Reason)
		}
		if side == "from" && (p.Status != extract.PairDerived || proof.Completeness.Attestable) {
			t.Fatalf("%s: pair %s %q attestable %v", side, p.Status, p.Reason, proof.Completeness.Attestable)
		}
	}
}

// A patch of the kind in the declared directory's kustomization (a
// JSON6902 on /spec/versions/0/served) makes the kustomization a reference:
// it blocks attestation and is recorded; the fragments are untouched and the
// pair is derived. This is intended: the listed paths are the committed
// output, and patches upstream of them cannot serve a version.
func TestGenerationJSON6902InTheKustomizationBlocksAttestation(t *testing.T) {
	edit := func(m map[string]string) {
		m[kvKust] += "\npatchesJson6902:\n- target:\n    group: apiextensions.k8s.io\n    version: v1\n    kind: CustomResourceDefinition\n    name: applications.core.oam.dev\n  patch: |-\n    - op: replace\n      path: /spec/versions/0/served\n      value: true\n"
	}
	p, proof := kvRun(t, kvTarget(t, nil), edit, edit)
	if p.Status != extract.PairDerived || proof.Completeness.Attestable {
		t.Fatalf("pair %s %q attestable %v", p.Status, p.Reason, proof.Completeness.Attestable)
	}
	k := kvFinding(proof.To, kvKust)
	if k == nil || k.Class != ClassReference || !k.blocks() {
		t.Fatalf("kustomization finding %+v", k)
	}
	for _, f := range []string{kvCain, kvWebhook} {
		if g := kvFinding(proof.To, f); g == nil || g.Class != ClassCRDPatch || g.Reason != ReasonFragment {
			t.Fatalf("%s: %+v", f, g)
		}
	}
}

// The loader refuses every malformed declaration.
func TestGenerationLoader(t *testing.T) {
	raw, err := os.ReadFile(kvTargetFile)
	must(t, err)
	good := func() map[string]any {
		var doc map[string]any
		must(t, json.Unmarshal(raw, &doc))
		return doc
	}
	gen := func(doc map[string]any) map[string]any {
		return doc["target"].(map[string]any)["generation"].([]any)[0].(map[string]any)
	}
	load := func(doc map[string]any) error {
		b, err := json.Marshal(doc)
		must(t, err)
		_, err = LoadTarget(TargetFileName("kubevela"), b)
		return err
	}
	if err := load(good()); err != nil {
		t.Fatalf("the reviewed file is refused: %v", err)
	}
	long := strings.Repeat("x", 801)
	for name, edit := range map[string]func(map[string]any){
		"at the repository root":      func(d map[string]any) { gen(d)["kustomization"] = "kustomization.yaml" },
		"not a kustomization name":    func(d map[string]any) { gen(d)["kustomization"] = "config/crd/other.yaml" },
		"unclean path":                func(d map[string]any) { gen(d)["kustomization"] = "config/../config/crd/kustomization.yaml" },
		"absolute path":               func(d map[string]any) { gen(d)["kustomization"] = "/config/crd/kustomization.yaml" },
		"under a default segment":     func(d map[string]any) { gen(d)["kustomization"] = "config/test/kustomization.yaml" },
		"output outside listed paths": func(d map[string]any) { gen(d)["output"] = "config/crd/base" },
		"output at the root":          func(d map[string]any) { gen(d)["output"] = "." },
		"output a sibling of a path":  func(d map[string]any) { gen(d)["output"] = "charts/vela-core/crdsx" },
		"unclean output":              func(d map[string]any) { gen(d)["output"] = "charts/vela-core/crds/../x" },
		"other repository":            func(d map[string]any) { gen(d)["repo"] = "github.com/other/repo" },
		"short reason":                func(d map[string]any) { gen(d)["reason"] = "short" },
		"padded reason":               func(d map[string]any) { gen(d)["reason"] = " a reason that is long enough " },
		"short evidence":              func(d map[string]any) { gen(d)["evidence"] = "config/crd charts/vela-core/crds" },
		"long evidence":               func(d map[string]any) { gen(d)["evidence"] = "config/crd charts/vela-core/crds " + long },
		"evidence without the dir": func(d map[string]any) {
			gen(d)["evidence"] = strings.Replace(gen(d)["evidence"].(string), "config/crd", "the build", -1)
		},
		"evidence without output": func(d map[string]any) {
			gen(d)["evidence"] = strings.Replace(gen(d)["evidence"].(string), "charts/vela-core/crds", "the output", -1)
		},
		"unknown member": func(d map[string]any) { gen(d)["extra"] = true },
		"duplicate": func(d map[string]any) {
			tg := d["target"].(map[string]any)
			tg["generation"] = []any{gen(d), gen(d)}
		},
		"too many": func(d map[string]any) {
			tg := d["target"].(map[string]any)
			var l []any
			for i := 0; i < 5; i++ {
				c := map[string]any{}
				for k, v := range gen(d) {
					c[k] = v
				}
				c["kustomization"] = "config/c" + string(rune('a'+i)) + "/kustomization.yaml"
				c["evidence"] = strings.Replace(c["evidence"].(string), "config/crd", "config/c"+string(rune('a'+i)), -1) + " config/c" + string(rune('a'+i))
				l = append(l, c)
			}
			tg["generation"] = l
		},
		"under an exclusion": func(d map[string]any) {
			d["target"].(map[string]any)["exclude"] = []any{map[string]any{"path": "config/crd/", "repo": "github.com/kubevela/kubevela", "reason": "a reviewed reason", "evidence": strings.Repeat("e", 50)}}
		},
	} {
		doc := good()
		edit(doc)
		if err := load(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
