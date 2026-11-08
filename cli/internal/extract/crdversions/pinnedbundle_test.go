// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	pbDir    = "examples/stack/"
	pbPath   = pbDir + "bundle.yaml"
	pbKust   = pbDir + "kustomization.yaml"
	pbGroupA = "source.vendor.example.net"
	pbGroupB = "notification.vendor.example.net"
)

// pbDigest is the pinned form of some bytes.
func pbDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return sha256Prefix + hex.EncodeToString(sum[:])
}

// pbCRD renders a definition of a foreign group.
func pbCRD(group, kind string) string {
	plural := strings.ToLower(kind) + "s"
	return fmt.Sprintf("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.%s\nspec:\n  group: %s\n  names:\n    kind: %s\n    plural: %s\n  scope: Namespaced\n  versions:\n  - name: v1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        type: object\n", plural, group, group, kind, plural)
}

// pbBundleDeployment is a document of a kind that is no definition.
const pbBundleDeployment = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: controller\nspec:\n  replicas: 1\n"

// pbBundle is a vendored bundle: definitions of two foreign groups and a
// deployment, like a rendered controller install.
func pbBundle() string {
	return pbCRD(pbGroupA, "Source") + "---\n" + pbCRD(pbGroupB, "Alert") + "---\n" + pbBundleDeployment
}

// pbPlainKust lists the bundle and nothing else.
const pbPlainKust = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- bundle.yaml\n"

// pbEntry pins the given contents (the bundle of each tag).
func pbEntry(groups []string, contents ...string) Exclusion {
	var d []string
	for _, c := range contents {
		d = append(d, pbDigest(c))
	}
	sort.Strings(d)
	return Exclusion{Path: pbPath, Repo: "github.com/argoproj/argo-cd", Reason: "a vendored third-party bundle of other groups", Evidence: "an example of the project that vendors the bundle of another project; its definitions are of other API groups and are never the project's own", Foreign: &ForeignBundle{Groups: groups, SHA256: slices.Compact(d)}}
}

// pbRun runs a pair whose listed definition loses a version (one rule) with
// the given extra files at the earlier and the later release.
func pbRun(t *testing.T, from, to map[string]string, links []string, exclude ...Exclusion) (extract.PairRecord, PairProof) {
	t.Helper()
	f := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
	g := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
	for p, c := range from {
		f[p] = c
	}
	for p, c := range to {
		g[p] = c
	}
	s := newSynth(release{"v1.0.0", f}, release{"v1.1.0", g})
	ls := linkRepo{synthRepo: s, links: map[string]bool{}}
	for _, l := range links {
		ls.links[l] = true
	}
	repo, err := extract.ParseRepo("github.com/argoproj/argo-cd")
	must(t, err)
	out, err := extract.Run(context.Background(), New(synthTarget(exclude...)), ls, ls, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	return pairOf(t, out, "1.0.0", "1.1.0")
}

// pbSame is pbRun with the same extra files at both releases.
func pbSame(t *testing.T, extra map[string]string, exclude ...Exclusion) (extract.PairRecord, PairProof) {
	t.Helper()
	return pbRun(t, extra, extra, nil, exclude...)
}

// pbHolds: the entry holds, the pair attests with its one rule.
func pbHolds(t *testing.T, p extract.PairRecord, proof PairProof) {
	t.Helper()
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable || len(voidFindings(proof)) != 0 {
		t.Fatalf("pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
	}
}

// pbVoid: the entry is void at the later release (and so the pair is not
// attestable) and the rule is still derived. detail is a part of the reason.
func pbVoid(t *testing.T, p extract.PairRecord, proof PairProof, detail string) {
	t.Helper()
	v := voidFindings(proof)
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Completeness.Attestable || len(v) == 0 {
		t.Fatalf("not void: pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
	}
	for _, f := range v {
		if f.Location == pbPath && strings.Contains(f.Detail, detail) {
			return
		}
	}
	t.Fatalf("no void finding of %s mentioning %q: %+v", pbPath, detail, v)
}

func pbFiles(bundle, kust string) map[string]string {
	m := map[string]string{pbPath: bundle}
	if kust != "" {
		m[pbKust] = kust
	}
	return m
}

var pbGroups = []string{pbGroupB, pbGroupA}

// P1: the exact pinned bytes under a plain kustomization hold the entry at
// both releases; the pair attests, the file is recorded as excluded with its
// digest, and the entry is not void.
func TestPinnedBundleHolds(t *testing.T) {
	b := pbBundle()
	p, proof := pbSame(t, pbFiles(b, pbPlainKust), pbEntry(pbGroups, b))
	pbHolds(t, p, proof)
	f, ok := findingAt(proof, pbPath)
	if !ok || f.Class != ClassExcluded || f.Location != pbPath || f.SHA256 != pbDigest(b) {
		t.Fatalf("finding %+v", f)
	}
	// Without any referrer it holds too.
	p, proof = pbSame(t, pbFiles(b, ""), pbEntry(pbGroups, b))
	pbHolds(t, p, proof)
	// A plain kustomization above the directory, and one that lists the
	// file from another directory, keep it.
	for name, extra := range map[string]map[string]string{
		"parent":  {pbKust: pbPlainKust, "examples/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- stack\n"},
		"sibling": {"examples/other/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- ../stack/bundle.yaml\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := pbFiles(b, "")
			for k, v := range extra {
				files[k] = v
			}
			p, proof := pbSame(t, files, pbEntry(pbGroups, b))
			pbHolds(t, p, proof)
		})
	}
	// Two accepted digests: each release has its own bytes.
	b2 := strings.Replace(b, "replicas: 1", "replicas: 2", 1)
	p, proof = pbRun(t, pbFiles(b, pbPlainKust), pbFiles(b2, pbPlainKust), nil, pbEntry(pbGroups, b, b2))
	pbHolds(t, p, proof)
}

// N1, N9: a changed byte, or the pin of one release applied to the other
// release's different bytes, voids the entry. The file then blocks.
func TestPinnedBundleDigestMismatch(t *testing.T) {
	b := pbBundle()
	changed := strings.Replace(b, "replicas: 1", "replicas: 2", 1)
	if changed == b || len(changed) != len(b) {
		t.Fatal("the fixture did not change by exactly one byte")
	}
	p, proof := pbSame(t, pbFiles(changed, pbPlainKust), pbEntry(pbGroups, b))
	pbVoid(t, p, proof, "digest")
	// N9: the earlier release matches, the later one does not.
	p, proof = pbRun(t, pbFiles(b, pbPlainKust), pbFiles(changed, pbPlainKust), nil, pbEntry(pbGroups, b))
	pbVoid(t, p, proof, "digest")
	// And the other way round: the earlier release is void.
	_, proof = pbRun(t, pbFiles(changed, pbPlainKust), pbFiles(b, pbPlainKust), nil, pbEntry(pbGroups, b))
	if proof.Completeness.Attestable {
		t.Fatalf("a pair with a void earlier release attests: %+v", proof.Completeness)
	}
	// An unreferenced file with a mismatching digest is void too.
	p, proof = pbSame(t, pbFiles(changed, ""), pbEntry(pbGroups, b))
	pbVoid(t, p, proof, "digest")
}

// Content checks run even on the exact pinned bytes: each of these files is
// pinned by its own digest and still voids the entry.
func TestPinnedBundleContentChecks(t *testing.T) {
	targetCRD := crd("Hidden", "v1")
	bigDoc := func() string {
		var sb strings.Builder
		sb.WriteString(pbBundle())
		sb.WriteString("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: filler\ndata:\n  blob: ")
		sb.WriteString(strings.Repeat("x", maxForeignBytes))
		sb.WriteString("\n")
		return sb.String()
	}
	cm := "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
	for _, tc := range []struct {
		name, content, detail string
		groups                []string
	}{
		{name: "N2 a CRD of the target group appended", content: pbBundle() + "---\n" + targetCRD, detail: synthGroup},
		{name: "a CRD of an undeclared foreign group appended", content: pbBundle() + "---\n" + pbCRD("evil.example.com", "Evil"), detail: "not declared"},
		{name: "N4 the target group only in a description", content: strings.Replace(pbBundle(), "type: object", "type: object\n        description: see "+synthGroup, 1), detail: synthGroup},
		{name: "the target group in another letter case", content: pbBundle() + cm + "  annotations:\n    a: SYNTH.Example.IO\n", detail: synthGroup},
		{name: "N5 the declared set misses one group", content: pbBundle(), groups: []string{pbGroupA}, detail: "not declared"},
		{name: "N6 a duplicate key", content: pbBundle() + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  name: b\n", detail: "strict"},
		{name: "N6 a YAML anchor", content: pbBundle() + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: &n a\ndata:\n  k: *n\n", detail: "strict"},
		{name: "N6 a merge key", content: pbBundle() + cm + "data:\n  <<: {k: v}\n", detail: "strict"},
		{name: "N6 a second kustomization document", content: pbBundle() + "---\napiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- other.yaml\n", detail: "kustomization"},
		{name: "a kustomization without a kind", content: pbBundle() + "---\nresources:\n- other.yaml\n", detail: "no kind"},
		{name: "a Component document", content: pbBundle() + "---\nkind: Component\nresources:\n- x.yaml\n", detail: "kustomization"},
		{name: "N7 over the size bound", content: bigDoc(), detail: "bound"},
		{name: "N10 template syntax", content: pbBundle() + cm + "data:\n  k: \"{{ .Values.k }}\"\n", detail: "template"},
		{name: "a definition that is not v1", content: strings.Replace(pbBundle(), "apiextensions.k8s.io/v1\n", "apiextensions.k8s.io/v1beta1\n", 1), detail: "not apiextensions.k8s.io/v1"},
		{name: "a definition named outside its group", content: strings.Replace(pbBundle(), "name: sources."+pbGroupA, "name: sources.other.example.net", 1), detail: "outside its group"},
		{name: "another apiextensions object", content: pbBundle() + "---\napiVersion: apiextensions.k8s.io/v1\nkind: ConversionReview\n", detail: "not a definition"},
		{name: "a manifest of the kind in a string", content: pbBundle() + cm + "data:\n  m: |\n    kind: CustomResourceDefinition\n", detail: "manifest"},
		{name: "a nested mapping of the kind with a spec", content: pbBundle() + "---\napiVersion: v1\nkind: List\nitems:\n- kind: CustomResourceDefinition\n  spec: {}\n", detail: "has a spec"},
		{name: "not a mapping", content: pbBundle() + "---\n- a\n- b\n", detail: "not a mapping"},
		{name: "no document", content: "# nothing\n", detail: "no document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := pbGroups
			if tc.groups != nil {
				groups = tc.groups
			}
			p, proof := pbSame(t, pbFiles(tc.content, pbPlainKust), pbEntry(groups, tc.content))
			pbVoid(t, p, proof, tc.detail)
		})
	}
	// A declared group that the target itself defines.
	p, proof := pbSame(t, pbFiles(pbBundle(), pbPlainKust), pbEntry([]string{pbGroupA, synthGroup}, pbBundle()))
	pbVoid(t, p, proof, "a group the target defines")
}

// N3: the referring kustomization is not a plain resources list, or a
// kustomization that reaches it is not: void. A reference from anything but
// a kustomization voids it too.
func TestPinnedBundleReferrers(t *testing.T) {
	b := pbBundle()
	head := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	res := "resources:\n- bundle.yaml\n"
	patch := "patches:\n- target:\n    kind: CustomResourceDefinition\n  patch: |-\n    - op: replace\n      path: /spec/group\n      value: x.example.org\n"
	apply := "kube" + "ctl apply -f " + pbPath + "\n"
	for _, tc := range []struct {
		name  string
		extra map[string]string
		by    string
	}{
		{name: "patches", extra: map[string]string{pbKust: head + res + patch}, by: pbKust},
		{name: "patchesJson6902", extra: map[string]string{pbKust: head + res + "patchesJson6902:\n- target: {kind: CustomResourceDefinition, name: x}\n  patch: |-\n    - op: remove\n      path: /spec\n"}, by: pbKust},
		{name: "patchesStrategicMerge", extra: map[string]string{pbKust: head + res + "patchesStrategicMerge:\n- p.yaml\n"}, by: pbKust},
		{name: "replacements", extra: map[string]string{pbKust: head + res + "replacements:\n- source: {kind: ConfigMap, name: x}\n  targets: []\n"}, by: pbKust},
		{name: "a generator", extra: map[string]string{pbKust: head + res + "configMapGenerator:\n- name: x\n  literals: [a=b]\n"}, by: pbKust},
		{name: "a transformer", extra: map[string]string{pbKust: head + res + "transformers:\n- t.yaml\n"}, by: pbKust},
		{name: "components", extra: map[string]string{pbKust: head + res + "components:\n- ../comp\n"}, by: pbKust},
		{name: "a name prefix", extra: map[string]string{pbKust: head + res + "namePrefix: x-\n"}, by: pbKust},
		{name: "a namespace", extra: map[string]string{pbKust: head + res + "namespace: x\n"}, by: pbKust},
		{name: "images", extra: map[string]string{pbKust: head + res + "images:\n- name: a\n  newTag: b\n"}, by: pbKust},
		{name: "a remote resource next to it", extra: map[string]string{pbKust: head + res + "- https://example.com/x.yaml\n"}, by: pbKust},
		{name: "no kind", extra: map[string]string{pbKust: "apiVersion: kustomize.config.k8s.io/v1beta1\n" + res}, by: pbKust},
		{name: "a Component", extra: map[string]string{pbKust: "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\n" + res}, by: pbKust},
		{name: "template syntax", extra: map[string]string{pbKust: head + res + "# {{ x }}\n- '{{ y }}'\n"}, by: pbKust},
		{name: "a plain one and a patched one", extra: map[string]string{pbKust: pbPlainKust, pbDir + "kustomization.yml": head + res + patch}, by: pbDir + "kustomization.yml"},
		{name: "a patched parent of a plain one", extra: map[string]string{pbKust: pbPlainKust, "examples/kustomization.yaml": head + "resources:\n- stack\n" + patch}, by: pbKust},
		{name: "a patched grandparent of a plain one", extra: map[string]string{pbKust: pbPlainKust, "examples/kustomization.yaml": head + "resources:\n- stack\n", "kustomization.yaml": head + "resources:\n- examples\n" + patch}, by: pbKust},
		{name: "a chart lists it", extra: map[string]string{pbDir + "Chart.yaml": "name: stack\nversion: 1.0.0\n# bundle.yaml\n"}, by: pbDir + "Chart.yaml"},
		{name: "a Makefile applies it", extra: map[string]string{"Makefile": "install:\n\t" + apply}, by: "Makefile"},
		{name: "a document applies it", extra: map[string]string{"docs/install.md": apply}, by: "docs/install.md"},
		{name: "a script applies it", extra: map[string]string{"hack/install.sh": apply}, by: "hack/install.sh"},
		{name: "a container build copies it", extra: map[string]string{"Dockerfile": "COPY " + pbPath + " /bundle.yaml\n"}, by: "Dockerfile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := pbFiles(b, "")
			for k, v := range tc.extra {
				files[k] = v
			}
			p, proof := pbSame(t, files, pbEntry(pbGroups, b))
			v := voidFindings(proof)
			if p.Status != extract.PairDerived || proof.Completeness.Attestable || len(v) != 1 || v[0].Location != pbPath {
				t.Fatalf("pair %s completeness %+v voids %+v", p.Status, proof.Completeness, v)
			}
			// The recorded referrer is the file that breaks the rule: a
			// patched ancestor is reported by the file that lists the
			// bundle.
			if v[0].Path != tc.by {
				t.Fatalf("referrer %s, want %s", v[0].Path, tc.by)
			}
		})
	}
}

// A symbolic link in place of the pinned file, a link inside a kustomization
// directory, and the bundle at another path: none is covered by the pin.
func TestPinnedBundleOtherFilesAndLinks(t *testing.T) {
	b := pbBundle()
	// The pinned path is a link: not a regular file, void.
	_, proof := pbRun(t, pbFiles(b, ""), pbFiles(b, ""), []string{pbPath}, pbEntry(pbGroups, b))
	if proof.Completeness.Attestable {
		t.Fatalf("a link attests: %+v", proof.Completeness)
	}
	// A link inside the kustomization directory voids every entry.
	withLink := pbFiles(b, pbPlainKust)
	withLink[pbDir+"other.yaml"] = "x"
	_, proof = pbRun(t, withLink, withLink, []string{pbDir + "other.yaml"}, pbEntry(pbGroups, b))
	if v := voidFindings(proof); proof.Completeness.Attestable || len(v) != 1 || !strings.Contains(v[0].Detail, "symbolic link") {
		t.Fatalf("link in the directory: voids %+v completeness %+v", v, proof.Completeness)
	}
	// The same bytes at another path, listed by a plain kustomization, are
	// not the pinned file: scanned like any file, they block, and the pinned
	// path itself is untouched.
	other := map[string]string{pbPath: b, "examples/copy/bundle.yaml": b, "examples/copy/kustomization.yaml": pbPlainKust}
	p, proof := pbSame(t, other, pbEntry(pbGroups, b))
	if proof.Completeness.Attestable || p.Status != extract.PairDerived {
		t.Fatalf("a copy elsewhere: pair %s completeness %+v", p.Status, proof.Completeness)
	}
	f, ok := findingAt(proof, "examples/copy/bundle.yaml")
	if !ok || f.Class == ClassExcluded || f.Class == ClassExcludedUnread || !f.blocks() {
		t.Fatalf("the copy at another path is classified %+v", f)
	}
	if f, ok := findingAt(proof, pbPath); !ok || f.Class != ClassExcluded || len(voidFindings(proof)) != 0 {
		t.Fatalf("the pinned file: %+v voids %+v", f, voidFindings(proof))
	}
	// Without the entry the bundle blocks too (the exclusion is what lets
	// it through, not the file).
	_, proof = pbSame(t, pbFiles(b, pbPlainKust))
	if proof.Completeness.Attestable {
		t.Fatalf("no entry: %+v", proof.Completeness)
	}
}

// The relaxation is only for a pin: the unpinned form of the same exclusion
// is still void under the same plain kustomization, and so is a directory
// entry over the bundle.
func TestPinnedBundleRelaxationIsOnlyForPins(t *testing.T) {
	b := pbBundle()
	plain := pbEntry(pbGroups, b)
	plain.Foreign = nil
	p, proof := pbSame(t, pbFiles(b, pbPlainKust), plain)
	pbVoid(t, p, proof, "does not hold")
	dir := plain
	dir.Path = pbDir
	files := pbFiles(b, pbPlainKust)
	files["examples/kustomization.yaml"] = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- stack\n"
	_, proof = pbSame(t, files, dir)
	if v := voidFindings(proof); proof.Completeness.Attestable || len(v) == 0 {
		t.Fatalf("directory entry: %+v voids %+v", proof.Completeness, v)
	}
}

func pbLoad(ej string) error {
	_, err := LoadTarget("target-p.json", testTargetsJSON(ej))
	return err
}

// pbEntryJSON is a pinned entry with the named member replaced.
func pbEntryJSON(path, extra, foreign string) string {
	return fmt.Sprintf(`{"path":%q,"repo":"github.com/o/p","reason":"a vendored third-party bundle","evidence":"an example that vendors another project's bundle of other API groups, never the project's own definitions"%s,"foreign":%s}`, path, extra, foreign)
}

const pbForeignOK = `{"groups":["a.example.net","b.example.net"],"sha256":["sha256:0000000000000000000000000000000000000000000000000000000000000001","sha256:0000000000000000000000000000000000000000000000000000000000000002"]}`

func tooMany(n int) string {
	var parts []string
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`"sha256:%064x"`, i+1))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// T2: the loader accepts the exact-file form and refuses every other shape.
func TestPinnedBundleLoader(t *testing.T) {
	if err := pbLoad(pbEntryJSON("examples/stack/bundle.yaml", "", pbForeignOK)); err != nil {
		t.Fatal(err)
	}
	tg, err := LoadTarget("target-p.json", testTargetsJSON(pbEntryJSON("examples/stack/bundle.json", "", pbForeignOK)))
	if err != nil || tg.Exclude[0].Foreign == nil || len(tg.Exclude[0].Foreign.Groups) != 2 || len(tg.Exclude[0].Foreign.SHA256) != 2 || tg.Exclude[0].DefinesNone || tg.Exclude[0].checked() {
		t.Fatalf("loaded %+v: %v", tg.Exclude, err)
	}
	hex64 := strings.Repeat("a", 64)
	one := func(groups, digests string) string {
		return fmt.Sprintf(`{"groups":%s,"sha256":%s}`, groups, digests)
	}
	ok := "examples/stack/bundle.yaml"
	for name, tc := range map[string]struct{ path, extra, foreign string }{
		"a glob in the name":      {path: "examples/stack/*.yaml", foreign: pbForeignOK},
		"a glob in a directory":   {path: "examples/*/bundle.yaml", foreign: pbForeignOK},
		"a bracket":               {path: "examples/stack/b[u]ndle.yaml", foreign: pbForeignOK},
		"a question mark":         {path: "examples/stack/bundle?.yaml", foreign: pbForeignOK},
		"a directory":             {path: "examples/stack/", foreign: pbForeignOK},
		"an upper-case extension": {path: "examples/stack/bundle.YAML", foreign: pbForeignOK},
		"a mixed-case extension":  {path: "examples/stack/bundle.Yml", foreign: pbForeignOK},
		"another extension":       {path: "examples/stack/bundle.txt", foreign: pbForeignOK},
		"no extension":            {path: "examples/stack/bundle", foreign: pbForeignOK},
		"a kustomization":         {path: "examples/stack/kustomization.yaml", foreign: pbForeignOK},
		"a Kustomization file":    {path: "examples/stack/Kustomization", foreign: pbForeignOK},
		"a chart file":            {path: "examples/stack/Chart.yaml", foreign: pbForeignOK},
		"a values file":           {path: "examples/stack/values.yaml", foreign: pbForeignOK},
		"an unclean path":         {path: "examples/stack/../stack/bundle.yaml", foreign: pbForeignOK},
		"an install directory":    {path: "deploy/stack/bundle.yaml", foreign: pbForeignOK},
		"no digest member":        {path: ok, foreign: `{"groups":["a.example.net"]}`},
		"an empty digest list":    {path: ok, foreign: one(`["a.example.net"]`, `[]`)},
		"no group member":         {path: ok, foreign: `{"sha256":["sha256:` + hex64 + `"]}`},
		"an empty group list":     {path: ok, foreign: one(`[]`, `["sha256:`+hex64+`"]`)},
		"a git blob id as digest": {path: ok, foreign: one(`["a.example.net"]`, `["83b02aed5270b150acb3c63fc4d96e2e055e7ac7"]`)},
		"an upper-case digest":    {path: ok, foreign: one(`["a.example.net"]`, `["sha256:`+strings.ToUpper(hex64)+`"]`)},
		"a short digest":          {path: ok, foreign: one(`["a.example.net"]`, `["sha256:abcd"]`)},
		"duplicate digests":       {path: ok, foreign: one(`["a.example.net"]`, `["sha256:`+hex64+`","sha256:`+hex64+`"]`)},
		"unsorted digests":        {path: ok, foreign: one(`["a.example.net"]`, `["sha256:`+strings.Repeat("b", 64)+`","sha256:`+hex64+`"]`)},
		"too many digests":        {path: ok, foreign: one(`["a.example.net"]`, tooMany(17))},
		"duplicate groups":        {path: ok, foreign: one(`["a.example.net","a.example.net"]`, `["sha256:`+hex64+`"]`)},
		"unsorted groups":         {path: ok, foreign: one(`["b.example.net","a.example.net"]`, `["sha256:`+hex64+`"]`)},
		"a group without a dot":   {path: ok, foreign: one(`["apps"]`, `["sha256:`+hex64+`"]`)},
		"a group with a wildcard": {path: ok, foreign: one(`["*.example.net"]`, `["sha256:`+hex64+`"]`)},
		"an upper-case group":     {path: ok, foreign: one(`["A.example.net"]`, `["sha256:`+hex64+`"]`)},
		"an empty group":          {path: ok, foreign: one(`[""]`, `["sha256:`+hex64+`"]`)},
		"an unknown member":       {path: ok, foreign: `{"groups":["a.example.net"],"sha256":["sha256:` + hex64 + `"],"gitBlob":"x"}`},
		"with copies":             {path: ok, extra: `,"copies":true`, foreign: pbForeignOK},
		"with prePatch":           {path: ok, extra: `,"prePatch":"kustomization.yaml"`, foreign: pbForeignOK},
		"with defines none":       {path: ok, extra: `,"defines":"none"`, foreign: pbForeignOK},
		"an empty foreign member": {path: ok, foreign: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := pbLoad(pbEntryJSON(tc.path, tc.extra, tc.foreign)); err == nil {
				t.Fatalf("accepted %s", tc.path)
			}
		})
	}
	// An earlier entry that covers the file would place it first: refused.
	cover := `{"path":"examples/","repo":"github.com/o/p","reason":"everything under the examples","evidence":"only read by the tests of the project; no install path names them at all"}`
	if _, err := LoadTarget("target-p.json", testTargetsJSON(cover+","+pbEntryJSON(ok, "", pbForeignOK))); err == nil {
		t.Fatal("a pinned entry under an earlier directory entry")
	}
	glob := `{"path":"examples/stack/*.yaml","repo":"github.com/o/p","reason":"the yaml files of the stack","evidence":"only read by the tests of the project; no install path names them at all"}`
	if _, err := LoadTarget("target-p.json", testTargetsJSON(glob+","+pbEntryJSON(ok, "", pbForeignOK))); err == nil {
		t.Fatal("a pinned entry after a pattern in its directory")
	}
	// The entry may not cover a listed path.
	if _, err := LoadTarget("target-p.json", testTargetsJSON(pbEntryJSON("crds/a.yaml", "", pbForeignOK))); err == nil {
		t.Fatal("a pinned entry over a listed path")
	}
}

// The pin is part of the reviewed entry: a changed group or digest list is a
// different declaration.
func TestForeignBundleEqual(t *testing.T) {
	a := &ForeignBundle{Groups: []string{"a.x.io"}, SHA256: []string{"sha256:" + strings.Repeat("1", 64)}}
	same := &ForeignBundle{Groups: []string{"a.x.io"}, SHA256: []string{"sha256:" + strings.Repeat("1", 64)}}
	if !a.Equal(same) || !(*ForeignBundle)(nil).Equal(nil) {
		t.Fatal("equal declarations differ")
	}
	for _, o := range []*ForeignBundle{nil, {Groups: []string{"b.x.io"}, SHA256: a.SHA256}, {Groups: a.Groups, SHA256: []string{"sha256:" + strings.Repeat("2", 64)}}, {Groups: a.Groups}} {
		if a.Equal(o) || o.Equal(a) {
			t.Fatalf("%+v equals %+v", a, o)
		}
	}
}

// foreignBundleProblem fails closed without a pin or a known target group.
func TestForeignBundleProblemFailsClosed(t *testing.T) {
	b := pbBundle()
	pin := pbEntry(pbGroups, b).Foreign
	if why := foreignBundleProblem(pin, []byte(b), []string{synthGroup}); why != "" {
		t.Fatalf("exact bytes: %s", why)
	}
	for name, tc := range map[string]struct {
		pin    *ForeignBundle
		groups []string
	}{
		"no pin":            {nil, []string{synthGroup}},
		"no groups pinned":  {&ForeignBundle{SHA256: pin.SHA256}, []string{synthGroup}},
		"no digests pinned": {&ForeignBundle{Groups: pin.Groups}, []string{synthGroup}},
		"no target groups":  {pin, nil},
	} {
		if foreignBundleProblem(tc.pin, []byte(b), tc.groups) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if targetGroups(nil) != nil || targetGroups(&Inventory{CRDs: []CRD{{Group: "g.example"}}}) != nil {
		t.Error("groups of a missing or incomplete inventory are known")
	}
	if g := targetGroups(&Inventory{Complete: true, CRDs: []CRD{{Group: "b.example"}, {Group: "a.example"}, {Group: "b.example"}}, Channels: []ChannelInventory{{CRDs: []CRD{{Group: "c.example"}}}}}); !slices.Equal(g, []string{"a.example", "b.example", "c.example"}) {
		t.Errorf("groups %v", g)
	}
}

// plainKustomization accepts one shape only.
func TestPlainKustomization(t *testing.T) {
	head := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	if !plainKustomization([]byte(head + "resources:\n- a.yaml\n- ../b/c.yaml\n")) {
		t.Fatal("a plain list is refused")
	}
	for name, s := range map[string]string{
		"empty":            "",
		"no resources":     head,
		"an empty list":    head + "resources: []\n",
		"a mapping item":   head + "resources:\n- {a: b}\n",
		"an absolute path": head + "resources:\n- /etc/x.yaml\n",
		"a url":            head + "resources:\n- https://example.com/x.yaml\n",
		"a repository":     head + "resources:\n- github.com/o/p//x?ref=v1\n",
		"an oci source":    head + "resources:\n- oci://example.com/x\n",
		"two documents":    head + "resources:\n- a.yaml\n---\n" + head + "resources:\n- b.yaml\n",
		"another version":  "apiVersion: kustomize.config.k8s.io/v1\nkind: Kustomization\nresources:\n- a.yaml\n",
		"an extra key":     head + "resources:\n- a.yaml\nsortOptions: {order: legacy}\n",
		"labels":           head + "resources:\n- a.yaml\nlabels:\n- pairs: {a: b}\n",
		"metadata":         head + "metadata:\n  name: x\nresources:\n- a.yaml\n",
		"an anchor":        head + "resources:\n- &a a.yaml\n- *a\n",
		"a template":       head + "resources:\n- '{{ x }}'\n",
		"duplicate keys":   head + "resources:\n- a.yaml\nresources:\n- b.yaml\n",
	} {
		if plainKustomization([]byte(s)) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An absent pinned file voids the entry at the release where it is missing,
// and the pair does not attest when the earlier release lacks it.
func TestPinnedBundleMissingFile(t *testing.T) {
	b := pbBundle()
	// Absent at both releases, nothing refers to it.
	p, proof := pbSame(t, nil, pbEntry(pbGroups, b))
	pbVoid(t, p, proof, "not a regular file")
	// Present at the earlier release, absent at the later one.
	p, proof = pbRun(t, pbFiles(b, pbPlainKust), nil, nil, pbEntry(pbGroups, b))
	pbVoid(t, p, proof, "not a regular file")
	// Absent at the earlier release only: the pair does not attest.
	_, proof = pbRun(t, nil, pbFiles(b, pbPlainKust), nil, pbEntry(pbGroups, b))
	if proof.Completeness.Attestable {
		t.Fatalf("a pair with a void earlier release attests: %+v", proof.Completeness)
	}
}
