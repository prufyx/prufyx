// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha1" //nolint:gosec // synthetic commit ids only
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// synthRepo is an in-memory repository: release tag -> path -> content.
type synthRepo struct {
	files memReader
	tags  []extract.Tag
}

func (s synthRepo) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	return s.files.Read(r, c, p)
}

func (s synthRepo) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	return s.files.List(r, c, d)
}

func (s synthRepo) Tags(extract.RepoRef) ([]extract.Tag, error) { return s.tags, nil }

func commitOf(tag string) string {
	sum := sha1.Sum([]byte("commit " + tag)) //nolint:gosec // synthetic commit ids only
	return hex.EncodeToString(sum[:])
}

// release is one tag's tree.
type release struct {
	tag   string
	files map[string]string
}

func newSynth(releases ...release) synthRepo {
	s := synthRepo{files: memReader{}}
	for _, r := range releases {
		c := commitOf(r.tag)
		s.tags = append(s.tags, extract.Tag{Name: r.tag, Commit: c})
		for p, content := range r.files {
			s.files[c+":"+p] = []byte(content)
		}
	}
	return s
}

const synthGroup = "synth.example.io"

// synthTarget reads every YAML file directly in deploy/crds.
func synthTarget(exclude ...Exclusion) Target {
	return Target{
		Project: "argo-cd", Name: "Synth", Repo: "github.com/argoproj/argo-cd", Component: "pkg:github/argoproj/argo-cd",
		FactProject: "argo_cd", TagPrefixes: []string{"v"}, MinFrom: [2]int{1, 0},
		Paths:   []PathSpec{{Path: "deploy/crds", Dir: true, Match: regexp.MustCompile(`^[^.][^/]*\.ya?ml$`), Guard: regexp.MustCompile(`(?i)crd`)}},
		Exclude: exclude,
	}
}

// crd renders one CRD; each version is "name" (served, the last one is
// the storage version) or "name:off" (not served).
func crd(kind string, versions ...string) string {
	plural := strings.ToLower(kind) + "s"
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.%s\nspec:\n  group: %s\n  names:\n    kind: %s\n    plural: %s\n  scope: Namespaced\n  versions:\n", plural, synthGroup, synthGroup, kind, plural)
	for i, v := range versions {
		name, off := strings.CutSuffix(v, ":off")
		fmt.Fprintf(&b, "  - name: %s\n    served: %v\n    storage: %v\n    schema:\n      openAPIV3Schema:\n        type: object\n", name, !off, i == len(versions)-1)
	}
	return b.String()
}

func runSynth(t *testing.T, tg Target, s synthRepo) *extract.Output {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	out, err := extract.Run(context.Background(), New(tg), s, s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func pairOf(t *testing.T, out *extract.Output, from, to string) (extract.PairRecord, PairProof) {
	t.Helper()
	for _, p := range out.Manifest.Pairs {
		if p.From == from && p.To == to {
			return p, pairProof(t, p)
		}
	}
	t.Fatalf("no pair %s -> %s in %+v", from, to, out.Manifest.Pairs)
	return extract.PairRecord{}, PairProof{}
}

func ruleOf(t *testing.T, out *extract.Output, id string) extract.Entry {
	t.Helper()
	for _, e := range out.Entries {
		if e.Rule.ID == id {
			return e
		}
	}
	t.Fatalf("no rule %s", id)
	return extract.Entry{}
}

func bases(r *constraintengine.VersionRange) []string {
	var out []string
	for _, b := range r.Bounds {
		out = append(out, b.Basis)
	}
	return out
}

// Every release of both lines is read; a removal that holds for every
// release of both lines gives a rule over both whole lines, with the
// release-boundary bounds for consecutive minor lines; a quiet pair is
// attestable.
func TestLineWideRules(t *testing.T) {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.0.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1:off", "v1")}},
		release{"v1.2.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || !proof.Lines.LineWide || len(proof.Lines.From.Tags) != 2 || len(proof.Lines.To.Tags) != 2 || !proof.Completeness.Attestable {
		t.Fatalf("pair %+v proof %+v", p, proof.Lines)
	}
	e := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
	r := e.Rule.Range
	if r == nil || r.From != (constraintengine.VersionBound{Gte: "1.0.0", Lt: "1.1.0"}) || r.To != (constraintengine.VersionBound{Gte: "1.1.0", Lt: "1.2.0"}) ||
		!slices.Equal(bases(r), []string{"PREVIOUS_MINOR_LINE", "REMOVED_IN_RELEASE", "REMOVED_IN_RELEASE", "TARGET_SERIES"}) {
		t.Fatalf("range %+v", r)
	}
	if !strings.Contains(e.Description, "every release of 1.0 and 1.1") {
		t.Fatalf("description %q", e.Description)
	}
	_, quiet := pairOf(t, out, "1.1.0", "1.2.0")
	if len(quiet.Removals) != 0 || !quiet.Completeness.Attestable {
		t.Fatalf("quiet pair %+v", quiet)
	}
	// The engine admits the rule and it matches a patch-to-patch upgrade.
	tr := constraintengine.RuleTransition{Component: e.Rule.Subject.Component, From: e.Rule.Subject.From, To: e.Rule.Subject.To, Range: r}
	if tr.Match("1.0.1", "1.1.1") != constraintengine.MatchRange {
		t.Fatal("range does not match 1.0.1 -> 1.1.1")
	}
}

// A new major or a skipped minor number ranges over each whole line
// without a release boundary.
func TestLineRangeShapes(t *testing.T) {
	s := newSynth(
		release{"v1.9.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v2.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta2", "v1")}},
		release{"v2.3.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	for _, tc := range []struct{ id, fromGte, fromLt, toGte, toLt string }{
		{"argo-cd.crd-version-removal.alphas-synth-example-io.1-9-0-to-2-0-0", "1.9.0", "1.10.0", "2.0.0", "2.1.0"},
		{"argo-cd.crd-version-removal.alphas-synth-example-io.2-0-0-to-2-3-0", "2.0.0", "2.1.0", "2.3.0", "2.4.0"},
	} {
		r := ruleOf(t, out, tc.id).Rule.Range
		if r == nil || r.From != (constraintengine.VersionBound{Gte: tc.fromGte, Lt: tc.fromLt}) || r.To != (constraintengine.VersionBound{Gte: tc.toGte, Lt: tc.toLt}) ||
			!slices.Equal(bases(r), []string{"UPGRADE_FROM_SERIES", "UPGRADE_FROM_SERIES", "TARGET_SERIES", "TARGET_SERIES"}) {
			t.Fatalf("%s range %+v", tc.id, r)
		}
	}
}

// A version some later-line releases serve again is not removed for the
// whole line: the rule holds for the anchor pair only and the pair is not
// attestable (Cilium 1.20.2 serves CiliumNodeConfig v2alpha1 again).
func TestFlappingVersionIsAnchorOnly(t *testing.T) {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1alpha1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1alpha1", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	e := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
	if e.Rule.Range != nil || proof.Lines.LineWide || proof.Completeness.Attestable || len(proof.Lines.NotLineWide) != 1 || !strings.Contains(proof.Lines.NotLineWide[0], "served by some releases of the later line and not by others") {
		t.Fatalf("rule %+v lines %+v", e.Rule.Range, proof.Lines)
	}
	if !slices.Equal(proof.Lines.To.Tags[1].Added, []string{synthGroup + "/v1alpha1/Alpha"}) {
		t.Fatalf("added %v", proof.Lines.To.Tags[1].Added)
	}
}

// An incomplete patch release keeps the anchor-pair rule (the anchors are
// complete) but drops the range and attestability; a version served only
// by a later earlier-line release is removed line-wide and cited there.
func TestPatchReleases(t *testing.T) {
	t.Run("incomplete patch", func(t *testing.T) {
		s := newSynth(
			release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
			release{"v1.0.1", map[string]string{"deploy/crds/a.yaml": "{{ template }}\n" + crd("Alpha", "v1beta1", "v1")}},
			release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		)
		out := runSynth(t, synthTarget(), s)
		p, proof := pairOf(t, out, "1.0.0", "1.1.0")
		if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Lines.LineWide || proof.Completeness.Declared || proof.Completeness.Attestable || out.Entries[0].Rule.Range != nil {
			t.Fatalf("pair %+v %+v", p, proof.Completeness)
		}
	})
	t.Run("version added in a patch", func(t *testing.T) {
		s := newSynth(
			release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
			release{"v1.0.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
			release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		)
		out := runSynth(t, synthTarget(), s)
		_, proof := pairOf(t, out, "1.0.0", "1.1.0")
		e := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
		if len(proof.Removals) != 1 || proof.Removals[0].FromTag != "v1.0.1" || e.Rule.Range == nil {
			t.Fatalf("removals %+v", proof.Removals)
		}
		if src := e.Rule.Evidence.Sources[1]; src.ID != "crd-versions-1-0-1" || src.Revision != commitOf("v1.0.1") {
			t.Fatalf("sources %+v", e.Rule.Evidence.Sources)
		}
	})
}

// The full-tree scan classifies every file outside the listed paths that
// holds CustomResourceDefinition content, wherever it lies: a file under a
// default-excluded directory blocks attestation (never silently skipped),
// a reviewed exclusion is recorded without blocking, and a templated source
// in the open tree withholds the pair's rules.
func TestScanClasses(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	alphaLater := crd("Alpha", "v1")
	cases := []struct {
		name       string
		extra      map[string]string // files at both tags
		exclude    []Exclusion
		status     string
		attestable bool
		class      string
		location   string
		reason     string
	}{
		{name: "nothing else", status: extract.PairDerived, attestable: true},
		{name: "default excluded directory", extra: map[string]string{"docs/examples/crd.yaml": crd("Gamma", "v1")}, status: extract.PairDerived, class: ClassExtra, location: "default: examples"},
		{name: "default excluded test data", extra: map[string]string{"vendor/x/crd.json": `{"kind": "CustomResourceDefinition"}`}, status: extract.PairDerived, class: ClassUnread, location: "default: vendor"},
		{name: "default excluded copy", extra: map[string]string{"test/crd.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"}, status: extract.PairDerived, attestable: true},
		{name: "reviewed exclusion", extra: map[string]string{"charts/templates/crds.yaml": "{{- if .Values.crds }}\n" + crd("Beta", "v1")}, exclude: []Exclusion{{Path: "charts/templates/", Reason: "Helm templates of the same definitions"}}, status: extract.PairDerived, attestable: true, class: ClassExcludedUnread, location: "charts/templates/", reason: "template syntax"},
		{name: "extra definition", extra: map[string]string{"deploy/other.yaml": crd("Beta", "v1")}, status: extract.PairDerived, class: ClassExtra},
		{name: "templated file", extra: map[string]string{"chart/crds.yaml": "{{- if .Values.crds }}\n" + crd("Beta", "v1")}, status: extract.PairWithheld, reason: "chart/crds.yaml is unread"},
		{name: "json mention", extra: map[string]string{"data/kinds.json": `{"items": [{"kind": "CustomResourceDefinition"}]}`}, status: extract.PairDerived, class: ClassReference},
		{name: "word in a comment of a templated file", extra: map[string]string{"docs/cm.yaml": "# 'crd' - CustomResourceDefinitions\ndata:\n  x: {{ .y }}\n"}, status: extract.PairDerived, attestable: true},
		{name: "kind on the next line of a templated file", extra: map[string]string{"chart/x.yaml": "{{ if .x }}\nkind:\n  CustomResourceDefinition\n"}, status: extract.PairWithheld, reason: "chart/x.yaml is unread"},
		{name: "word in a comment only", extra: map[string]string{"deploy/rbac.yaml": "# grants access to every CustomResourceDefinition\nkind: ClusterRole\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: x\n"}, status: extract.PairDerived, attestable: true},
		{name: "flow mapping", extra: map[string]string{"deploy/flow.yaml": "{apiVersion: apiextensions.k8s.io/v1, kind: CustomResourceDefinition, metadata: {name: betas.synth.example.io}, spec: {group: synth.example.io, names: {kind: Beta, plural: betas}, scope: Namespaced, versions: [{name: v1, served: true, storage: true}]}}\n"}, status: extract.PairDerived, class: ClassExtra},
		{name: "kind on the next line", extra: map[string]string{"deploy/next.yaml": strings.Replace(crd("Beta", "v1"), "kind: CustomResourceDefinition", "kind:\n  CustomResourceDefinition", 1)}, status: extract.PairDerived, class: ClassExtra},
		{name: "embedded manifest", extra: map[string]string{"deploy/values.yaml": "manifests: |\n  apiVersion: apiextensions.k8s.io/v1\n  kind: CustomResourceDefinition\n"}, status: extract.PairDerived, class: ClassReference},
		{name: "template source", extra: map[string]string{"deploy/crds.yaml.tmpl": crd("Beta", "v1")}, status: extract.PairWithheld, reason: "deploy/crds.yaml.tmpl is unsupported"},
		{name: "jsonnet source", extra: map[string]string{"jsonnet/crds.libsonnet": "{ kind: 'CustomResourceDefinition' }\n"}, status: extract.PairWithheld, reason: "jsonnet/crds.libsonnet is unsupported"},
		{name: "go construction", extra: map[string]string{"pkg/crds/build.go": "package crds\n\nvar x = &apiextv1.CustomResourceDefinition{\n\tObjectMeta: metav1.ObjectMeta{},\n}\n"}, status: extract.PairWithheld, reason: "pkg/crds/build.go is unsupported"},
		{name: "go use only", extra: map[string]string{"pkg/crds/use.go": "package crds\n\nvar x apiextv1.CustomResourceDefinition\nvar y = apiextv1.CustomResourceDefinition{}\n"}, status: extract.PairDerived, attestable: true},
		{name: "go outside a crd path", extra: map[string]string{"pkg/other/build.go": "package other\n\nvar x = &apiextv1.CustomResourceDefinition{\n\tObjectMeta: metav1.ObjectMeta{},\n}\n"}, status: extract.PairDerived, attestable: true},
		{name: "go test file", extra: map[string]string{"pkg/crds/build_test.go": "package crds\n\nvar x = &apiextv1.CustomResourceDefinition{\n\tObjectMeta: metav1.ObjectMeta{},\n}\n"}, status: extract.PairDerived, attestable: true},
		{name: "packaged chart", extra: map[string]string{"deploy/charts/charts/sub-1.0.0.tgz": "binary"}, status: extract.PairWithheld, reason: "sub-1.0.0.tgz is unsupported"},
		{name: "schema-only kustomization", extra: map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/a.yaml\n  target:\n    kind: CustomResourceDefinition\n    name: alphas.synth.example.io\n",
			"deploy/patches/a.yaml":     "- op: add\n  path: /spec/versions/0/schema/openAPIV3Schema/x-kubernetes-preserve-unknown-fields\n  value: true\n",
		}, status: extract.PairDerived, attestable: true},
		{name: "kustomization patching served", extra: map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/a.yaml\n  target:\n    kind: CustomResourceDefinition\n    name: alphas.synth.example.io\n",
			"deploy/patches/a.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}, status: extract.PairDerived, class: ClassReference, reason: "outside version schemas"},
		{name: "kustomization with a strategic merge patch", extra: map[string]string{
			"deploy/kustomization.yaml": "patchesStrategicMerge:\n- p.yaml\npatches:\n- path: p.yaml\n  target:\n    kind: CustomResourceDefinition\n",
		}, status: extract.PairDerived, class: ClassReference, reason: "strategic merge"},
		{name: "kustomization naming the kind elsewhere", extra: map[string]string{
			"deploy/kustomization.yaml": "patches:\n- path: patches/a.yaml\n  target:\n    kind: CustomResourceDefinition\nreplacements:\n- source:\n    kind: CustomResourceDefinition\n",
			"deploy/patches/a.yaml":     "- op: add\n  path: /metadata/labels/x\n  value: y\n",
		}, status: extract.PairDerived, class: ClassReference, reason: "replacements entry"},
		{name: "remote kustomize resource", extra: map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\n- github.com/other/project//config/crd?ref=v1.2.3\n",
		}, status: extract.PairDerived, class: ClassExternal, reason: "github.com/other/project//config/crd?ref=v1.2.3"},
		{name: "local kustomize resource", extra: map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\n- ../other\n",
		}, status: extract.PairDerived, attestable: true},
		{name: "reviewed file pattern", extra: map[string]string{"data/kinds.json": `{"kind": "CustomResourceDefinition"}`}, exclude: []Exclusion{{Path: "data/*.json", Reason: "discovery data listing kinds only"}}, status: extract.PairDerived, attestable: true, class: ClassExcludedUnread, location: "data/*.json"},
		{name: "consistent copy", extra: map[string]string{"install.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n---\n"}, status: extract.PairDerived, attestable: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := map[string]string{"deploy/crds/a.yaml": alpha}
			to := map[string]string{"deploy/crds/a.yaml": alphaLater}
			for p, c := range tc.extra {
				from[p], to[p] = c, c
			}
			if tc.name == "consistent copy" || tc.name == "default excluded copy" {
				for p := range tc.extra {
					from[p] += "---\n" + alpha
					to[p] += "---\n" + alphaLater
				}
			}
			s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
			out := runSynth(t, synthTarget(tc.exclude...), s)
			p, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if p.Status == extract.PairWithheld && tc.status == extract.PairWithheld {
				if !strings.Contains(p.Reason, tc.reason) {
					t.Fatalf("withheld %q, want %q", p.Reason, tc.reason)
				}
				return
			}
			if p.Status != tc.status || proof.Completeness.Attestable != tc.attestable || len(p.Rules) != 1 {
				t.Fatalf("pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
			}
			findings := proof.To.Scan.Findings
			if tc.class == "" {
				for _, f := range findings {
					if f.blocks() {
						t.Fatalf("finding %+v", f)
					}
				}
				if (tc.name == "consistent copy" || tc.name == "default excluded copy") && len(proof.To.Scan.Copies) != 1 {
					t.Fatalf("copies %v", proof.To.Scan.Copies)
				}
				return
			}
			if len(findings) != 1 || findings[0].Class != tc.class || findings[0].Location != tc.location || !strings.Contains(findings[0].Detail, tc.reason) {
				t.Fatalf("findings %+v", findings)
			}
			if tc.location != "" && !slices.Contains(proof.To.Scan.Exclusions, tc.location) {
				t.Fatalf("exclusions %v", proof.To.Scan.Exclusions)
			}
			if findings[0].blocks() && (proof.Completeness.Scan || !strings.Contains(strings.Join(proof.Completeness.Reasons, "\n"), "found "+tc.class)) {
				t.Fatalf("completeness %+v", proof.Completeness)
			}
		})
	}
}

// A copy outside the listed paths that serves other versions withholds a
// pair whose anchor holds it, and keeps a pair whose patch release holds
// it from ranging over the line.
func TestScanConflict(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "bundle.yaml": alpha}},
		release{"v1.2.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "bundle.yaml": alpha}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || proof.Lines.LineWide || out.Entries[0].Rule.Range != nil {
		t.Fatalf("first pair %+v %+v", p, proof.Lines)
	}
	if p, _ := pairOf(t, out, "1.1.0", "1.2.0"); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "bundle.yaml defines alphas.synth.example.io differently from the listed paths") {
		t.Fatalf("second pair %+v", p)
	}
}

// A definition the later release holds nowhere (a clean scan) is recorded,
// never a rule: an upgraded cluster keeps the old definition. The pair is
// derived and not attestable. With a dirty scan it is withheld.
func TestDefinitionRemoved(t *testing.T) {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1alpha1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	want := []DefinitionRemoval{{CRD: "betas." + synthGroup, Members: []string{synthGroup + "/v1/Beta", synthGroup + "/v1alpha1/Beta"}, FromTag: "v1.0.0", FromPath: "deploy/crds/b.yaml"}}
	if p.Status != extract.PairDerived || len(p.Rules) != 0 || len(proof.Removals) != 0 || !slices.EqualFunc(proof.DefinitionsRemoved, want, func(a, b DefinitionRemoval) bool {
		return a.CRD == b.CRD && slices.Equal(a.Members, b.Members) && a.FromTag == b.FromTag && a.FromPath == b.FromPath
	}) || proof.Completeness.Attestable || !proof.Lines.LineWide {
		t.Fatalf("pair %+v proof %+v", p, proof)
	}
	// The same, with a templated file anywhere at the later release.
	s = newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "chart/crds.yaml": "{{ if x }}\n" + crd("Gamma", "v1")}},
	)
	out = runSynth(t, synthTarget(), s)
	if p, _ := pairOf(t, out, "1.0.0", "1.1.0"); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "a removed definition cannot be told from a moved one") {
		t.Fatalf("dirty scan %+v", p)
	}
}

// An optional listed path may be missing; a recursive one reads its
// subdirectories; a listed path inside a default-excluded directory is
// still read.
func TestPathOptions(t *testing.T) {
	tg := synthTarget()
	tg.Paths = []PathSpec{
		{Path: "deploy/examples/crds.yaml"},
		{Path: "extra/crds", Dir: true, Recursive: true, Optional: true, Match: regexp.MustCompile(`\.yaml$`), Guard: regexp.MustCompile(`(?i)crd`)},
	}
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/examples/crds.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/examples/crds.yaml": crd("Alpha", "v1"), "extra/crds/sub/b.yaml": crd("Beta", "v1")}},
	)
	out := runSynth(t, tg, s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable {
		t.Fatalf("pair %+v %+v", p, proof.Completeness)
	}
	if proof.From.Paths[1].Kind != "missing" || proof.To.Paths[1].Files != 1 || len(proof.To.CRDs) != 2 {
		t.Fatalf("paths %+v %+v", proof.From.Paths, proof.To.Paths)
	}
}

// A release tagged twice at different commits withholds the pairs of its
// line.
func TestTagConflictWithholds(t *testing.T) {
	tg := synthTarget()
	tg.TagPrefixes = []string{"v", ""}
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, tg, s)
	if p, _ := pairOf(t, out, "1.0.0", "1.1.0"); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "tagged twice") {
		t.Fatalf("%+v", p)
	}
}

// The decoder reads definitions nested deeper than the configuration
// decoder's 32 levels (Argo CD's ApplicationSet) and keeps every other
// refusal.
func TestDecoderBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString("a:\n")
	for i := 1; i < 60; i++ {
		b.WriteString(strings.Repeat("  ", i) + "b:\n")
	}
	b.WriteString(strings.Repeat("  ", 60) + "c: 1\n")
	if _, _, err := decodeStrict([]byte(b.String())); err != nil {
		t.Fatalf("60 levels: %v", err)
	}
	if _, _, err := decodeStrict([]byte(strings.Repeat("[", maxDecodeDepth+2) + strings.Repeat("]", maxDecodeDepth+2))); err == nil {
		t.Fatal("over the depth bound")
	}
	for _, bad := range []string{"a: &x 1\nb: *x\n", "a: !custom 1\n", "a: 1\na: 2\n", "? [1]\n: 2\n", "<<: {a: 1}\n", "a: yes\n"} {
		_, values, err := decodeStrict([]byte(bad))
		if bad == "a: yes\n" {
			// YAML 1.2: a string, never a boolean (served: yes is refused
			// by the CRD reader as not a boolean).
			if err != nil || values[0].(map[string]any)["a"] != "yes" {
				t.Fatalf("%q: %v %v", bad, values, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%q decoded", bad)
		}
	}
}

// The reviewed target table: every entry valid, sorted and unique; each
// refusal of the loader.
// exclusionOf is a valid exclusion entry of a target but for the given path
// and reason.
func exclusionOf(tg map[string]any, p, reason string) map[string]any {
	return map[string]any{"path": p, "repo": tg["repo"], "reason": reason, "evidence": "read only by the tests of the project; nothing installs from it"}
}

func TestLoadTargets(t *testing.T) {
	if len(Targets) < 12 || !sort.SliceIsSorted(Targets, func(i, j int) bool { return Targets[i].Project < Targets[j].Project }) {
		t.Fatalf("targets %d", len(Targets))
	}
	var doc map[string]any
	must(t, json.Unmarshal(targetsJSON, &doc))
	mutate := func(f func(target map[string]any, doc map[string]any)) []byte {
		var d map[string]any
		must(t, json.Unmarshal(targetsJSON, &d))
		f(d["targets"].([]any)[0].(map[string]any), d)
		raw, err := json.Marshal(d)
		must(t, err)
		return raw
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"unknown field", mutate(func(tg, _ map[string]any) { tg["extra"] = true }), "unknown field"},
		{"schema", mutate(func(_, d map[string]any) { d["schema"] = "x" }), "schema"},
		{"unsorted", mutate(func(_, d map[string]any) {
			ts := d["targets"].([]any)
			ts[0], ts[1] = ts[1], ts[0]
		}), "not sorted"},
		{"component", mutate(func(tg, _ map[string]any) { tg["component"] = "pkg:github/x/y" }), "does not name repository"},
		{"min from", mutate(func(tg, _ map[string]any) { tg["minFrom"] = "3" }), "minFrom"},
		{"bad regex", mutate(func(tg, _ map[string]any) { tg["paths"].([]any)[0].(map[string]any)["match"] = "(" }), "match"},
		{"unclean path", mutate(func(tg, _ map[string]any) { tg["paths"].([]any)[0].(map[string]any)["path"] = "a/../b" }), "clean repository path"},
		{"exclusion without reason", mutate(func(tg, _ map[string]any) { tg["exclude"] = []any{exclusionOf(tg, "x/", "")} }), "reason"},
		{"exclusion over a listed path", mutate(func(tg, _ map[string]any) {
			tg["paths"].([]any)[0].(map[string]any)["path"] = "data/crds"
			tg["exclude"] = []any{exclusionOf(tg, "data/", "a reason that is long enough")}
		}), "covers the listed path"},
		{"every path optional", mutate(func(tg, _ map[string]any) { tg["paths"].([]any)[0].(map[string]any)["optional"] = true }), "every path is optional"},
		{"tag prefix", mutate(func(tg, _ map[string]any) { tg["tagPrefixes"] = []any{"release-"} }), "tagPrefixes"},
		{"duplicate fact project", mutate(func(tg, d map[string]any) {
			tg["factProject"] = d["targets"].([]any)[1].(map[string]any)["factProject"]
		}), "fact " + Targets[1].FactProject + " is used by"},
	} {
		if _, err := LoadTargets(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// The reviewed target table is part of the code digest.
func TestCodeDigestCoversTargets(t *testing.T) {
	dir, files := New(Targets[0]).SourceFiles()
	cf, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: files})
	must(t, err)
	found := false
	for _, f := range cf {
		found = found || f.Path == "extract/crdversions/targets.json"
		if strings.HasSuffix(f.Path, "_test.go") {
			t.Fatalf("test file %s in the digest", f.Path)
		}
	}
	if !found {
		t.Fatalf("targets.json is not in the code files %+v", cf)
	}
}

// The upstream oracles: the removals measured on the published manifests of
// Cilium 1.19 -> 1.20, Kyverno 1.15 -> 1.16 and Longhorn 1.8 -> 1.9, read
// at every release of both lines (testdata/oracle, see PROVENANCE.txt).
// Cilium 1.20.2 serves CiliumNodeConfig v2alpha1 again, so its rule holds
// for the anchor pair only. Rook 1.17 -> 1.18 has no removal under its
// listed path and is not attestable (deploy/examples/csi-operator.yaml).
func TestUpstreamOracles(t *testing.T) {
	for _, project := range []string{"cilium", "kyverno", "longhorn", "rook"} {
		t.Run(project, func(t *testing.T) {
			out := mustRun(t, project, extract.FixtureReader{Root: "testdata/oracle"})
			dir := t.TempDir()
			must(t, out.Write(dir))
			expected, err := os.ReadFile("testdata/oracle-" + project + ".json")
			must(t, err)
			diffs, err := Oracle(dir, expected)
			must(t, err)
			if len(diffs) != 0 {
				t.Fatalf("oracle: %v", diffs)
			}
			// The oracle notices a wrong expectation.
			var exp Expected
			must(t, json.Unmarshal(expected, &exp))
			exp.Removals = append(exp.Removals, ExpectedRemoval{From: exp.Pairs[0].From, To: exp.Pairs[0].To, Member: "x.example.io/v1/X", Reason: "absent"})
			flipped := !*exp.Pairs[0].Attestable
			exp.Pairs[0].Attestable = &flipped
			raw, err := json.Marshal(exp)
			must(t, err)
			diffs, err = Oracle(dir, raw)
			must(t, err)
			if len(diffs) != 2 || !strings.HasPrefix(diffs[0], "ATTESTABLE") || !strings.HasPrefix(diffs[1], "MISSING") {
				t.Fatalf("mutated oracle: %v", diffs)
			}
		})
	}
}
