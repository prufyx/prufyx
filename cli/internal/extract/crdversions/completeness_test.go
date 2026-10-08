// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func runSynthConcurrent(t *testing.T, tg Target, s synthRepo, concurrency int) *extract.Output {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	out, err := extract.Run(context.Background(), NewConcurrent(tg, concurrency), s, s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func outputBytes(t *testing.T, out *extract.Output) map[string][]byte {
	t.Helper()
	files, err := out.Files()
	must(t, err)
	return files
}

// Rook installs from deploy/examples: crds.yaml is the listed path, and
// csi-operator.yaml, applied next to it, holds the csi.ceph.io definitions
// that serve only v1 from v1.18.0. The scan reads the default-excluded
// directory: the file is an extra definition there, the pair is not
// attestable, and the versions it no longer serves are recorded (upstream
// fixture, testdata/oracle/PROVENANCE.txt).
func TestRookExamplesInstall(t *testing.T) {
	out := mustRun(t, "rook", extract.FixtureReader{Root: "testdata/oracle"})
	p, proof := pairOf(t, out, "1.17.0", "1.18.0")
	if p.Status != extract.PairDerived || len(p.Rules) != 0 || len(proof.Removals) != 0 {
		t.Fatalf("pair %+v", p)
	}
	c := proof.Completeness
	if c.Attestable || c.Scan || !c.Declared || !c.LineWide {
		t.Fatalf("completeness %+v", c)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		f := inv.Scan.Findings
		if len(f) != 1 || f[0].Path != "deploy/examples/csi-operator.yaml" || f[0].Class != ClassExtra || f[0].Location != "default: examples" || len(f[0].CRDs) != 5 {
			t.Fatalf("findings at %s: %+v", inv.Tag, f)
		}
		if !slices.Contains(inv.Scan.Exclusions, "default: examples") {
			t.Fatalf("exclusions %v", inv.Scan.Exclusions)
		}
	}
	var members []string
	for _, u := range proof.UnlistedRemovals {
		if u.FromTag != "v1.17.0" || u.Path != "deploy/examples/csi-operator.yaml" || !strings.HasPrefix(u.Member, "csi.ceph.io/v1alpha1/") {
			t.Fatalf("unlisted removal %+v", u)
		}
		members = append(members, u.Member)
	}
	if !slices.Contains(members, "csi.ceph.io/v1alpha1/Driver") || len(members) < 3 {
		t.Fatalf("unlisted removals %v", members)
	}
	if !strings.Contains(strings.Join(c.Reasons, "\n"), "extra (default: examples)") || !strings.Contains(strings.Join(c.Reasons, "\n"), "csi.ceph.io/v1alpha1/Driver is served outside the listed paths") {
		t.Fatalf("reasons %v", c.Reasons)
	}
}

// Kyverno 1.19's chart takes its policies.kyverno.io definitions from the
// kyverno-api chart of another repository, and its report definitions from
// the openreports chart: definitions the scan cannot read. Such a pair is
// not attestable; a local dependency (no repository, or file://) is read
// with the rest of the tree.
func TestExternalChartDependency(t *testing.T) {
	alpha := crd("Alpha", "v1")
	local := "apiVersion: v2\nname: kyverno\nversion: 3.5.0\ndependencies:\n- name: crds\n  version: 3.5.0\n  condition: crds.install\n- name: grafana\n  version: 1.0.0\n  repository: file://../grafana\n"
	external := local + "- name: kyverno-api\n  version: 0.0.1-alpha.4\n  repository: https://kyverno.github.io/api\n- name: openreports\n  version: 0.1.0\n  repository: oci://ghcr.io/openreports/charts\n"
	s := newSynth(
		release{"v1.18.0", map[string]string{"deploy/crds/a.yaml": alpha, "charts/kyverno/Chart.yaml": local}},
		release{"v1.18.1", map[string]string{"deploy/crds/a.yaml": alpha, "charts/kyverno/Chart.yaml": local}},
		release{"v1.19.0", map[string]string{"deploy/crds/a.yaml": alpha, "charts/kyverno/Chart.yaml": external}},
		release{"v1.20.0", map[string]string{"deploy/crds/a.yaml": alpha, "charts/kyverno/Chart.yaml": local}},
	)
	tg := synthTarget()
	tg.MinFrom = [2]int{1, 18}
	out := runSynth(t, tg, s)
	p, proof := pairOf(t, out, "1.18.0", "1.19.0")
	if p.Status != extract.PairDerived || proof.Completeness.Attestable || proof.Completeness.Scan {
		t.Fatalf("pair %+v completeness %+v", p, proof.Completeness)
	}
	f := proof.To.Scan.Findings
	if len(f) != 1 || f[0].Class != ClassExternal || f[0].Path != "charts/kyverno/Chart.yaml" ||
		!strings.Contains(f[0].Detail, "kyverno-api 0.0.1-alpha.4 from https://kyverno.github.io/api") || !strings.Contains(f[0].Detail, "openreports 0.1.0 from oci://ghcr.io/openreports/charts") || strings.Contains(f[0].Detail, "grafana") {
		t.Fatalf("findings %+v", f)
	}
	if len(proof.From.Scan.Findings) != 0 {
		t.Fatalf("local dependencies %+v", proof.From.Scan.Findings)
	}
	// The pair from 1.19 holds the external chart in its earlier line.
	if _, next := pairOf(t, out, "1.19.0", "1.20.0"); next.Completeness.Attestable {
		t.Fatalf("1.19 -> 1.20 %+v", next.Completeness)
	}
}

// A reviewed exclusion that declares copies (Helm chart templates) is
// checked: with its template directives removed it must define the listed
// CRDs with the same versions and served flags. A template that serves
// another version blocks attestation, and at the later anchor withholds
// the rules that would forbid it; one that cannot be read blocks
// attestation.
func TestCheckedTemplateCopies(t *testing.T) {
	template := func(body string) string {
		// Longhorn's form: labels: {{- include ... | nindent 4 }} with a
		// literal label under it.
		return "{{- if .Values.crds.install }}\n" + strings.Replace(body, "metadata:\n", "metadata:\n  labels: {{- include \"chart.labels\" . | nindent 4 }}\n    app: x\n  annotations:\n    {{- include \"chart.annotations\" . | nindent 4 }}\n    helm.sh/resource-policy: {{ .Values.crds.keep | quote }}\n", 1) + "{{- end }}\n"
	}
	copies := Exclusion{Path: "charts/crds/templates/", Reason: "Helm chart templates of the listed definitions", Copies: true}
	run := func(fromTpl, toTpl string) (extract.PairRecord, PairProof) {
		s := newSynth(
			release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), "charts/crds/templates/a.yaml": fromTpl}},
			release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1:off", "v1"), "charts/crds/templates/a.yaml": toTpl}},
		)
		return pairOf(t, runSynth(t, synthTarget(copies), s), "1.0.0", "1.1.0")
	}
	p, proof := run(template(crd("Alpha", "v1beta1", "v1")), template(crd("Alpha", "v1beta1:off", "v1")))
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable || !slices.Equal(proof.To.Scan.Copies, []string{"charts/crds/templates/a.yaml"}) {
		t.Fatalf("matching copies: %+v %+v %+v", p, proof.Completeness, proof.To.Scan)
	}
	// The chart still serves v1beta1 at the later anchor.
	p, _ = run(template(crd("Alpha", "v1beta1", "v1")), template(crd("Alpha", "v1beta1", "v1")))
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "charts/crds/templates/a.yaml is conflict") {
		t.Fatalf("serving copy: %+v", p)
	}
	// A template expression over two lines cannot be read.
	p, proof = run(template(crd("Alpha", "v1beta1", "v1")), template(crd("Alpha", "v1beta1:off", "v1"))+"{{ include\n \"x\" . }}\n")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "is unread") {
		t.Fatalf("unreadable copy: %+v %+v", p, proof.To)
	}
	// The earlier line's chart serves another version: no rule depends on
	// it, but the pair is not attestable.
	p, proof = run(template(crd("Alpha", "v1beta2", "v1beta1", "v1")), template(crd("Alpha", "v1beta1:off", "v1")))
	f := proof.From.Scan.Findings
	if p.Status != extract.PairDerived || proof.Completeness.Attestable || len(f) != 1 || f[0].Class != ClassConflict || f[0].Location != "charts/crds/templates/" {
		t.Fatalf("earlier conflict: %+v %+v", p, f)
	}
	// A declared copy that defines a CRD the listed paths do not hold.
	p, proof = run(template(crd("Alpha", "v1beta1", "v1")), template(crd("Alpha", "v1beta1:off", "v1"))+"---\n"+crd("Beta", "v1"))
	f = proof.To.Scan.Findings
	if p.Status != extract.PairDerived || proof.Completeness.Attestable || len(f) != 1 || f[0].Class != ClassExtra || !strings.Contains(f[0].Detail, "declared copy") {
		t.Fatalf("extra copy: %+v %+v", p, f)
	}
}

// The scan's per-blob summary is a function of the bytes only: the same
// templated blob at many paths, and the same bytes as a kustomization and
// as another file, give the same manifest whatever the read concurrency
// (40 runs with 8 readers against one).
func TestScanDeterministicUnderConcurrency(t *testing.T) {
	templated := "{{- if .Values.crds }}\n" + crd("Beta", "v1")
	remote := "resources:\n- github.com/other/project//config?ref=v1\n"
	files := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
	for i := 0; i < 12; i++ {
		files[fmt.Sprintf("d%02d/chart.yaml", i)] = templated
		files[fmt.Sprintf("k%02d/kustomization.yaml", i)] = remote
		files[fmt.Sprintf("k%02d/other.yaml", i)] = remote
	}
	// The same bytes as a template source and as YAML are read as each.
	files["a/crds.tmpl"] = crd("Beta", "v1")
	files["b/crds.yaml"] = crd("Beta", "v1")
	s := newSynth(release{"v1.0.0", files}, release{"v1.1.0", files})
	want := outputBytes(t, runSynthConcurrent(t, synthTarget(), s, 1))
	_, proof := pairOf(t, runSynthConcurrent(t, synthTarget(), s, 1), "1.0.0", "1.1.0")
	classes := map[string]int{}
	for _, f := range proof.To.Scan.Findings {
		classes[f.Class]++
		if strings.Contains(f.Detail, "/") && f.Class == ClassUnread {
			t.Fatalf("a path in the detail %+v", f)
		}
		if strings.HasSuffix(f.Path, "other.yaml") {
			t.Fatalf("a kustomization's reading at another name: %+v", f)
		}
	}
	if classes[ClassUnread] != 12 || classes[ClassExternal] != 12 || classes[ClassUnsupported] != 1 || classes[ClassExtra] != 1 {
		t.Fatalf("classes %v", classes)
	}
	for run := 0; run < 40; run++ {
		got := outputBytes(t, runSynthConcurrent(t, synthTarget(), s, 8))
		var names []string
		for k := range want {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if !bytes.Equal(want[k], got[k]) {
				t.Fatalf("run %d: %s differs with concurrency 8", run, k)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: %d files, want %d", run, len(got), len(want))
		}
	}
}

// A CRD that a later release of the later line no longer defines (P2: its
// only version is unserved at the anchor, and the definition is gone at
// the next patch) is a removed definition: the pair's rule holds for the
// anchor pair only, and the pair is not attestable.
func TestDefinitionRemovedAtLaterPatch(t *testing.T) {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1beta1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1beta1:off")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	e := ruleOf(t, out, "argo-cd.crd-version-removal.betas-synth-example-io.1-0-0-to-1-1-0")
	if p.Status != extract.PairDerived || e.Rule.Range != nil || proof.Lines.LineWide || proof.Completeness.Attestable {
		t.Fatalf("pair %+v lines %+v", p, proof.Lines)
	}
	want := DefinitionRemoval{CRD: "betas." + synthGroup, FromTag: "v1.1.0", FromPath: "deploy/crds/b.yaml", AbsentAt: []string{"v1.1.1"}}
	if len(proof.DefinitionsRemoved) != 1 {
		t.Fatalf("definitions removed %+v", proof.DefinitionsRemoved)
	}
	if d := proof.DefinitionsRemoved[0]; d.CRD != want.CRD || d.FromTag != want.FromTag || d.FromPath != want.FromPath || !slices.Equal(d.AbsentAt, want.AbsentAt) || len(d.Members) != 0 {
		t.Fatalf("definitions removed %+v", proof.DefinitionsRemoved)
	}
	if !strings.Contains(strings.Join(proof.Lines.NotLineWide, "\n"), "v1.1.1: betas.synth.example.io is no longer defined") {
		t.Fatalf("not line-wide %v", proof.Lines.NotLineWide)
	}
	// A definition that is gone from the later anchor is recorded with
	// the releases that lack it, even when an unrelated extra definition
	// lies in an examples directory.
	s = newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "examples/c.yaml": crd("Gamma", "v1")}},
	)
	_, proof = pairOf(t, runSynth(t, synthTarget(), s), "1.0.0", "1.1.0")
	if len(proof.DefinitionsRemoved) != 1 || !slices.Equal(proof.DefinitionsRemoved[0].AbsentAt, []string{"v1.1.0"}) || proof.Completeness.Attestable {
		t.Fatalf("anchor removal %+v", proof.DefinitionsRemoved)
	}
}

// An unread CRD source at a later-line release keeps the rules to the
// anchor pair; at the later anchor it withholds them. A pair without
// removals is derived and not attestable.
func TestUnreadLaterReleases(t *testing.T) {
	tpl := "{{- if .Values.legacy }}\n" + crd("Alpha", "v1beta1", "v1")
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "chart/crds.yaml": tpl}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Lines.LineWide || out.Entries[0].Rule.Range != nil || !strings.Contains(strings.Join(proof.Lines.NotLineWide, "\n"), "v1.1.1: chart/crds.yaml is unread") {
		t.Fatalf("patch: %+v %+v", p, proof.Lines)
	}
	s = newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "chart/crds.yaml": tpl}},
	)
	p, proof = pairOf(t, runSynth(t, synthTarget(), s), "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || proof.Completeness.Attestable {
		t.Fatalf("quiet: %+v %+v", p, proof.Completeness)
	}
}

// The hop shape is recorded; only the previous minor line is attestable.
func TestHopShape(t *testing.T) {
	s := newSynth(
		release{"v1.8.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.9.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v2.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v2.2.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	for _, tc := range []struct {
		from, to, hop string
		attestable    bool
	}{
		{"1.8.0", "1.9.0", HopPreviousMinor, true},
		{"1.9.0", "2.0.0", HopMajor, false},
		{"2.0.0", "2.2.0", HopSkippedMinor, false},
	} {
		_, proof := pairOf(t, out, tc.from, tc.to)
		c := proof.Completeness
		if c.Hop != tc.hop || c.Attestable != tc.attestable || !c.Declared || !c.Scan || !c.LineWide {
			t.Fatalf("%s -> %s: %+v", tc.from, tc.to, c)
		}
		if !tc.attestable && !strings.Contains(strings.Join(c.Reasons, "\n"), "a "+tc.hop+" hop") {
			t.Fatalf("%s -> %s reasons %v", tc.from, tc.to, c.Reasons)
		}
	}
}

// A removed version that was a storage version at some release read: the
// next action migrates the stored objects first, and the proof keeps the
// storage history.
func TestStoredVersionNextAction(t *testing.T) {
	stored := strings.Replace(strings.Replace(crd("Alpha", "v1beta1", "v1"), "storage: false", "storage: X", 1), "storage: true", "storage: false", 1)
	stored = strings.Replace(stored, "storage: X", "storage: true", 1)
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": stored, "deploy/crds/b.yaml": crd("Beta", "v1beta1", "v1")}},
		release{"v1.0.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	a := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
	if want := "migrate stored Alpha objects to v1 and remove v1beta1 from status.storedVersions, then change apiVersion to synth.example.io/v1 before upgrading to 1.1.0"; a.Rule.NextAction != want {
		t.Fatalf("next action %q", a.Rule.NextAction)
	}
	b := ruleOf(t, out, "argo-cd.crd-version-removal.betas-synth-example-io.1-0-0-to-1-1-0")
	if b.Rule.NextAction != "change apiVersion of Beta to synth.example.io/v1 before upgrading to 1.1.0" {
		t.Fatalf("next action %q", b.Rule.NextAction)
	}
	var hist []string
	for _, h := range proof.StorageHistory {
		hist = append(hist, h.CRD+"="+strings.Join(h.Versions, ","))
	}
	if !slices.Equal(hist, []string{"alphas.synth.example.io=v1,v1beta1", "betas.synth.example.io=v1"}) {
		t.Fatalf("history %v", hist)
	}
	for _, rm := range proof.Removals {
		if rm.WasStorage != (rm.CRD == "alphas."+synthGroup) {
			t.Fatalf("removal %+v", rm)
		}
	}
	if !strings.HasPrefix(nextAction(&CRD{Kind: "Alpha", Group: synthGroup}, "", []string{"v1beta1"}, "1.1.0"), "migrate stored Alpha objects off v1beta1") {
		t.Fatal("no replacement")
	}
	long := nextAction(&CRD{Kind: "Alpha", Group: strings.Repeat("g", 120) + ".io"}, "v1", []string{"v1beta1"}, "1.1.0")
	if len(long) > maxNext || !strings.Contains(long, "prune status.storedVersions") {
		t.Fatalf("long next action %d %q", len(long), long)
	}
}

// Exclusion entries and default segments match whole path segments.
func TestExclusionBoundaries(t *testing.T) {
	tg := synthTarget(Exclusion{Path: "chart/templates/", Reason: "Helm templates of the same definitions"}, Exclusion{Path: "data/kinds.json", Reason: "discovery data listing kinds only"})
	for p, want := range map[string]place{
		"chart/templates/a.yaml":       {kind: locReviewed, entry: "chart/templates/"},
		"chart/templates/sub/a.yaml":   {kind: locReviewed, entry: "chart/templates/"},
		"chart/templates-x/a.yaml":     {kind: locTree},
		"chart/templates-x.yaml":       {kind: locTree},
		"chart/templatesa.yaml":        {kind: locTree},
		"data/kinds.json":              {kind: locReviewed, entry: "data/kinds.json"},
		"data/kinds.json.bak":          {kind: locTree},
		"data/kinds.jsonx":             {kind: locTree},
		"test/a.yaml":                  {kind: locDefault, entry: "default: test"},
		"x/tests/y/a.yaml":             {kind: locDefault, entry: "default: tests"},
		"testing/a.yaml":               {kind: locTree},
		"contest/a.yaml":               {kind: locTree},
		"x/examples-old/a.yaml":        {kind: locTree},
		"test.yaml":                    {kind: locTree},
		"chart/templates/test/a.yaml":  {kind: locReviewed, entry: "chart/templates/"},
		"vendorx/github.com/a/b.yaml":  {kind: locTree},
		"x/vendor/github.com/a/b.yaml": {kind: locDefault, entry: "default: vendor"},
	} {
		if got := tg.placeOf(p); got != want {
			t.Errorf("%s: %+v, want %+v", p, got, want)
		}
	}
	// Through the scan: a conflicting copy in testing/ is in the open tree
	// and withholds the pair; in test/ it only blocks attestation.
	for dir, withheld := range map[string]bool{"testing": true, "test": false} {
		s := newSynth(
			release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), dir + "/bundle.yaml": crd("Alpha", "v1")}},
			release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		)
		p, proof := pairOf(t, runSynth(t, tg, s), "1.0.0", "1.1.0")
		if (p.Status == extract.PairWithheld) != withheld || (!withheld && proof.Completeness.Attestable) {
			t.Fatalf("%s: %+v", dir, p)
		}
	}
}

// A version served by the earlier anchor and a later earlier-line release
// is cited at the anchor.
func TestCitationPrefersTheEarlierAnchor(t *testing.T) {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.0.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.0.2", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if len(proof.Removals) != 1 || proof.Removals[0].FromTag != "v1.0.0" {
		t.Fatalf("removals %+v", proof.Removals)
	}
	e := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
	var cited []string
	for _, src := range e.Rule.Evidence.Sources {
		if strings.HasPrefix(src.ID, "crd-versions-") {
			cited = append(cited, src.ID+"@"+src.Revision)
		}
	}
	if !slices.Equal(cited, []string{"crd-versions-1-0-0@" + commitOf("v1.0.0")}) {
		t.Fatalf("sources %+v", e.Rule.Evidence.Sources)
	}
}
