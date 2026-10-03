// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func releaseSummary(r Release) string {
	return fmt.Sprintf("%s %s@%s %s ns=%s rel=%s", r.Kind, r.Chart, r.ChartVersion, r.RepoURL, r.Namespace, r.ReleaseName)
}

func TestFluxEnvironments(t *testing.T) {
	ws, root := openFixture(t, "flux")
	repo := Analyze(ws, Options{Root: root})
	if got := envNames(repo); len(got) != 2 || got[0] != "clusters/production" || got[1] != "clusters/staging" {
		t.Fatalf("environments = %v", got)
	}
	want := map[string]string{
		"clusters/production": "HelmRelease podinfo@6.5.4 https://charts.example.test/podinfo ns=podinfo rel=podinfo",
		"clusters/staging":    "HelmRelease podinfo@6.6.0 https://charts.example.test/podinfo ns=podinfo rel=podinfo",
	}
	for _, e := range repo.Environments {
		if len(e.Releases) != 1 || releaseSummary(e.Releases[0]) != want[e.Name] {
			t.Fatalf("%s releases = %+v", e.Name, e.Releases)
		}
		r := e.Releases[0]
		if r.SourceRef != "HelmRepository/podinfo/podinfo" || r.Values["replicaCount"] == nil {
			t.Fatalf("%s release = %+v", e.Name, r)
		}
		if ui, _ := r.Values["ui"].(map[string]any); ui["message"] != "hello" {
			t.Fatalf("inline values are not kept: %+v", r.Values)
		}
		if len(e.Gaps) != 1 || e.Gaps[0].Reason != ValuesFromNotResolved || !strings.Contains(e.Gaps[0].Detail, "ConfigMap/podinfo-values") {
			t.Fatalf("%s gaps = %+v", e.Name, e.Gaps)
		}
		if e.Root.Display != filepath.Join(root, "clusters", strings.TrimPrefix(e.Name, "clusters/"), "sync.yaml") {
			t.Fatalf("root = %+v", e.Root)
		}
	}
	staging := repo.Environments[1]
	if len(staging.Images) != 2 || staging.Images[0].Image != "registry.example.test/team/proxy" || staging.Images[0].Digest == "" ||
		staging.Images[1].Image != "registry.example.test/team/web" || staging.Images[1].Tag != "1.2.3" {
		t.Fatalf("staging images = %+v", staging.Images)
	}
	production := repo.Environments[0]
	if len(production.Images) != 1 || production.Images[0].Tag != "1.2.0" {
		t.Fatalf("production images = %+v", production.Images)
	}
	if len(repo.Gaps) != 0 {
		t.Fatalf("repo gaps = %+v", repo.Gaps)
	}
}

func TestArgoEnvironments(t *testing.T) {
	ws, root := openFixture(t, "argo")
	repo := Analyze(ws, Options{Root: root, SelfRepoURLs: []string{"https://github.com/example/fleet"}})
	if got := envNames(repo); len(got) != 1 || got[0] != "argocd/root" {
		t.Fatalf("environments = %v", got)
	}
	e := repo.Environments[0]
	var summaries []string
	for _, r := range e.Releases {
		summaries = append(summaries, releaseSummary(r))
	}
	want := []string{
		"Application web@1.4.0 https://charts.example.test ns=web rel=web-prod",
		"ChartDependency redis@18.1.0 https://charts.example.test ns= rel=redis",
	}
	if strings.Join(summaries, "|") != strings.Join(want, "|") {
		t.Fatalf("releases = %q", summaries)
	}
	if e.Releases[0].Values["replicas"] == nil {
		t.Fatalf("helm.values were not parsed: %+v", e.Releases[0].Values)
	}
	for _, g := range [][2]string{
		{ValueFilesNotResolved, ""},
		{RemoteReferenceNotResolved, "https://github.com/example/other"},
		{GeneratedApplicationsNotEvaluated, ""},
	} {
		if !hasGap(e.Gaps, g[0], g[1]) {
			t.Fatalf("missing gap %v in %+v", g, e.Gaps)
		}
	}
	if len(e.Gaps) != 3 {
		t.Fatalf("gaps = %+v", e.Gaps)
	}

	// Without SelfRepoURLs no path source is followed: every Application is
	// its own environment and every path source is a gap.
	bare := Analyze(ws, Options{Root: root})
	if len(bare.Environments) != 4 {
		t.Fatalf("environments without SelfRepoURLs = %v", envNames(bare))
	}
	for _, env := range bare.Environments {
		for _, r := range env.Releases {
			if r.Kind == KindChartDependency {
				t.Fatalf("a path source was followed: %+v", r)
			}
		}
		switch env.Name {
		case "argocd/root", "argocd/local", "argocd/remote":
			if !hasGap(env.Gaps, RemoteReferenceNotResolved, "is not this repository") {
				t.Fatalf("%s gaps = %+v", env.Name, env.Gaps)
			}
		}
	}
	if !hasGap(bare.Gaps, GeneratedApplicationsNotEvaluated, "") {
		t.Fatalf("ApplicationSet gap missing from %+v", bare.Gaps)
	}
}

func TestChartAndKustomization(t *testing.T) {
	ws, root := openFixture(t, "aux")
	repo := Analyze(ws, Options{Root: root})
	if len(repo.Environments) != 1 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	e := repo.Environments[0]
	var rel []string
	for _, r := range e.Releases {
		rel = append(rel, releaseSummary(r))
	}
	want := []string{
		"ChartDependency common@~1.0.0 https://charts.example.test ns= rel=base",
		"ChartDependency redis@18.1.0 https://charts.example.test ns= rel=redis",
	}
	if strings.Join(rel, "|") != strings.Join(want, "|") {
		t.Fatalf("releases = %q", rel)
	}
	if !hasGap(e.Gaps, ChartVersionNotPinned, "~1.0.0") || len(e.Gaps) != 1 {
		t.Fatalf("gaps = %+v", e.Gaps)
	}
	var images []string
	for _, p := range e.Images {
		images = append(images, p.Image+":"+p.Tag+"@"+p.Digest)
	}
	wantImages := []string{
		"mirror.example.test/team/web:1.2.4@",
		"registry.example.test/team/job:@sha256:0000000000000000000000000000000000000000000000000000000000000002",
		"registry.example.test/team/web:1.0.0@",
	}
	if strings.Join(images, "|") != strings.Join(wantImages, "|") {
		t.Fatalf("images = %q", images)
	}
}

func TestClosurePathSafety(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repoDir := filepath.Join(base, "repo")
	outside := filepath.Join(base, "outside")
	writeFile(t, filepath.Join(outside, "release.yaml"), helmRelease("stolen", "1.0.0"))
	writeFile(t, filepath.Join(outside, "repo.yaml"), helmRepo)
	writeFile(t, filepath.Join(repoDir, "git.yaml"), gitRepo)
	writeFile(t, filepath.Join(repoDir, "inside", "release.yaml"), helmRelease("inside", "1.0.0"))
	writeFile(t, filepath.Join(repoDir, "inside", "repo.yaml"), helmRepo)
	if err := os.Symlink(outside, filepath.Join(repoDir, "link")); err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{
		"dotdot":   "../outside",
		"abs":      outside,
		"sneaky":   "./inside/../../outside",
		"symlink":  "./link",
		"url":      "https://example.test/x",
		"backslas": `..\outside`,
	}
	for name, p := range roots {
		writeFile(t, filepath.Join(repoDir, "roots", name+".yaml"), fluxRoot(name, p))
	}
	writeFile(t, filepath.Join(repoDir, "kust", "kustomization.yaml"),
		"resources:\n  - ../../outside\n  - ../../outside/release.yaml\n  - /etc\n  - github.com/org/repo//base?ref=v1\n")
	writeFile(t, filepath.Join(repoDir, "roots", "kust.yaml"), fluxRoot("kust", "./kust"))
	ws, err := intake.Open([]string{repoDir, outside}, intake.Options{Permissions: intake.RefuseWritable})
	if err != nil {
		t.Fatal(err)
	}
	repo := Analyze(ws, Options{Root: repoDir})
	out := marshal(t, repo)
	if strings.Contains(out, "stolen") {
		t.Fatalf("a release outside the root was resolved: %s", out)
	}
	for _, e := range repo.Environments {
		if len(e.Releases) != 0 {
			t.Fatalf("%s resolved %+v", e.Name, e.Releases)
		}
		if len(e.Gaps) == 0 {
			t.Fatalf("%s has no gap", e.Name)
		}
		switch e.Name {
		case "./link", "link":
			if !hasGap(e.Gaps, SourceNotFound, "symlink") {
				t.Fatalf("symlink gaps = %+v", e.Gaps)
			}
		case "kust":
			if len(e.Gaps) != 4 {
				t.Fatalf("kust gaps = %+v", e.Gaps)
			}
			for _, g := range e.Gaps {
				if g.Reason != RemoteReferenceNotResolved {
					t.Fatalf("kust gap = %+v", g)
				}
			}
		default:
			for _, g := range e.Gaps {
				if g.Reason != RemoteReferenceNotResolved && g.Reason != SourceNotFound {
					t.Fatalf("%s gap = %+v", e.Name, g)
				}
			}
		}
	}
	if len(repo.Environments) != len(roots)+1 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	if !hasGap(repo.Gaps, SourceNotFound, "outside the repository root") {
		t.Fatalf("files outside the root are not reported: %+v", repo.Gaps)
	}
}

func TestClosureCyclesAndDepth(t *testing.T) {
	chain := func(n int) map[string]string {
		files := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("k0", "./d1"), "d" + fmt.Sprint(n) + "/leaf.yaml": helmRelease("leaf", "1.0.0"), "d" + fmt.Sprint(n) + "/repo.yaml": helmRepo}
		for i := 1; i < n; i++ {
			files[fmt.Sprintf("d%d/k.yaml", i)] = fluxRoot(fmt.Sprintf("k%d", i), fmt.Sprintf("./d%d", i+1))
		}
		return files
	}
	// 32 nested references are followed, the 33rd is refused.
	ok := analyze(t, chain(32))
	if e := envByName(t, ok, "d1"); len(e.Releases) != 1 || len(e.Gaps) != 0 {
		t.Fatalf("depth 32: %+v", e)
	}
	deep := analyze(t, chain(33))
	e := envByName(t, deep, "d1")
	if len(e.Releases) != 0 || !hasGap(e.Gaps, ClosureLimit, "deeper than 32") {
		t.Fatalf("depth 33: %+v", e)
	}

	cycle := analyze(t, map[string]string{
		"git.yaml":  gitRepo,
		"root.yaml": fluxRoot("root", "./a"),
		"a/k1.yaml": fluxRoot("k1", "./b"),
		"b/k2.yaml": fluxRoot("k2", "./a"),
		"a/r.yaml":  helmRelease("one", "1.0.0"),
		"a/s.yaml":  helmRepo,
	})
	e = envByName(t, cycle, "a")
	if len(e.Releases) != 1 || !hasGap(e.Gaps, ClosureLimit, "reference cycle") {
		t.Fatalf("cycle: %+v", e)
	}

	// Kustomization files that reach each other terminate as well.
	loop := analyze(t, map[string]string{
		"git.yaml":            gitRepo,
		"root.yaml":           fluxRoot("root", "./a"),
		"a/kustomization.yml": "resources:\n  - ../b\n",
		"b/kustomization.yml": "resources:\n  - ../a\n",
	})
	if e := envByName(t, loop, "a"); !hasGap(e.Gaps, ClosureLimit, "reference cycle") {
		t.Fatalf("kustomization loop: %+v", e)
	}

	// Two Kustomizations that only manage each other have no root.
	rootless := analyze(t, map[string]string{
		"git.yaml": gitRepo,
		"a/k.yaml": fluxRoot("ka", "./b"),
		"b/k.yaml": fluxRoot("kb", "./a"),
	})
	if len(rootless.Environments) != 0 || !hasGap(rootless.Gaps, ClosureLimit, "not reachable from any root") {
		t.Fatalf("rootless: %+v", rootless)
	}
}

func TestSOPSNeverDecoded(t *testing.T) {
	ws, root := openFixture(t, "sops")
	repo := Analyze(ws, Options{Root: root})
	out := marshal(t, repo)
	for _, leak := range []string{"ENC[", "AES256", "cGFzc3dvcmQ", "Y2lwaGVydGV4dC1jaGFydA", "age1example", "AGE ENCRYPTED", "private"} {
		if strings.Contains(out, leak) {
			t.Fatalf("encrypted content %q reached the result: %s", leak, out)
		}
	}
	if len(repo.Environments) != 1 || len(repo.Environments[0].Releases) != 0 {
		t.Fatalf("environments = %+v", repo.Environments)
	}
	if !hasGap(repo.Environments[0].Gaps, Encrypted, "") || !hasGap(repo.Gaps, Encrypted, "") {
		t.Fatalf("ENCRYPTED gap missing: %+v", repo)
	}
	// The marker alone is enough, with no sops block at all.
	partial := analyze(t, map[string]string{
		"git.yaml":  gitRepo,
		"root.yaml": fluxRoot("root", "./app"),
		"app/x.yaml": `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: x, namespace: apps}
spec:
  chart:
    spec: {chart: x, version: 1.0.0, sourceRef: {kind: HelmRepository, name: charts}}
  values:
    token: "ENC[AES256_GCM,data:c2VjcmV0,iv:aXY=,tag:dGFn,type:str]"
`,
	})
	if strings.Contains(marshal(t, partial), "c2VjcmV0") || len(partial.Environments[0].Releases) != 0 {
		t.Fatalf("ciphertext marker not honoured: %+v", partial)
	}
}

func TestUnpinnedVersions(t *testing.T) {
	cases := map[string]bool{
		">=1.2.0": false, "1.x": false, "*": false, "1.2": false, "~1.2.0": false, "^1.2.0": false, "1.2.x": false,
		"": false, "latest": false, "1.2.3 - 1.4.0": false,
		"1.2.3": true, "v1.2.3": true, "=1.2.3": true, "1.2.3-rc.1": true, "1.2.3+build.5": true,
		"sha256:0000000000000000000000000000000000000000000000000000000000000001": true,
	}
	for version, pinnedWant := range cases {
		files := map[string]string{
			"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"), "app/repo.yaml": helmRepo,
		}
		quoted := fmt.Sprintf("%q", version)
		files["app/r.yaml"] = strings.Replace(helmRelease("web", "X"), "X", quoted, 1)
		if version == "" {
			files["app/r.yaml"] = helmRelease("web", "")
		}
		repo := analyze(t, files)
		e := envByName(t, repo, "app")
		if len(e.Releases) != 1 {
			t.Fatalf("%q: %+v", version, e)
		}
		got := !hasGap(e.Gaps, ChartVersionNotPinned, "")
		if got != pinnedWant {
			t.Errorf("version %q: pinned = %v, want %v (gaps %+v)", version, got, pinnedWant, e.Gaps)
		}
		if e.Releases[0].ChartVersion != version {
			t.Errorf("version %q was changed to %q", version, e.Releases[0].ChartVersion)
		}
	}
	// A bare number is read as written and is not an exact version.
	num := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"), "app/repo.yaml": helmRepo,
		"app/r.yaml": strings.Replace(helmRelease("web", "X"), "X", "1.2", 1),
	})
	if e := envByName(t, num, "app"); e.Releases[0].ChartVersion != "1.2" || !hasGap(e.Gaps, ChartVersionNotPinned, "1.2") {
		t.Fatalf("number: %+v", e)
	}
	// Argo CD chart revisions and Chart.yaml dependencies are checked too.
	argo := analyze(t, map[string]string{
		"a.yaml": `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: a, namespace: argocd}
spec:
  source: {repoURL: "https://charts.example.test", chart: web, targetRevision: "1.*"}
`,
		"b.yaml": `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: b, namespace: argocd}
spec:
  source: {repoURL: "https://charts.example.test", chart: web, targetRevision: "1.2.3"}
`,
	})
	if !hasGap(envByName(t, argo, "argocd/a").Gaps, ChartVersionNotPinned, "1.*") || hasGap(envByName(t, argo, "argocd/b").Gaps, ChartVersionNotPinned, "") {
		t.Fatalf("argo: %+v", argo)
	}
}

func TestPatches(t *testing.T) {
	base := map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./overlay"),
		"base/r.yaml": helmRelease("web", "1.0.0"), "base/repo.yaml": helmRepo,
		"base/kustomization.yaml": "resources: [r.yaml, repo.yaml]\n",
	}
	run := func(patches string) Environment {
		files := map[string]string{}
		for k, v := range base {
			files[k] = v
		}
		files["overlay/kustomization.yaml"] = "resources: [../base]\npatches:\n" + patches
		return envByName(t, analyze(t, files), "overlay")
	}
	strategic := `  - patch: |-
      apiVersion: helm.toolkit.fluxcd.io/v2
      kind: HelmRelease
      metadata: {name: web, namespace: apps}
      spec: {chart: {spec: {version: 2.0.0}}}
`
	if e := run(strategic); e.Releases[0].ChartVersion != "2.0.0" || len(e.Gaps) != 0 {
		t.Fatalf("strategic merge: %+v", e)
	}
	other := `  - patch: |-
      apiVersion: helm.toolkit.fluxcd.io/v2
      kind: HelmRelease
      metadata: {name: web}
      spec: {interval: 5m, chart: {spec: {version: 2.0.0}}}
`
	if e := run(other); e.Releases[0].ChartVersion != "1.0.0" || !hasGap(e.Gaps, PatchNotEvaluated, "") {
		t.Fatalf("extra field: %+v", e)
	}
	wrongPath := `  - target: {kind: HelmRelease, name: web}
    patch: |-
      - op: replace
        path: /spec/values/x
        value: 1
`
	if e := run(wrongPath); e.Releases[0].ChartVersion != "1.0.0" || !hasGap(e.Gaps, PatchNotEvaluated, "") {
		t.Fatalf("other path: %+v", e)
	}
	missing := `  - target: {kind: HelmRelease, name: nothing}
    patch: |-
      - op: replace
        path: /spec/chart/spec/version
        value: 3.0.0
`
	if e := run(missing); !hasGap(e.Gaps, PatchNotEvaluated, "not found") {
		t.Fatalf("missing target: %+v", e)
	}
	selector := `  - target: {kind: HelmRelease, labelSelector: "a=b"}
    patch: |-
      - op: replace
        path: /spec/chart/spec/version
        value: 3.0.0
`
	if e := run(selector); e.Releases[0].ChartVersion != "1.0.0" || !hasGap(e.Gaps, PatchNotEvaluated, "") {
		t.Fatalf("selector: %+v", e)
	}
	// A patched version is checked for pinning.
	ranged := `  - target: {kind: HelmRelease, name: web}
    patch: |-
      - op: replace
        path: /spec/chart/spec/version
        value: ">=1.0.0"
`
	if e := run(ranged); !hasGap(e.Gaps, ChartVersionNotPinned, ">=1.0.0") {
		t.Fatalf("range: %+v", e)
	}
}

func TestGitopsDeterministic(t *testing.T) {
	ws1, root := openFixture(t, "flux", "clusters", "apps")
	ws2, _ := openFixture(t, "flux", "apps", "clusters")
	ws3, _ := openFixture(t, "flux")
	var first string
	for i, ws := range []intake.Workspace{ws1, ws2, ws3} {
		out := marshal(t, Analyze(ws, Options{Root: root}))
		if i == 0 {
			first = out
		} else if out != first {
			t.Fatalf("argument order %d changed the result:\n%s\n%s", i, first, out)
		}
	}
	a1, aroot := openFixture(t, "argo", "apps", "bootstrap", "charts")
	a2, _ := openFixture(t, "argo", "charts", "bootstrap", "apps")
	o1 := marshal(t, Analyze(a1, Options{Root: aroot, SelfRepoURLs: []string{"https://github.com/example/fleet"}}))
	o2 := marshal(t, Analyze(a2, Options{Root: aroot, SelfRepoURLs: []string{"https://github.com/example/fleet"}}))
	if o1 != o2 {
		t.Fatalf("argo order changed the result")
	}
}
