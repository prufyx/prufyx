// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"fmt"
	"strings"
	"testing"
)

// The tests in this file check that a construct that is not evaluated, or a
// field of the wrong shape, is reported instead of being dropped.

const selfURL = "ssh://git@git.example.test/team/fleet"

func TestRootSourceIsCheckedForEveryDefinition(t *testing.T) {
	foreign := strings.Replace(gitRepo, selfURL, "https://evil.example.test/other", 1)
	base := map[string]string{"root.yaml": fluxRoot("root", "./app"), "app/r.yaml": helmRelease("x", "1.0.0"), "app/repo.yaml": helmRepo}
	cases := map[string]struct {
		defs   []string
		follow bool
	}{
		"two foreign":      {[]string{foreign, foreign}, false},
		"self and foreign": {[]string{gitRepo, foreign}, false},
		"none":             {nil, false},
		"one self":         {[]string{gitRepo}, true},
		"two self":         {[]string{gitRepo, gitRepo}, true},
	}
	for name, c := range cases {
		files := with(base, nil)
		for i, d := range c.defs {
			files[fmt.Sprintf("git%d.yaml", i)] = d
		}
		e := envByName(t, analyze(t, files, selfURL), "app")
		if followed := len(e.Releases) == 1; followed != c.follow || (!c.follow && !hasGap(e.Gaps, RemoteReferenceNotResolved, "GitRepository")) {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

func TestUnreadKustomizationFileIsNotAPlainDirectory(t *testing.T) {
	base := map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./apps"),
		"apps/r.yaml": helmRelease("web", "1.0.0"), "apps/repo.yaml": helmRepo,
		"apps/unused/x.yaml": helmRelease("notdeployed", "1.0.0"),
	}
	for name, kust := range map[string]string{
		"templated": "resources: [r.yaml, repo.yaml]\nnamePrefix: '{{ .prefix }}'\n",
		"encrypted": "resources: [r.yaml, repo.yaml]\nsops: {mac: x, version: 3.8.1}\n",
		"a list":    "- r.yaml\n",
	} {
		e := envByName(t, analyze(t, with(base, map[string]string{"apps/kustomization.yaml": kust})), "apps")
		if len(e.Releases) != 0 || !hasGap(e.Gaps, SourceNotFound, "kustomization file in apps was not read") {
			t.Errorf("%s: %+v", name, e)
		}
		if name == "encrypted" && !hasGap(e.Gaps, Encrypted, "") {
			t.Errorf("encrypted kustomization not reported: %+v", e.Gaps)
		}
	}
	// Two kustomization files in one directory are reported.
	two := envByName(t, analyze(t, with(base, map[string]string{
		"apps/kustomization.yaml": "resources: [r.yaml, repo.yaml]\n", "apps/kustomization.yml": "resources: [r.yaml]\n",
	})), "apps")
	if !hasGap(two.Gaps, SourceNotFound, "more than one kustomization file") {
		t.Fatalf("two kustomization files: %+v", two.Gaps)
	}
}

func TestChartDependencies(t *testing.T) {
	base := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./charts/app")}
	chart := func(repo string) string {
		return "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n  - {name: pg, version: 1.0.0, repository: '" + repo + "'}\n"
	}
	// A sibling chart is read through its own Chart.yaml.
	sibling := envByName(t, analyze(t, with(base, map[string]string{
		"charts/app/Chart.yaml": chart("file://../pg"),
		"charts/pg/Chart.yaml":  "apiVersion: v2\nname: pg\nversion: 1.0.0\ndependencies:\n  - {name: lib, version: '*', repository: 'https://charts.example.test'}\n",
	})), "charts/app")
	if len(sibling.Releases) != 1 || sibling.Releases[0].Chart != "lib" || !hasGap(sibling.Gaps, ChartVersionNotPinned, "*") {
		t.Fatalf("sibling chart: %+v", sibling)
	}
	// A file:// dependency outside the repository is a gap.
	out := envByName(t, analyze(t, with(base, map[string]string{"charts/app/Chart.yaml": chart("file://../../../outside")})), "charts/app")
	if !hasGap(out.Gaps, RemoteReferenceNotResolved, "leaves the repository") {
		t.Fatalf("outside chart: %+v", out)
	}
	// A Chart.yaml that carries a kind is still a chart.
	kinded := envByName(t, analyze(t, with(base, map[string]string{
		"charts/app/Chart.yaml": "apiVersion: v2\nkind: Chart\nname: app\ndependencies:\n  - {name: pg, version: '*', repository: 'https://charts.example.test'}\n",
	})), "charts/app")
	if len(kinded.Releases) != 1 || !hasGap(kinded.Gaps, ChartVersionNotPinned, "*") {
		t.Fatalf("chart with kind: %+v", kinded)
	}
	// A chart with templates is not rendered: one gap says so.
	rendered := envByName(t, analyze(t, with(base, map[string]string{
		"charts/app/Chart.yaml":            "apiVersion: v2\nname: app\nversion: 1.0.0\n",
		"charts/app/templates/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: '{{ .Release.Name }}'}\n",
	})), "charts/app")
	if len(rendered.Gaps) != 1 || !hasGap(rendered.Gaps, ConstructNotEvaluated, "is not rendered") {
		t.Fatalf("chart templates: %+v", rendered.Gaps)
	}
}

func argoApp(name, source string) string {
	return "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: " + name + ", namespace: argocd}\nspec:\n  destination: {namespace: apps}\n  source:\n" + source
}

func TestArgoConstructs(t *testing.T) {
	const repoURL = "https://github.com/example/fleet"
	deploy := func(image string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {containers: [{name: c, image: '" + image + "'}]}}}\n"
	}
	tree := map[string]string{"dir/top.yaml": deploy("registry.example.test/top:1"), "dir/sub/nested.yaml": deploy("registry.example.test/nested:1")}
	run := func(source string, opts Options) Environment {
		opts.Root, opts.SelfRepoURLs = "repo", []string{repoURL}
		repo := Analyze(memory(t, with(tree, map[string]string{"app.yaml": argoApp("a", source)})), opts)
		return envByName(t, repo, "argocd/a")
	}
	images := func(e Environment) string {
		var out []string
		for _, p := range e.Images {
			out = append(out, p.Image)
		}
		return strings.Join(out, ",")
	}
	// A plain directory is not recursed by default.
	if e := run("    {repoURL: '"+repoURL+"', path: dir}\n", Options{}); images(e) != "registry.example.test/top" || len(e.Gaps) != 0 {
		t.Fatalf("default directory: %+v", e)
	}
	if e := run("    {repoURL: '"+repoURL+"', path: dir, directory: {recurse: true}}\n", Options{}); images(e) != "registry.example.test/nested,registry.example.test/top" {
		t.Fatalf("recursive directory: %+v", e)
	}
	// Directory filters and plugins are not evaluated.
	if e := run("    {repoURL: '"+repoURL+"', path: dir, directory: {include: '*.yaml'}}\n", Options{}); !hasGap(e.Gaps, ConstructNotEvaluated, "directory.include") {
		t.Fatalf("include: %+v", e)
	}
	if e := run("    {repoURL: '"+repoURL+"', path: dir, plugin: {name: cmp}}\n", Options{}); len(e.Images) != 0 || !hasGap(e.Gaps, ConstructNotEvaluated, "plugin") {
		t.Fatalf("plugin: %+v", e)
	}
	// The revision of a path source must be the checked-out one.
	if e := run("    {repoURL: '"+repoURL+"', path: dir, targetRevision: some-old-tag}\n", Options{}); len(e.Images) != 0 || !hasGap(e.Gaps, RemoteReferenceNotResolved, "some-old-tag") {
		t.Fatalf("other revision: %+v", e)
	}
	for _, rev := range []string{"HEAD", ""} {
		if e := run("    {repoURL: '"+repoURL+"', path: dir, targetRevision: '"+rev+"'}\n", Options{}); len(e.Images) != 1 {
			t.Fatalf("revision %q: %+v", rev, e)
		}
	}
	if e := run("    {repoURL: '"+repoURL+"', path: dir, targetRevision: v2}\n", Options{SelfRevisions: []string{"v2"}}); len(e.Images) != 1 {
		t.Fatalf("named revision: %+v", e)
	}
	// Helm parameters override values and are reported.
	params := "    repoURL: 'https://charts.example.test'\n    chart: web\n    targetRevision: 1.0.0\n    helm:\n      values: 'image: {tag: good}'\n      parameters: [{name: image.tag, value: evil}]\n"
	if e := run(params, Options{}); !hasGap(e.Gaps, ValuesFromNotResolved, "helm.parameters") {
		t.Fatalf("parameters: %+v", e)
	}
	// Values given for a local chart are not attached to any release.
	local := run("    {repoURL: '"+repoURL+"', path: dir, helm: {values: 'a: 1'}}\n", Options{})
	if !hasGap(local.Gaps, ValuesFromNotResolved, "local chart") {
		t.Fatalf("local chart values: %+v", local)
	}
	// A ref source at another revision is a gap.
	ref := "    {repoURL: '" + repoURL + "', ref: values, targetRevision: release-1}\n"
	if e := run(ref, Options{}); !hasGap(e.Gaps, RemoteReferenceNotResolved, "release-1") {
		t.Fatalf("ref revision: %+v", e)
	}
}

func TestFluxHelmReleaseConstructs(t *testing.T) {
	base := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app")}
	gitChart := func(ref string) map[string]string {
		return with(base, map[string]string{
			"app/r.yaml": "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata: {name: web, namespace: apps}\nspec:\n  chart:\n    spec: {chart: ./charts/web, sourceRef: {kind: GitRepository, name: charts}}\n",
			"app/g.yaml": "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata: {name: charts, namespace: apps}\nspec:\n  url: https://git.example.test/charts\n" + ref,
		})
	}
	for ref, unpinned := range map[string]string{
		"  ref: {branch: main}\n":                   "branch main",
		"":                                          "without a fixed tag or commit",
		"  ref: {semver: '>=1.0.0'}\n":              "version range",
		"  ref: {name: refs/heads/main}\n":          "reference refs/heads/main",
		"  ref: {tag: v1.0.0}\n":                    "",
		"  ref: {commit: 0123456789abcdef}\n":       "",
		"  ref: {name: refs/tags/v1.0.0}\n":         "",
		"  ref: {branch: main, commit: 01234567}\n": "",
	} {
		e := envByName(t, analyze(t, gitChart(ref)), "app")
		got := hasGap(e.Gaps, ChartVersionNotPinned, "")
		if len(e.Releases) != 1 || got != (unpinned != "") || (unpinned != "" && !hasGap(e.Gaps, ChartVersionNotPinned, unpinned)) {
			t.Errorf("git ref %q: %+v", ref, e)
		}
	}
	// A Git source that is not in the input: the revision is unknown.
	missing := gitChart("")
	delete(missing, "app/g.yaml")
	if e := envByName(t, analyze(t, missing), "app"); !hasGap(e.Gaps, SourceNotFound, "was not found") || !hasGap(e.Gaps, ChartVersionNotPinned, "revision is unknown") {
		t.Fatalf("missing Git source: %+v", e.Gaps)
	}
	files := with(base, map[string]string{
		"app/repo.yaml": helmRepo,
		"app/r.yaml": `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: web, namespace: apps}
spec:
  targetNamespace: prod
  chart:
    spec:
      chart: web
      version: 1.0.0
      sourceRef: {kind: HelmRepository, name: charts}
      valuesFiles: [values-prod.yaml]
  postRenderers:
    - kustomize: {patches: [{patch: x}]}
`,
	})
	e := envByName(t, analyze(t, files), "app")
	if !hasGap(e.Gaps, ValueFilesNotResolved, "valuesFiles") || !hasGap(e.Gaps, PatchNotEvaluated, "postRenderers") {
		t.Fatalf("gaps = %+v", e.Gaps)
	}
	if r := e.Releases[0]; r.ReleaseName != "prod-web" || r.Namespace != "prod" {
		t.Fatalf("default release name with targetNamespace: %+v", r)
	}
	long := strings.Replace(files["app/r.yaml"], "targetNamespace: prod", "targetNamespace: "+strings.Repeat("n", 50), 1)
	e = envByName(t, analyze(t, with(files, map[string]string{"app/r.yaml": long})), "app")
	if e.Releases[0].ReleaseName != "" || !hasGap(e.Gaps, ConstructNotEvaluated, "53 characters") {
		t.Fatalf("long release name: %+v", e)
	}
}

func TestPatchesStayInsideTheirObject(t *testing.T) {
	child := `apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: child, namespace: flux-system}
spec:
  path: ./apps
  sourceRef: {kind: GitRepository, name: fleet}
`
	repo := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./clusters/prod"),
		"clusters/prod/kustomization.yaml": "resources: [inner]\n",
		"clusters/prod/inner/kustomization.yaml": "resources: [child.yaml]\npatches:\n" +
			"  - target: {kind: HelmRelease, name: web}\n    patch: '[{op: replace, path: /spec/chart/spec/version, value: 9.9.9}]'\n",
		"clusters/prod/inner/child.yaml": child,
		"apps/r.yaml":                    helmRelease("web", "1.0.0"), "apps/repo.yaml": helmRepo,
	})
	e := envByName(t, repo, "clusters/prod")
	if len(e.Releases) != 1 || e.Releases[0].ChartVersion != "1.0.0" || !hasGap(e.Gaps, PatchNotEvaluated, "not found among the releases of this object") {
		t.Fatalf("patch leaked into a nested Kustomization: %+v", e)
	}
	// The same patch applies to what the kustomization collects itself,
	// through nested kustomization directories.
	direct := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./overlay"),
		"overlay/kustomization.yaml": "resources: [../base]\npatches:\n" +
			"  - target: {kind: HelmRelease, name: web}\n    patch: '[{op: replace, path: /spec/chart/spec/version, value: 9.9.9}]'\n",
		"base/kustomization.yaml": "resources: [r.yaml, repo.yaml]\n",
		"base/r.yaml":             helmRelease("web", "1.0.0"), "base/repo.yaml": helmRepo,
	})
	if e := envByName(t, direct, "overlay"); e.Releases[0].ChartVersion != "9.9.9" {
		t.Fatalf("patch through a base: %+v", e)
	}
}

func TestKustomizeTransformers(t *testing.T) {
	base := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"), "app/r.yaml": helmRelease("web", "1.0.0"),
		"app/repo.yaml": strings.Replace(helmRepo, "namespace: apps", "namespace: other", 1)}
	run := func(kust string) Environment {
		return envByName(t, analyze(t, with(base, map[string]string{"app/kustomization.yaml": kust})), "app")
	}
	// The namespace transformer moves the release and its source together.
	e := run("namespace: prod\nresources: [r.yaml, repo.yaml]\n")
	if r := e.Releases[0]; r.Namespace != "prod" || r.SourceRef != "HelmRepository/prod/charts" || r.RepoURL == "" {
		t.Fatalf("namespace: %+v %+v", r, e.Gaps)
	}
	// An outer namespace wins over an inner one.
	outer := envByName(t, analyze(t, with(base, map[string]string{
		"root.yaml": fluxRoot("root", "./overlay"), "overlay/kustomization.yaml": "namespace: outer\nresources: [../app]\n",
		"app/kustomization.yaml": "namespace: inner\nresources: [r.yaml, repo.yaml]\n",
	})), "overlay")
	if outer.Releases[0].Namespace != "outer" {
		t.Fatalf("outer namespace: %+v", outer.Releases)
	}
	for kust, want := range map[string][2]string{
		"namePrefix: p-\nresources: [r.yaml, repo.yaml]\n":         {ConstructNotEvaluated, "namePrefix"},
		"resources: r.yaml\n":                                      {SourceNotFound, "resources is not a list"},
		"resources: [r.yaml, repo.yaml]\npatches: {a: b}\n":        {PatchNotEvaluated, "patches is not a list"},
		"resources: [r.yaml, repo.yaml]\nimages: {a: b}\n":         {ConstructNotEvaluated, "images is not a list"},
		"resources: [r.yaml, repo.yaml]\ngenerators: [g.yaml]\n":   {ConstructNotEvaluated, "generators"},
		"resources: [r.yaml, repo.yaml]\nreplacements: [{a: b}]\n": {PatchNotEvaluated, "replacements"},
		"resources: [r.yaml, repo.yaml]\nnamespace: [x]\n":         {ConstructNotEvaluated, "namespace is not a string"},
	} {
		if e := run(kust); !hasGap(e.Gaps, want[0], want[1]) {
			t.Errorf("%q: gaps = %+v", kust, e.Gaps)
		}
	}
	// Flux targetNamespace acts as an outer namespace transformer.
	target := strings.Replace(fluxRoot("root", "./app"), "spec:\n", "spec:\n  targetNamespace: tenant\n", 1)
	tn := envByName(t, analyze(t, with(base, map[string]string{"root.yaml": target})), "app")
	if tn.Releases[0].Namespace != "tenant" {
		t.Fatalf("targetNamespace: %+v", tn.Releases)
	}
}

func TestWholeRepositoryKustomization(t *testing.T) {
	files := map[string]string{
		"git.yaml":                   gitRepo,
		"clusters/prod/sync.yaml":    fluxRoot("prod", "./clusters/prod/apps"),
		"clusters/prod/apps/r.yaml":  helmRelease("web", "1.0.0"),
		"clusters/stage/sync.yaml":   fluxRoot("stage", "./clusters/stage/apps"),
		"clusters/stage/apps/r.yaml": helmRelease("web", "2.0.0-rc.1"),
		"legacy/stray.yaml":          fluxRoot("stray", "./"),
	}
	repo := analyze(t, files)
	if got := envNames(repo); len(got) != 2 || got[0] != "clusters/prod/apps" || got[1] != "clusters/stage/apps" {
		t.Fatalf("environments = %v", got)
	}
	if !hasGap(repo.Gaps, ConstructNotEvaluated, "whole repository") {
		t.Fatalf("stray root not reported: %+v", repo.Gaps)
	}
	for _, e := range repo.Environments {
		if hasGap(e.Gaps, ClosureLimit, "") {
			t.Fatalf("%s: %+v", e.Name, e.Gaps)
		}
	}
	// The Flux bootstrap object may apply the whole repository.
	boot := strings.NewReplacer("name: fleet", "name: flux-system").Replace(gitRepo)
	bootRoot := strings.NewReplacer("name: root", "name: flux-system", "name: fleet", "name: flux-system").Replace(fluxRoot("root", "./"))
	whole := analyze(t, map[string]string{"git.yaml": boot, "root.yaml": bootRoot, "apps/r.yaml": helmRelease("web", "1.0.0")})
	if len(whole.Environments) != 1 || len(whole.Environments[0].Releases) != 1 {
		t.Fatalf("bootstrap root: %+v", whole)
	}
	// Reached as a child, a whole-repository Kustomization is not followed.
	child := analyze(t, map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./a"), "a/k.yaml": fluxRoot("k", "./"),
		"b/r.yaml": helmRelease("web", "1.0.0")})
	if e := envByName(t, child, "a"); len(e.Releases) != 0 || !hasGap(e.Gaps, ConstructNotEvaluated, "whole repository") {
		t.Fatalf("child: %+v", e)
	}
	// A reference to a directory already read through its parent is not
	// called a cycle.
	parent := analyze(t, map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./a"), "a/b/k.yaml": fluxRoot("k", "./a/b")})
	if e := envByName(t, parent, "a"); hasGap(e.Gaps, ClosureLimit, "cycle") || !hasGap(e.Gaps, ClosureLimit, "through a parent directory") {
		t.Fatalf("parent: %+v", e.Gaps)
	}
}

func TestSelfURLMatching(t *testing.T) {
	a := &analysis{self: map[string]bool{}}
	for _, u := range []string{"https://GitHub.com/org/repo.git", "git@GitHub.com:org/other", "https://token@github.com/org/third"} {
		n, ok := normalizeURL(u)
		if !ok {
			t.Fatalf("%q refused", u)
		}
		a.self[n] = true
	}
	for url, want := range map[string]bool{
		"https://github.com/org/repo":         true,
		"https://github.com/org/repo/":        true,
		"https://github.com/org/repo.git/":    true,
		"https://GITHUB.COM/org/repo":         true,
		"git@github.com:org/other.git":        true,
		"https://token@github.com/org/third":  true,
		"https://github.com/org/third":        false, // user info is part of the URL
		"https://other@github.com/org/third":  false,
		"https://github.com/Org/repo":         false, // only the host is case-insensitive
		"https://github.com/org/repo?ref=x":   false,
		"https://github.com/org/repo#frag":    false,
		"https://github.com/org/repo/.git/":   false,
		"https://github.com/org/repo/.git":    false,
		" https://github.com/org/repo":        false,
		"https://github.com/org/repo\x1b[0m":  false,
		"https://github.com/org/repo.git.git": false,
		"":                                    false,
	} {
		if got := a.isSelf(url); got != want {
			t.Errorf("isSelf(%q) = %v, want %v", url, got, want)
		}
	}
	// A configured URL with a query, a fragment or white space matches
	// nothing, not even itself.
	for _, u := range []string{"https://github.com/org/q?x=1", "https://github.com/org/f#x", "https://github.com/org/s p"} {
		if _, ok := normalizeURL(u); ok {
			t.Errorf("%q accepted", u)
		}
	}
	for url, want := range map[string]bool{} {
		if got := a.isSelf(url); got != want {
			t.Errorf("isSelf(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestEncryptedFileThatIsNotAManifest(t *testing.T) {
	repo := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"),
		"app/secrets.enc.yaml": "password: ENC[AES256_GCM,data:c2VjcmV0,iv:aXY=,tag:dGFn,type:str]\nsops:\n  mac: ENC[x]\n",
		"app/only-mac.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: m}\ndata: {a: b}\nsops: {mac: x}\n",
	})
	e := envByName(t, repo, "app")
	count := 0
	for _, g := range e.Gaps {
		if g.Reason == Encrypted {
			count++
		}
	}
	if count != 2 || !hasGap(repo.Gaps, Encrypted, "") || strings.Contains(marshal(t, repo), "c2VjcmV0") {
		t.Fatalf("encrypted files: %+v / %+v", e.Gaps, repo.Gaps)
	}
}

func TestPrintableDetails(t *testing.T) {
	evil := "1.0.0\x1b[31m\u202e"
	repo := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"), "app/repo.yaml": helmRepo,
		"app/r.yaml": strings.Replace(helmRelease("web", "X"), "X", fmt.Sprintf("%q", evil), 1),
		"app/k.yaml": strings.Replace(fluxRoot("k", "./app"), "name: fleet", "name: \"x\\e[2J\"", 1),
		"app/d.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {containers: [{name: c, image: \"registry.example.test/i:1\\e[0m\"}]}}}\n",
	})
	e := envByName(t, repo, "app")
	if len(e.Releases) != 0 || !hasGap(e.Gaps, SourceNotFound, "control characters") || len(e.Images) != 0 {
		t.Fatalf("release with control characters: %+v", e)
	}
	for _, g := range e.Gaps {
		if needsEscape(g.Detail) {
			t.Fatalf("detail not escaped: %q", g.Detail)
		}
	}
	if !hasGap(e.Gaps, RemoteReferenceNotResolved, `x\u001b[2J`) {
		t.Fatalf("escape missing: %+v", e.Gaps)
	}
	if got := clip("a\x00b\u2066c\xffd"); got != `a\u0000b\u2066c\ufffdd` {
		t.Fatalf("clip = %q", got)
	}
	for _, r := range []rune{0x2028, 0x2029, 0x061c, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0xe0001, 0xe0041, 0xe007f, 0x00ad} {
		if got := clip("a" + string(r) + "b"); got != fmt.Sprintf(`a\u%04xb`, r) {
			t.Errorf("clip(U+%04X) = %q", r, got)
		}
	}
	if got := clip("plain é ü 日本"); got != "plain é ü 日本" {
		t.Errorf("printable text changed: %q", got)
	}
}

func TestPathRefusals(t *testing.T) {
	repo := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./k"),
		"k/kustomization.yaml": "resources:\n  - 'a\\b'\n  - ''\n  - '" + strings.Repeat("a/", MaxRefBytes/2+1) + "'\n",
		"a/b/x.yaml":           helmRelease("x", "1.0.0"),
	})
	e := envByName(t, repo, "k")
	if !hasGap(e.Gaps, SourceNotFound, `invalid path a\b`) || !hasGap(e.Gaps, SourceNotFound, "longer than 4096") || len(e.Releases) != 0 {
		t.Fatalf("%+v", e)
	}
}

func TestLongImageIsRefused(t *testing.T) {
	long := "registry.example.test/" + strings.Repeat("i", MaxFieldBytes)
	repo := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"),
		"app/d.yaml":             "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {containers: [{name: c, image: '" + long + ":1'}]}}}\n",
		"app/kustomization.yaml": "resources: [d.yaml]\nimages: [{name: '" + long + "', newTag: '1'}]\n",
	})
	e := envByName(t, repo, "app")
	if len(e.Images) != 0 || len(e.Gaps) != 2 || !hasGap(e.Gaps, SourceNotFound, "longer than 256 bytes") {
		t.Fatalf("%+v", e)
	}
}

func TestDigestPins(t *testing.T) {
	for version, want := range map[string]bool{
		"sha256:" + strings.Repeat("0", 64): true,
		"sha256:":                           false,
		"sha256:" + strings.Repeat("0", 63): false,
		"sha256:" + strings.Repeat("g", 64): false,
		"sha512:" + strings.Repeat("0", 64): false,
	} {
		if isPinned(version) != want {
			t.Errorf("isPinned(%q) != %v", version, want)
		}
	}
}

func TestDepthThroughKustomizationDirectories(t *testing.T) {
	chain := func(n int) map[string]string {
		files := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./d0")}
		for i := 0; i < n; i++ {
			files[fmt.Sprintf("d%d/kustomization.yaml", i)] = fmt.Sprintf("resources: [../d%d]\n", i+1)
		}
		files[fmt.Sprintf("d%d/r.yaml", n)] = helmRelease("leaf", "1.0.0")
		files[fmt.Sprintf("d%d/repo.yaml", n)] = helmRepo
		return files
	}
	// The root's path is the first reference, each directory entry one more.
	if e := envByName(t, analyze(t, chain(MaxDepth-1)), "d0"); len(e.Releases) != 1 || len(e.Gaps) != 0 {
		t.Fatalf("depth 32: %+v", e)
	}
	if e := envByName(t, analyze(t, chain(MaxDepth)), "d0"); len(e.Releases) != 0 || !hasGap(e.Gaps, ClosureLimit, "deeper than 32") {
		t.Fatalf("depth 33: %+v", e)
	}
}

func TestSymlinkParents(t *testing.T) {
	links := &linkTrie{}
	links.add("a/link")
	links.add("top")
	for p, want := range map[string]string{
		"a/link": "a/link", "a/link/x/y": "a/link", "a/lin": "", "a/linkx/y": "", "a": "", "top/z": "top", "x/top": "", "": "",
	} {
		if got := links.under(p); got != want {
			t.Errorf("under(%q) = %q, want %q", p, got, want)
		}
	}
}

// TestBaseUnderTwoNamespaces: a base reached under two namespaces is
// deployed twice and is reported twice.
func TestBaseUnderTwoNamespaces(t *testing.T) {
	tenant := func(name string) string {
		return strings.Replace(fluxRoot(name, "./base"), "spec:\n", "spec:\n  targetNamespace: "+name+"\n", 1)
	}
	flux := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./tenants"),
		"tenants/a.yaml": tenant("team-a"), "tenants/b.yaml": tenant("team-b"),
		"base/r.yaml": helmRelease("web", "1.0.0"), "base/repo.yaml": helmRepo,
	})
	e := envByName(t, flux, "tenants")
	if len(e.Releases) != 2 || e.Releases[0].Namespace != "team-a" || e.Releases[1].Namespace != "team-b" || len(e.Gaps) != 0 {
		t.Fatalf("tenants: %+v", e)
	}
	overlay := func(ns, version string) string {
		return "namespace: " + ns + "\nresources: [../../base]\npatches:\n" +
			"  - target: {kind: HelmRelease, name: web}\n    patch: '[{op: replace, path: /spec/chart/spec/version, value: " + version + "}]'\n"
	}
	kust := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./apps"),
		"apps/kustomization.yaml":       "resources: [../overlays/a, ../overlays/b]\n",
		"overlays/a/kustomization.yaml": overlay("team-a", "2.0.0"),
		"overlays/b/kustomization.yaml": overlay("team-b", "3.0.0"),
		"base/kustomization.yaml":       "resources: [r.yaml, repo.yaml]\n",
		"base/r.yaml":                   helmRelease("web", "1.0.0"),
		"base/repo.yaml":                helmRepo,
	})
	e = envByName(t, kust, "apps")
	var got []string
	for _, r := range e.Releases {
		got = append(got, r.Namespace+"@"+r.ChartVersion+"@"+r.SourceRef)
	}
	if strings.Join(got, ",") != "team-a@2.0.0@HelmRepository/team-a/charts,team-b@3.0.0@HelmRepository/team-b/charts" || len(e.Gaps) != 0 {
		t.Fatalf("overlays: %v %+v", got, e.Gaps)
	}
}

func TestFluxRootRevision(t *testing.T) {
	withRef := func(ref string) string { return gitRepo + ref }
	base := map[string]string{"root.yaml": fluxRoot("root", "./app"), "app/r.yaml": helmRelease("x", "1.0.0"), "app/repo.yaml": helmRepo}
	cases := []struct {
		git       []string
		revisions []string
		follow    bool
		detail    string
	}{
		{[]string{withRef("  ref: {tag: v0.0.1-old}\n")}, nil, false, "tracks v0.0.1-old"},
		{[]string{withRef("  ref: {tag: v0.0.1-old}\n")}, []string{"v0.0.1-old"}, true, ""},
		{[]string{gitRepo}, nil, true, ""},
		{[]string{withRef("  ref: {branch: main}\n")}, []string{"main"}, true, ""},
		{[]string{withRef("  ref: {name: refs/heads/main}\n")}, []string{"main"}, true, ""},
		{[]string{withRef("  ref: {branch: main, commit: abc123}\n")}, []string{"main"}, false, "tracks abc123"},
		{[]string{withRef("  ref: [main]\n")}, nil, false, "not understood"},
		{[]string{withRef("  ref: {branch: [main]}\n")}, []string{"main"}, false, "not understood"},
		{[]string{gitRepo, withRef("  ref: {branch: old}\n")}, nil, false, "tracks old"},
		{nil, nil, false, "not in the input"},
	}
	for i, c := range cases {
		files := with(base, nil)
		for j, g := range c.git {
			files[fmt.Sprintf("git%d.yaml", j)] = strings.Replace(g, "spec: {url: \"ssh://git@git.example.test/team/fleet\"}\n", "spec:\n  url: \"ssh://git@git.example.test/team/fleet\"\n", 1)
		}
		repo := Analyze(memory(t, files), Options{Root: "repo", SelfRevisions: c.revisions})
		e := envByName(t, repo, "app")
		if (len(e.Releases) == 1) != c.follow || (!c.follow && !hasGap(e.Gaps, RemoteReferenceNotResolved, c.detail)) {
			t.Errorf("case %d: %+v", i, e)
		}
	}
}

func TestArgoNonScalarRevision(t *testing.T) {
	for _, rev := range []string{"{a: b}", "[v1]", "true"} {
		repo := Analyze(memory(t, map[string]string{
			"app.yaml":   argoApp("a", "    {repoURL: 'https://github.com/example/fleet', path: dir, targetRevision: "+rev+"}\n"),
			"dir/d.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {containers: [{name: c, image: 'r.example.test/i:1'}]}}}\n",
		}), Options{Root: "repo", SelfRepoURLs: []string{"https://github.com/example/fleet"}})
		e := envByName(t, repo, "argocd/a")
		if len(e.Images) != 0 || !hasGap(e.Gaps, ConstructNotEvaluated, "targetRevision is not a string") {
			t.Errorf("targetRevision %s: %+v", rev, e)
		}
	}
}

func deployment(images ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec:\n  template:\n    spec:\n      containers:\n")
	for i, im := range images {
		fmt.Fprintf(&b, "        - {name: c%d, image: '%s'}\n", i, im)
	}
	return b.String()
}

func pinList(e Environment) string {
	var out []string
	for _, p := range e.Images {
		out = append(out, p.Image+":"+p.Tag+"@"+p.Digest)
	}
	return strings.Join(out, ",")
}

// TestImagesTransformer: an images list changes the images of the workloads
// of its own object; it never adds a pin of its own.
func TestImagesTransformer(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	base := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app"),
		"app/d.yaml": deployment("r.example.test/web:v1", "r.example.test/job@"+digest, "r.example.test/other:1")}
	run := func(images string, extra map[string]string) Environment {
		files := with(base, extra)
		files["app/kustomization.yaml"] = "resources: [d.yaml]\nimages:\n" + images
		return envByName(t, analyze(t, files), "app")
	}
	cases := []struct{ images, pins, gap string }{
		{"  - {name: r.example.test/web, newTag: v2}\n", "r.example.test/job:@" + digest + ",r.example.test/other:1@,r.example.test/web:v2@", ""},
		{"  - {name: r.example.test/web, newName: m.example.test/web}\n", "m.example.test/web:v1@,r.example.test/job:@" + digest + ",r.example.test/other:1@", ""},
		{"  - {name: r.example.test/web, digest: '" + digest + "'}\n", "r.example.test/job:@" + digest + ",r.example.test/other:1@,r.example.test/web:@" + digest, ""},
		{"  - {name: r.example.test/job, newTag: '2'}\n", "r.example.test/job:2@,r.example.test/other:1@,r.example.test/web:v1@", ""},
		{"  - {name: r.example.test/web, newName: m.example.test/web}\n  - {name: m.example.test/web, newTag: v3}\n", "m.example.test/web:v3@,r.example.test/job:@" + digest + ",r.example.test/other:1@", ""},
		{"  - {name: r.example.test/none, newTag: v2}\n", "r.example.test/job:@" + digest + ",r.example.test/other:1@,r.example.test/web:v1@", "matches no image read here"},
		{"  - {name: 'r.example.test/web:v1', newTag: v2}\n", "r.example.test/job:@" + digest + ",r.example.test/other:1@,r.example.test/web:v1@", "with a tag or digest"},
		{"  - {name: r.example.test/web, newTag: [v2]}\n", "r.example.test/job:@" + digest + ",r.example.test/other:1@,r.example.test/web:v1@", "newTag is not a string"},
	}
	for _, c := range cases {
		e := run(c.images, nil)
		if pinList(e) != c.pins || (c.gap == "") != (len(e.Gaps) == 0) || (c.gap != "" && !hasGap(e.Gaps, ConstructNotEvaluated, c.gap)) {
			t.Errorf("%q: pins %s, gaps %+v", c.images, pinList(e), e.Gaps)
		}
	}
	// An outer kustomization changes the images of its bases.
	outer := envByName(t, analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./overlay"),
		"overlay/kustomization.yaml": "resources: [../base]\nimages: [{name: r.example.test/web, newTag: v9}]\n",
		"base/kustomization.yaml":    "resources: [d.yaml]\nimages: [{name: r.example.test/web, newTag: v5}]\n",
		"base/d.yaml":                deployment("r.example.test/web:v1"),
	}), "overlay")
	if pinList(outer) != "r.example.test/web:v9@" {
		t.Fatalf("outer rule: %s %+v", pinList(outer), outer.Gaps)
	}
	// It does not reach into a nested Flux Kustomization.
	nested := envByName(t, analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./parent"),
		"parent/kustomization.yaml": "resources: [child.yaml]\nimages: [{name: r.example.test/web, newTag: v9}]\n",
		"parent/child.yaml":         fluxRoot("child", "./apps"),
		"apps/d.yaml":               deployment("r.example.test/web:v1"),
	}), "parent")
	if pinList(nested) != "r.example.test/web:v1@" || !hasGap(nested.Gaps, ConstructNotEvaluated, "matches no image") {
		t.Fatalf("nested: %s %+v", pinList(nested), nested.Gaps)
	}
	// Flux spec.images apply to the Kustomization's own content.
	fluxImages := strings.Replace(fluxRoot("root", "./app"), "spec:\n", "spec:\n  images: [{name: r.example.test/web, newTag: v7}]\n", 1)
	fe := envByName(t, analyze(t, with(base, map[string]string{"root.yaml": fluxImages})), "app")
	if !strings.Contains(pinList(fe), "r.example.test/web:v7@") || strings.Contains(pinList(fe), "web:v1") {
		t.Fatalf("flux images: %s", pinList(fe))
	}
	// Argo CD kustomize.images, in both forms.
	for img, want := range map[string]string{
		"r.example.test/web=m.example.test/web:v3": "m.example.test/web:v3@",
		"r.example.test/web:v4":                    "r.example.test/web:v4@",
		"r.example.test/web@" + digest:             "r.example.test/web:@" + digest,
	} {
		repo := Analyze(memory(t, map[string]string{
			"app.yaml":   argoApp("a", "    {repoURL: 'https://github.com/example/fleet', path: dir, kustomize: {images: ['"+img+"']}}\n"),
			"dir/d.yaml": deployment("r.example.test/web:v1"),
		}), Options{Root: "repo", SelfRepoURLs: []string{"https://github.com/example/fleet"}})
		if e := envByName(t, repo, "argocd/a"); pinList(e) != want || len(e.Gaps) != 0 {
			t.Errorf("argo %s: %s %+v", img, pinList(e), e.Gaps)
		}
	}
}
