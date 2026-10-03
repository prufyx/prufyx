// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// usage runs Analyze and returns the steps each pass charged.
func usage(t *testing.T, files map[string]string, opts Options) (int, int, Repo) {
	t.Helper()
	opts.Root = "repo"
	a := newAnalysis(memory(t, files), opts)
	repo := a.run()
	return a.disc.used, a.work.used, repo
}

func with(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

const templated = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .x }}'}\n"

// TestWorkIsCharged checks, loop by loop, that every item a walk reads costs
// a fixed number of steps: n items cost exactly n times as much as one.
func TestWorkIsCharged(t *testing.T) {
	flux := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./app")}
	argo := func(sources string) string {
		return "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: root, namespace: argocd}\nspec:\n  sources:\n" + sources
	}
	repeat := func(n int, f func(i int) string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(f(i))
		}
		return b.String()
	}
	cases := []struct {
		name             string
		build            func(n int) map[string]string
		discPer, workPer int
		self             []string
	}{
		{"documents of a directory", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: keep}\n"})
			for i := 0; i < n; i++ {
				files[fmt.Sprintf("app/c%d.yaml", i)] = fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c%d}\n", i)
			}
			return files
		}, 0, 1, nil},
		{"omissions of a directory", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "a: 1\n"})
			for i := 0; i < n; i++ {
				files[fmt.Sprintf("app/t%d.yaml", i)] = templated
			}
			return files
		}, 0, 1, nil},
		{"encrypted files of a directory", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "a: 1\n"})
			for i := 0; i < n; i++ {
				files[fmt.Sprintf("app/e%d.yaml", i)] = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: e}\nsops: {mac: x}\n"
			}
			return files
		}, 0, 1, nil},
		{"subdirectories", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "a: 1\n"})
			for i := 0; i < n; i++ {
				files[fmt.Sprintf("app/d%d/c.yaml", i)] = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"
			}
			return files
		}, 1, 2, nil},
		{"kustomization entries", func(n int) map[string]string {
			return with(flux, map[string]string{"app/kustomization.yaml": "resources:\n" + repeat(n, func(i int) string { return fmt.Sprintf("  - missing%d.yaml\n", i) }) + "  - keep.yaml\n"})
		}, 3, 1, nil}, // discovery: parse, resolve, entry
		{"omissions of a resource file", func(n int) map[string]string {
			return with(flux, map[string]string{"app/kustomization.yaml": "resources: [f.yaml]\n", "app/f.yaml": "---\n" + repeat(n+1, func(int) string { return templated + "---\n" })})
		}, 0, 1, nil},
		{"kustomization images", func(n int) map[string]string {
			return with(flux, map[string]string{"app/kustomization.yaml": "images:\n" + repeat(n+1, func(i int) string { return fmt.Sprintf("  - {name: i%d, newTag: '1'}\n", i) })})
		}, 1, 1, nil},
		{"kustomization patches", func(n int) map[string]string {
			patch := "  - target: {kind: HelmRelease, name: web}\n    patch: '[{op: replace, path: /spec/chart/spec/version, value: 1.0.1}]'\n"
			return with(flux, map[string]string{
				"app/kustomization.yaml": "resources: [r.yaml, repo.yaml]\npatches:\n" + repeat(n+1, func(int) string { return patch }),
				"app/r.yaml":             helmRelease("web", "1.0.0"), "app/repo.yaml": helmRepo,
			})
		}, 1, 1, nil},
		{"releases scanned for patches", func(n int) map[string]string {
			files := with(flux, map[string]string{
				"app/kustomization.yaml": "resources: [repo.yaml" + repeat(n+1, func(i int) string { return fmt.Sprintf(", r%d.yaml", i) }) + "]\npatches:\n" +
					"  - target: {kind: HelmRelease, name: r0}\n    patch: '[{op: replace, path: /spec/chart/spec/version, value: 1.0.1}]'\n",
				"app/repo.yaml": helmRepo,
			})
			for i := 0; i <= n; i++ {
				files[fmt.Sprintf("app/r%d.yaml", i)] = helmRelease(fmt.Sprintf("r%d", i), "1.0.0")
			}
			return files
		}, 3, 4, nil}, // discovery: entry parse, resolve and entry; work: entry, document, parse, patch scan
		{"gaps of a document", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "a: 1\n"})
			for i := 0; i < n; i++ {
				files[fmt.Sprintf("app/r%d.yaml", i)] = "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata: {name: x}\nspec: {}\n"
			}
			return files
		}, 0, 3, nil}, // document, parse, gap
		{"Argo CD sources", func(n int) map[string]string {
			return map[string]string{"root.yaml": argo(repeat(n+1, func(i int) string {
				return fmt.Sprintf("    - {repoURL: 'https://charts.example.test', chart: c%d, targetRevision: 1.0.0}\n", i)
			}))}
		}, 2, 1, nil}, // discovery: parse and loop; work: loop
		{"chart dependencies", func(n int) map[string]string {
			return with(flux, map[string]string{"app/Chart.yaml": "apiVersion: v2\nname: c\ndependencies:\n" + repeat(n+1, func(i int) string {
				return fmt.Sprintf("  - {name: d%d, version: 1.0.0, repository: 'https://charts.example.test'}\n", i)
			})})
		}, 0, 2, nil},
		{"chart file dependencies", func(n int) map[string]string {
			return with(flux, map[string]string{"app/Chart.yaml": "apiVersion: v2\nname: c\ndependencies:\n" + repeat(n+1, func(i int) string {
				return fmt.Sprintf("  - {name: d%d, version: 1.0.0, repository: 'file://../none%d'}\n", i, i)
			})})
		}, 0, 3, nil}, // parse, resolve, loop
		{"workload containers", func(n int) map[string]string {
			return with(flux, map[string]string{"app/d.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec:\n  template:\n    spec:\n      containers:\n" +
				repeat(n+1, func(i int) string {
					return fmt.Sprintf("        - {name: c%d, image: 'registry.example.test/i%d:1'}\n", i, i)
				})})
		}, 0, 2, nil},
		{"Flux components", func(n int) map[string]string {
			return with(map[string]string{"git.yaml": gitRepo, "app/keep.yaml": "a: 1\n"}, map[string]string{"root.yaml": fluxRoot("root", "./app") + "  components:\n" +
				repeat(n+1, func(i int) string { return fmt.Sprintf("    - ../none%d\n", i) })})
		}, 3, 1, nil},
		{"root source definitions", func(n int) map[string]string {
			files := with(flux, map[string]string{"app/keep.yaml": "a: 1\n"})
			for i := 0; i <= n; i++ {
				files[fmt.Sprintf("other/g%d.yaml", i)] = gitRepo
			}
			return files
		}, 1, 1, []string{"ssh://git@git.example.test/team/fleet"}},
	}
	for _, c := range cases {
		d0, w0, _ := usage(t, c.build(0), Options{SelfRepoURLs: c.self})
		d4, w4, repo := usage(t, c.build(4), Options{SelfRepoURLs: c.self})
		if d4-d0 != 4*c.discPer || w4-w0 != 4*c.workPer {
			t.Errorf("%s: discovery %d -> %d (want +%d), work %d -> %d (want +%d)", c.name, d0, d4, 4*c.discPer, w0, w4, 4*c.workPer)
		}
		if len(repo.Environments) != 1 {
			t.Errorf("%s: environments = %v", c.name, envNames(repo))
		}
	}
	// Decoding text costs one step per 64 bytes.
	values := func(size int) map[string]string {
		return map[string]string{"root.yaml": argo("    - repoURL: 'https://charts.example.test'\n      chart: c\n      targetRevision: 1.0.0\n      helm:\n        values: |\n" +
			repeat(size/16, func(i int) string { return fmt.Sprintf("          k%06d: v\n", i) }))}
	}
	_, small, _ := usage(t, values(1024), Options{})
	_, large, _ := usage(t, values(64*1024), Options{})
	// Each line decodes to 11 bytes of text.
	if want := (4096*11)/64 - (64*11)/64; large-small != want {
		t.Errorf("decoding 44 KiB cost %d more steps than 704 bytes, want %d", large-small, want)
	}
}

// TestDiscoveryHasItsOwnBudget: finding the roots cannot use up the budget
// of the environments, and the other way round.
func TestDiscoveryHasItsOwnBudget(t *testing.T) {
	files := manyRootsRepo(30, 200)
	files["roots/child.yaml"] = fluxRoot("child", "./apps") // reached from no root, so a root too
	saved := discoveryBudget
	defer func() { discoveryBudget = saved }()
	discoveryBudget = 10
	repo := analyze(t, files)
	if !hasGap(repo.Gaps, ClosureLimit, "finding environment roots") {
		t.Fatalf("discovery limit not reported: %+v", repo.Gaps)
	}
	for _, e := range repo.Environments {
		if len(e.Releases) != 200 {
			t.Fatalf("%s: %d releases, gaps %+v", e.Name, len(e.Releases), e.Gaps)
		}
	}
	discoveryBudget = saved

	savedWork := workBudget
	defer func() { workBudget = savedWork }()
	workBudget = 3
	nested := analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./a"), "a/child.yaml": fluxRoot("child", "./b"),
		"b/r.yaml": helmRelease("web", "1.0.0"),
	})
	if got := envNames(nested); len(got) != 1 || got[0] != "a" {
		t.Fatalf("roots found with a small work budget: %v", got)
	}
	if !hasGap(nested.Environments[0].Gaps, ClosureLimit, "work limit") || !hasGap(nested.Gaps, ClosureLimit, "reading environments") {
		t.Fatalf("work limit not reported: %+v", nested)
	}
}

// TestValuesAreDecodedOnce: an Application reached from several roots is
// decoded once and every environment shares the decoded values.
func TestValuesAreDecodedOnce(t *testing.T) {
	files := bigValuesRepo(1, 2048, 3)
	a := newAnalysis(memory(t, files), Options{Root: "repo", SelfRepoURLs: []string{"https://github.com/example/fleet"}})
	repo := a.run()
	if len(repo.Environments) != 3 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	first := repo.Environments[0].Releases[0].Values
	if len(first) == 0 {
		t.Fatalf("values were not decoded: %+v", repo.Environments[0])
	}
	for _, e := range repo.Environments[1:] {
		if reflect.ValueOf(e.Releases[0].Values).Pointer() != reflect.ValueOf(first).Pointer() {
			t.Fatal("each environment decoded its own values")
		}
	}
	if used := valuesNodeBudget - a.nodes; used != countNodes(first) {
		t.Fatalf("decoded %d nodes for one map of %d", used, countNodes(first))
	}
}

// TestPatchesAreParsedOnce: a kustomization reached from several roots has
// its patches decoded once.
func TestPatchesAreParsedOnce(t *testing.T) {
	a := newAnalysis(memory(t, manyPatchesRepo(3, 5)), Options{Root: "repo"})
	repo := a.run()
	if len(repo.Environments) != 5 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	for _, e := range repo.Environments {
		if len(e.Releases) != 1 || e.Releases[0].ChartVersion != "1.0.2" {
			t.Fatalf("%s: %+v", e.Name, e.Releases)
		}
	}
	// One patch decodes to a list of one object of three members.
	if used := valuesNodeBudget - a.nodes; used != 3*(1+1+3) {
		t.Fatalf("decoded %d nodes for three patches", used)
	}
}

func TestValuesNodeBudget(t *testing.T) {
	saved := valuesNodeBudget
	defer func() { valuesNodeBudget = saved }()
	valuesNodeBudget = 1500
	files := bigValuesRepo(4, 8<<10, 1)
	repo := analyze(t, files, "https://github.com/example/fleet")
	e := repo.Environments[0]
	if !hasGap(e.Gaps, ClosureLimit, "YAML nodes for inline values and patches is used up") {
		t.Fatalf("node budget not reported: %+v", e.Gaps)
	}
	withValues := 0
	for _, r := range e.Releases {
		if r.Values != nil {
			withValues++
		}
	}
	if len(e.Releases) != 4 || withValues == 0 || withValues == 4 {
		t.Fatalf("releases with values: %d of %d", withValues, len(e.Releases))
	}
	// Patches draw on the same budget.
	valuesNodeBudget = 5
	p := analyze(t, manyPatchesRepo(1, 1))
	if !hasGap(p.Environments[0].Gaps, ClosureLimit, "patch not read") {
		t.Fatalf("patch budget not reported: %+v", p.Environments[0].Gaps)
	}
}

func TestTextSizeBounds(t *testing.T) {
	big := bigValuesRepo(1, 2*MaxValuesBytes, 1)
	e := analyze(t, big, "https://github.com/example/fleet").Environments[0]
	if len(e.Releases) != 1 || e.Releases[0].Values != nil || !hasGap(e.Gaps, ValuesFromNotResolved, "longer than 65536") {
		t.Fatalf("helm.values size bound: %+v", e)
	}
	patch := "  - target: {kind: HelmRelease, name: web}\n    patch: |-\n      - op: replace\n        path: /spec/chart/spec/version\n        value: 2.0.0\n      # " +
		strings.Repeat("x", MaxPatchBytes) + "\n"
	p := envByName(t, analyze(t, map[string]string{
		"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./k"),
		"k/kustomization.yaml": "resources: [r.yaml, repo.yaml]\npatches:\n" + patch,
		"k/r.yaml":             helmRelease("web", "1.0.0"), "k/repo.yaml": helmRepo,
	}), "k")
	if p.Releases[0].ChartVersion != "1.0.0" || !hasGap(p.Gaps, PatchNotEvaluated, "longer than 4096") {
		t.Fatalf("patch size bound: %+v", p)
	}
}

func TestEnvironmentBoundIsExact(t *testing.T) {
	for _, n := range []int{MaxEnvironments, MaxEnvironments + 1} {
		files := map[string]string{"git.yaml": gitRepo}
		for i := 0; i < n; i++ {
			files[fmt.Sprintf("r/k%04d.yaml", i)] = fluxRoot(fmt.Sprintf("k%04d", i), "./none")
		}
		repo := analyze(t, files)
		limited := hasGap(repo.Gaps, ClosureLimit, "256 environments")
		if len(repo.Environments) != MaxEnvironments || limited != (n > MaxEnvironments) {
			t.Fatalf("%d roots: %d environments, limit gap %v", n, len(repo.Environments), limited)
		}
	}
}

func TestRepoGapBound(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < MaxGaps+5; i++ {
		files[fmt.Sprintf("o/r%05d.yaml", i)] = helmRelease(fmt.Sprintf("r%d", i), "1.0.0")
	}
	repo := analyze(t, files)
	if len(repo.Gaps) != MaxGaps || !hasGap(repo.Gaps[MaxGaps-1:], ClosureLimit, "4096 gaps") {
		t.Fatalf("repo gaps = %d", len(repo.Gaps))
	}
}

// TestNothingAfterTheWorkLimit: once the budget is used up, a walk adds
// nothing but the gap that says so.
func TestNothingAfterTheWorkLimit(t *testing.T) {
	saved := workBudget
	defer func() { workBudget = saved }()
	workBudget = 0
	repo := analyze(t, map[string]string{"git.yaml": gitRepo, "a.yaml": fluxRoot("a", "./app"), "b.yaml": fluxRoot("b", "./app/"),
		"app/kustomization.yaml": "resources: []\n", "app/kustomization.yml": "resources: []\n"})
	if len(repo.Environments) != 2 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	for _, e := range repo.Environments {
		if len(e.Gaps) != 1 || !hasGap(e.Gaps, ClosureLimit, "work limit") {
			t.Fatalf("%s: %+v", e.Name, e.Gaps)
		}
	}
}

// TestResolveCostsItsLength: a reference costs one step per 64 bytes.
func TestResolveCostsItsLength(t *testing.T) {
	short := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./k"), "k/kustomization.yaml": "resources: [x]\n"}
	long := with(short, map[string]string{"k/kustomization.yaml": "resources: [" + strings.Repeat("a/", 1000) + "x]\n"})
	d0, _, _ := usage(t, short, Options{})
	d1, _, _ := usage(t, long, Options{})
	if d1-d0 != 2000/64 {
		t.Fatalf("a 2001-byte reference cost %d more steps", d1-d0)
	}
}

// TestResultSizeLimit: once the result holds the allowed bytes, nothing more
// is added, and the environments say so.
func TestResultSizeLimit(t *testing.T) {
	saved := resultBytes
	defer func() { resultBytes = saved }()
	resultBytes = 2000
	files := manyRootsRepo(3, 40)
	repo := analyze(t, files)
	total := 0
	for _, e := range repo.Environments {
		for _, r := range e.Releases {
			total += len(r.Chart) + len(r.ChartVersion) + len(r.RepoURL) + len(r.SourceRef) + len(r.Namespace) + len(r.ReleaseName)
		}
		for _, g := range e.Gaps {
			if g.Reason != ClosureLimit {
				total += len(g.Detail)
			}
		}
	}
	if total > resultBytes || total == 0 {
		t.Fatalf("result holds %d bytes", total)
	}
	first, last := repo.Environments[0], repo.Environments[2]
	if !hasGap(first.Gaps, ClosureLimit, "result size limit of 16 MiB reached; the rest") ||
		!hasGap(last.Gaps, ClosureLimit, "reached before this environment was read") || len(last.Releases) != 0 || len(last.Gaps) != 1 {
		t.Fatalf("first %+v\nlast %+v", first.Gaps, last)
	}
	// Inline values count once per release that carries them.
	resultBytes = 2000
	v := analyze(t, bigValuesRepo(4, 1200, 1), "https://github.com/example/fleet")
	if e := v.Environments[0]; len(e.Releases) >= 4 || !hasGap(e.Gaps, ClosureLimit, "result size limit") {
		t.Fatalf("values not counted: %d releases", len(e.Releases))
	}
}
