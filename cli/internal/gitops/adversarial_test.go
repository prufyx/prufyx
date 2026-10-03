// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests build repositories shaped to make a careless walk slow or
// memory-hungry, all well inside the intake limits, and check that Analyze
// stays fast and small at the default bounds.

const (
	adversarialTime  = 2 * time.Second
	adversarialAlloc = 256 << 20
)

func measure(t *testing.T, f func() Repo) (Repo, time.Duration, uint64) {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	repo := f()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return repo, elapsed, after.TotalAlloc - before.TotalAlloc
}

func checkCost(t *testing.T, name string, elapsed time.Duration, alloc uint64) {
	t.Helper()
	t.Logf("%s: %v, %d MiB allocated", name, elapsed, alloc>>20)
	if elapsed > adversarialTime || alloc > adversarialAlloc {
		t.Fatalf("%s took %v and allocated %d MiB", name, elapsed, alloc>>20)
	}
}

// manyEntriesRepo: one kustomization lists the same small file thousands of
// times, next to a directory with thousands of documents and omissions, and
// several roots point at it.
func manyEntriesRepo(roots, docs, entries int) map[string]string {
	files := map[string]string{"git.yaml": gitRepo, "x/blank.yaml": "a: 1\n"}
	for f := 0; f*250 < docs; f++ {
		var cm, tpl strings.Builder
		for i := 0; i < 250 && f*250+i < docs; i++ {
			fmt.Fprintf(&cm, "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c%d-%d}\n", f, i)
			fmt.Fprintf(&tpl, "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .n%d }}'}\n", i)
		}
		files[fmt.Sprintf("x/cm%02d.yaml", f)] = cm.String()
		files[fmt.Sprintf("x/tpl%02d.yaml", f)] = tpl.String()
	}
	var k strings.Builder
	for _, field := range []string{"resources", "bases", "components"} {
		k.WriteString(field + ":\n")
		for i := 0; i < entries; i++ {
			k.WriteString("  - ../x/blank.yaml\n")
		}
	}
	files["k/kustomization.yaml"] = k.String()
	for i := 0; i < roots; i++ {
		files[fmt.Sprintf("roots/r%04d.yaml", i)] = fluxRoot(fmt.Sprintf("r%04d", i), "./k")
	}
	return files
}

// bigValuesRepo: child Applications with large inline helm.values texts,
// reached from many root Applications.
func bigValuesRepo(children, valueBytes, roots int) map[string]string {
	files := map[string]string{}
	var values strings.Builder
	for i := 0; values.Len() < valueBytes; i++ {
		fmt.Fprintf(&values, "        k%05d: v%05d\n", i, i)
	}
	for i := 0; i < children; i++ {
		files[fmt.Sprintf("apps/a%03d.yaml", i)] = fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: a%03d, namespace: argocd}
spec:
  destination: {namespace: a}
  source:
    repoURL: https://charts.example.test
    chart: c%03d
    targetRevision: 1.0.0
    helm:
      values: |
%s`, i, i, values.String())
	}
	for i := 0; i < roots; i++ {
		files[fmt.Sprintf("roots/r%03d.yaml", i)] = fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: r%03d, namespace: argocd}
spec:
  source: {repoURL: "https://github.com/example/fleet", path: apps}
`, i)
	}
	return files
}

// manyPatchesRepo: one kustomization with hundreds of large patches, reached
// from many roots.
func manyPatchesRepo(patches, roots int) map[string]string {
	files := map[string]string{"git.yaml": gitRepo, "base/r.yaml": helmRelease("web", "1.0.0"), "base/repo.yaml": helmRepo}
	var k strings.Builder
	k.WriteString("resources: [../base/r.yaml, ../base/repo.yaml]\npatches:\n")
	pad := strings.Repeat("x", 3900)
	for i := 0; i < patches; i++ {
		fmt.Fprintf(&k, "  - target: {kind: HelmRelease, name: web}\n    patch: |-\n      - op: replace\n        path: /spec/chart/spec/version\n        value: 1.0.%d\n      # %s\n", i, pad)
	}
	files["k/kustomization.yaml"] = k.String()
	for i := 0; i < roots; i++ {
		files[fmt.Sprintf("roots/r%03d.yaml", i)] = fluxRoot(fmt.Sprintf("r%03d", i), "./k")
	}
	return files
}

// manyRootsRepo: many roots point at one directory of many HelmReleases.
func manyRootsRepo(roots, releases int) map[string]string {
	files := map[string]string{"git.yaml": gitRepo, "apps/repo.yaml": helmRepo}
	for f := 0; f*200 < releases; f++ {
		var b strings.Builder
		for i := 0; i < 200 && f*200+i < releases; i++ {
			b.WriteString("---\n" + helmRelease(fmt.Sprintf("r%d-%d", f, i), "1.0.0"))
		}
		files[fmt.Sprintf("apps/r%02d.yaml", f)] = b.String()
	}
	for i := 0; i < roots; i++ {
		files[fmt.Sprintf("roots/r%04d.yaml", i)] = fluxRoot(fmt.Sprintf("r%04d", i), "./apps")
	}
	return files
}

func TestAdversarialManyEntries(t *testing.T) {
	ws := memory(t, manyEntriesRepo(10, 2000, 2048))
	repo, elapsed, alloc := measure(t, func() Repo { return Analyze(ws, Options{Root: "repo"}) })
	checkCost(t, "many entries", elapsed, alloc)
	if len(repo.Environments) != 10 {
		t.Fatalf("environments = %d", len(repo.Environments))
	}
}

func TestAdversarialBigValues(t *testing.T) {
	ws := memory(t, bigValuesRepo(100, 60<<10, 40))
	repo, elapsed, alloc := measure(t, func() Repo {
		return Analyze(ws, Options{Root: "repo", SelfRepoURLs: []string{"https://github.com/example/fleet"}})
	})
	checkCost(t, "big values", elapsed, alloc)
	if len(repo.Environments) != 40 {
		t.Fatalf("environments = %d", len(repo.Environments))
	}
}

func TestAdversarialManyPatches(t *testing.T) {
	ws := memory(t, manyPatchesRepo(480, 20))
	repo, elapsed, alloc := measure(t, func() Repo { return Analyze(ws, Options{Root: "repo"}) })
	checkCost(t, "many patches", elapsed, alloc)
	if len(repo.Environments) != 20 {
		t.Fatalf("environments = %d", len(repo.Environments))
	}
}

func TestAdversarialManyRoots(t *testing.T) {
	ws := memory(t, manyRootsRepo(300, 1000))
	repo, elapsed, alloc := measure(t, func() Repo { return Analyze(ws, Options{Root: "repo"}) })
	checkCost(t, "many roots", elapsed, alloc)
	if len(repo.Environments) != MaxEnvironments {
		t.Fatalf("environments = %d", len(repo.Environments))
	}
	for _, e := range repo.Environments {
		if len(e.Releases) == 0 {
			t.Fatalf("%s has no release: %+v", e.Name, e.Gaps)
		}
	}
}
