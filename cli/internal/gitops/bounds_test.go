// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func doc(display string, index int, apiVersion, kind, ns, name string, spec map[string]any) intake.Document {
	return intake.Document{
		Source:     intake.Source{Display: display, Digest: "sha256:x", Document: index, Item: -1},
		APIVersion: apiVersion, Kind: kind, Namespace: ns, Name: name,
		Value: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec},
	}
}

func flux(display string, index int, name, path string) intake.Document {
	return doc(display, index, "kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", name, map[string]any{
		"path": path, "sourceRef": map[string]any{"kind": "GitRepository", "name": "fleet"},
	})
}

func release(display string, index int, name string) intake.Document {
	return doc(display, index, "helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", name, map[string]any{
		"chart": map[string]any{"spec": map[string]any{"chart": name, "version": "1.0.0",
			"sourceRef": map[string]any{"kind": "HelmRepository", "name": "charts"}}},
	})
}

// gitDoc is the GitRepository the Kustomizations made by flux use.
func gitDoc() intake.Document {
	return doc("repo/git.yaml", 0, "source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "fleet", map[string]any{"url": "ssh://git@git.example.test/team/fleet"})
}

func TestEnvironmentBound(t *testing.T) {
	ws := intake.Workspace{Documents: []intake.Document{gitDoc()}}
	for i := 0; i < MaxEnvironments+5; i++ {
		ws.Documents = append(ws.Documents, flux(fmt.Sprintf("repo/r/k%04d.yaml", i), 0, fmt.Sprintf("k%04d", i), "./none"))
	}
	repo := Analyze(ws, Options{Root: "repo"})
	if len(repo.Environments) != MaxEnvironments || !hasGap(repo.Gaps, ClosureLimit, "256 environments") {
		t.Fatalf("environments = %d, gaps = %+v", len(repo.Environments), repo.Gaps)
	}
}

func TestReleaseBound(t *testing.T) {
	ws := intake.Workspace{Documents: []intake.Document{gitDoc()}}
	ws.Documents = append(ws.Documents, flux("repo/root.yaml", 0, "root", "./app"))
	for i := 0; i < MaxReleases+3; i++ {
		ws.Documents = append(ws.Documents, release(fmt.Sprintf("repo/app/r%05d.yaml", i), 0, fmt.Sprintf("r%05d", i)))
	}
	repo := Analyze(ws, Options{Root: "repo"})
	e := repo.Environments[0]
	if len(e.Releases) != MaxReleases || !hasGap(e.Gaps, ClosureLimit, "4096 releases") {
		t.Fatalf("releases = %d, gaps = %d", len(e.Releases), len(e.Gaps))
	}
}

func TestImageBound(t *testing.T) {
	ws := intake.Workspace{Documents: []intake.Document{gitDoc()}}
	ws.Documents = append(ws.Documents, flux("repo/root.yaml", 0, "root", "./app"))
	for i := 0; i < MaxImages+3; i++ {
		ws.Documents = append(ws.Documents, doc(fmt.Sprintf("repo/app/p%05d.yaml", i), 0, "v1", "Pod", "apps", fmt.Sprintf("p%d", i), map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": fmt.Sprintf("registry.example.test/i%d:1", i)}},
		}))
	}
	repo := Analyze(ws, Options{Root: "repo"})
	e := repo.Environments[0]
	if len(e.Images) != MaxImages || !hasGap(e.Gaps, ClosureLimit, "4096 image pins") {
		t.Fatalf("images = %d, gaps = %+v", len(e.Images), e.Gaps)
	}
}

func TestGapBound(t *testing.T) {
	ws := intake.Workspace{Documents: []intake.Document{gitDoc()}}
	ws.Documents = append(ws.Documents, flux("repo/root.yaml", 0, "root", "./app"))
	for i := 0; i < MaxGaps+10; i++ {
		d := release(fmt.Sprintf("repo/app/r%05d.yaml", i), 0, "x")
		d.Value["spec"] = map[string]any{} // no chart: one gap each
		ws.Documents = append(ws.Documents, d)
	}
	repo := Analyze(ws, Options{Root: "repo"})
	e := repo.Environments[0]
	if len(e.Gaps) != MaxGaps+1 && len(e.Gaps) != MaxGaps {
		t.Fatalf("gaps = %d", len(e.Gaps))
	}
	if len(e.Gaps) > MaxGaps+1 || !hasGap(e.Gaps, ClosureLimit, "4096 gaps") {
		t.Fatalf("gap bound: %d gaps", len(e.Gaps))
	}
}

func TestSourceBound(t *testing.T) {
	var sources []any
	for i := 0; i < MaxSources+6; i++ {
		sources = append(sources, map[string]any{"repoURL": "https://charts.example.test", "chart": fmt.Sprintf("c%d", i), "targetRevision": "1.0.0"})
	}
	ws := intake.Workspace{Documents: []intake.Document{
		doc("repo/app.yaml", 0, "argoproj.io/v1alpha1", "Application", "argocd", "many", map[string]any{"sources": sources}),
	}}
	repo := Analyze(ws, Options{Root: "repo"})
	e := repo.Environments[0]
	if len(e.Releases) != MaxSources || !hasGap(e.Gaps, ClosureLimit, "64 sources") {
		t.Fatalf("releases = %d, gaps = %+v", len(e.Releases), e.Gaps)
	}
}

func TestWorkBudget(t *testing.T) {
	saved := workBudget
	defer func() { workBudget = saved }()
	workBudget = 50
	ws := intake.Workspace{Documents: []intake.Document{gitDoc()}}
	for i := 0; i < 20; i++ {
		ws.Documents = append(ws.Documents, flux(fmt.Sprintf("repo/k%02d.yaml", i), 0, fmt.Sprintf("k%02d", i), "./a"))
	}
	for i := 0; i < 100; i++ {
		ws.Documents = append(ws.Documents, release(fmt.Sprintf("repo/a/r%03d.yaml", i), 0, fmt.Sprintf("r%03d", i)))
	}
	repo := Analyze(ws, Options{Root: "repo"})
	if !hasGap(repo.Gaps, ClosureLimit, "work limit") {
		t.Fatalf("gaps = %+v", repo.Gaps)
	}
	if len(repo.Environments) != 20 {
		t.Fatalf("environments = %v", envNames(repo))
	}
	for _, e := range repo.Environments {
		if !hasGap(e.Gaps, ClosureLimit, "work limit") && len(e.Releases) < 100 {
			t.Fatalf("%s is silently incomplete", e.Name)
		}
	}
	if last := repo.Environments[19]; !hasGap(last.Gaps, ClosureLimit, "before this environment was read") {
		t.Fatalf("last environment gaps = %+v", last.Gaps)
	}
}

func TestDiamondDoesNotMultiply(t *testing.T) {
	// Every level references the next level twice; without a visited set the
	// walk would take 2^20 steps.
	files := map[string]string{"git.yaml": gitRepo, "root.yaml": fluxRoot("root", "./l0")}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("l%d/kustomization.yaml", i)] = fmt.Sprintf("resources:\n  - ../l%d\n  - ../l%d/\n  - ../l%d/.\n", i+1, i+1, i+1)
	}
	files["l20/r.yaml"] = helmRelease("leaf", "1.0.0")
	files["l20/repo.yaml"] = helmRepo
	repo := analyze(t, files)
	e := envByName(t, repo, "l0")
	if len(e.Releases) != 1 {
		t.Fatalf("%+v", e)
	}
}

func TestLongFieldsAreRefused(t *testing.T) {
	long := strings.Repeat("a", 300)
	ws := intake.Workspace{Documents: []intake.Document{
		doc("repo/app.yaml", 0, "argoproj.io/v1alpha1", "Application", "argocd", "long", map[string]any{
			"source": map[string]any{"repoURL": "https://charts.example.test/" + long, "chart": "web", "targetRevision": "1.0.0"},
		}),
	}}
	repo := Analyze(ws, Options{Root: "repo"})
	e := repo.Environments[0]
	if len(e.Releases) != 0 || !hasGap(e.Gaps, SourceNotFound, "256 bytes") {
		t.Fatalf("%+v", e)
	}
	for _, g := range e.Gaps {
		if len(g.Detail) > MaxFieldBytes {
			t.Fatalf("detail too long: %d", len(g.Detail))
		}
	}
	if got := len(clip(strings.Repeat("é", 200))); got > MaxFieldBytes || got%2 != 0 {
		t.Fatalf("clip cut a rune: %d", got)
	}
}
