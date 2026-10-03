// SPDX-License-Identifier: AGPL-3.0-only

package cncfknowledge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// TestSelectedBundleRejectsAListedProjectThatWasNotLoaded covers the guard
// that no public entry point can reach: a revision opened for one project
// must never be evaluated for another listed project as if it were empty.
func TestSelectedBundleRejectsAListedProjectThatWasNotLoaded(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, repo.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets("5", nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string][]byte{index.Path: index.Bytes}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	raw, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(dir, "package.tar")
	if err := os.WriteFile(packagePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "store")
	if _, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: packagePath, StoreRoot: store, BootstrapRootPath: rootPath, BootstrapRootDigest: repo.RootDigest}); err != nil {
		t.Fatal(err)
	}
	selected, err := knowledge.OpenSelectedCNCF(knowledge.SelectionRequest{StoreRoot: store}, []string{"kyverno"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, binding, err := selectedBundle("kyverno", selected); err != nil || binding == nil || binding.Status != "present" {
		t.Fatalf("loaded project: binding=%+v err=%v", binding, err)
	}
	if _, _, binding, err := selectedBundle("helm", selected); !errors.Is(err, ErrIntegrity) || binding != nil {
		t.Fatalf("listed but not loaded project evaluated: binding=%+v err=%v", binding, err)
	}
	// A project that is not listed at all is still the UNKNOWN case.
	if _, _, binding, err := selectedBundle("visual-studio-code-kubernetes-tools", selected); err != nil || binding == nil || binding.Status != "absent_from_index" {
		t.Fatalf("unlisted project: binding=%+v err=%v", binding, err)
	}
}
