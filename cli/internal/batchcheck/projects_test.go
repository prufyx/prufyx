// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// TestEvaluateWithPerProjectStoreOpensOnlyPlannedProjects binds a batch to a
// per-project store and checks the opener receives exactly the CNCF projects
// named by the plan.
func TestEvaluateWithPerProjectStoreOpensOnlyPlannedProjects(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	dir := t.TempDir()
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets("3", nil)
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
	rootPath, packagePath := filepath.Join(dir, "root.json"), filepath.Join(dir, "package.tar")
	if os.WriteFile(rootPath, repo.Root, 0o600) != nil || os.WriteFile(packagePath, raw, 0o600) != nil {
		t.Fatal("write fixture")
	}
	store := filepath.Join(dir, "store")
	receipt, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: packagePath, StoreRoot: store, BootstrapRootPath: rootPath, BootstrapRootDigest: repo.RootDigest})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "kyverno.json"), canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
		map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
		map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
		map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": true},
	}))
	writeBatchFile(t, filepath.Join(root, "loki.json"), canonical("pkg:github/grafana/loki", "2.9.8", "3.0.0", []any{}, []any{boolFact("component.loki.compactor_legacy_shared_store_present", false)}))
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), signedKnowledgePlan([]Item{
		{ID: "signed-cncf", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"},
		{ID: "embedded-neutral", Kind: "community_project", Project: "loki", From: "2.9.8", To: "3.0.0", InputPath: "loki.json"},
	}))
	var requested []string
	open := func(selection knowledge.SelectionRequest, projects []string) (knowledge.VerifiedRevision, error) {
		requested = append([]string(nil), projects...)
		return knowledge.OpenSelectedCNCF(selection, projects)
	}
	report, exit, err := evaluate(planPath, root, time.Time{}, store, currentbundle.OpenDirectoryNoFollow, open)
	if err != nil || exit != 10 || len(report.Items) != 2 || !reflect.DeepEqual(requested, []string{"kyverno"}) {
		t.Fatalf("report=%+v exit=%d err=%v requested=%v", report, exit, err, requested)
	}
	if report.KnowledgeRevision != "3" || report.KnowledgeBundleDigest != receipt.TrustReceipt.TargetDigest || report.Items[0].KnowledgeOrigin != "external_signed_local" {
		t.Fatalf("binding=%+v", report)
	}
}
