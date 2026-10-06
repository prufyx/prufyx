// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func perProjectPackage(t *testing.T, repo *knowledgefixture.ProjectsRepository, version int64, revision string) []byte {
	t.Helper()
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets(revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string][]byte{index.Path: index.Bytes}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	raw, err := repo.Package(knowledgefixture.ProjectsPackage{Version: version, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKnowledgeUpdatePerProjectProfileUsesPerProjectTransport(t *testing.T) {
	t.Parallel()
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	raw := perProjectPackage(t, repo, 1, "4")
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	store := filepath.Join(t.TempDir(), "store")
	args, _ := updateCLIArgs(t, store, "retained.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", repo.RootDigest)
	for i := range args {
		if args[i] == "cncf" {
			args[i] = "cncf-projects"
		}
	}
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	single := func(context.Context, string) ([]byte, error) {
		t.Fatal("single-target transport used")
		return nil, nil
	}
	perProject := func(context.Context, string) ([]byte, error) { return raw, nil }
	code := r.databaseUpdateWithFetches(context.Background(), args, single, perProject)
	var output knowledgeUpdateOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || code != ExitOK || output.Status != "IMPORTED" || output.ImportReceipt == nil || len(output.ImportReceipt.ProjectTargets) == 0 || output.ImportReceipt.TrustReceipt.TargetPath != knowledge.ConstraintsProjectsIndexTargetPath {
		t.Fatalf("code=%d output=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	if code := r.databaseStatus([]string{"--db-root", store, "--profile", "cncf-projects"}); code != ExitOK || !strings.Contains(stdout.String(), "knowledge profile: cncf-projects") || !strings.Contains(stdout.String(), "knowledge database state: READY") {
		t.Fatalf("status code=%d output=%s", code, stdout.String())
	}
}

func TestKnowledgeUpdateSingleTargetProfileRejectsPerProjectPackageClearly(t *testing.T) {
	t.Parallel()
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "root.json", artifacts.Root, 0o600)
	store := filepath.Join(t.TempDir(), "store")
	args, _ := updateCLIArgs(t, store, "first.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest)
	if code, output, stderr := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code != ExitOK || output.Status != "IMPORTED" {
		t.Fatalf("seed import code=%d output=%+v stderr=%s", code, output, stderr)
	}
	before, err := knowledge.InspectConstraints(store)
	if err != nil || before.State != "READY" {
		t.Fatalf("seed status=%+v err=%v", before, err)
	}

	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	args, _ = updateCLIArgs(t, store, "per-project.tar")
	code, output, _ := runKnowledgeUpdate(t, perProjectPackage(t, repo, 1, "4"), nil, args...)
	if code != ExitUsage || output.Status != "REJECTED" || output.ReasonCode != "KNOWLEDGE_LAYOUT_MISMATCH" || !output.PackageRetained || !strings.Contains(output.NextAction, "--profile cncf-projects") {
		t.Fatalf("code=%d output=%+v", code, output)
	}
	after, err := knowledge.InspectConstraints(store)
	if err != nil || after.State != "READY" || after.SelectedRevision != before.SelectedRevision || after.SelectedBundleDigest != before.SelectedBundleDigest || after.TrustStateDigest != before.TrustStateDigest {
		t.Fatalf("store changed: before=%+v after=%+v err=%v", before, after, err)
	}
}
