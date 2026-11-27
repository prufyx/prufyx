// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// perProjectPackage is the shipped knowledge as a publisher builds it for
// clients from the floor.
func perProjectPackage(t *testing.T, repo *knowledgefixture.ProjectsRepository, version int64, revision string) []byte {
	t.Helper()
	return signedPerProjectPackage(t, repo, version, revision, buildEmbeddedForFloorClient)
}

// The shipped floor package offered to a client below the floor is too new:
// exit 15, trust not advanced, the data directory untouched.
func TestKnowledgeUpdateShippedFloorPackageIsTooNewBelowTheFloor(t *testing.T) {
	// buildidentity.Version is a package variable, so this test cannot run in
	// parallel.
	old := buildidentity.Version
	buildidentity.Version = oldClientFloor
	t.Cleanup(func() { buildidentity.Version = old })
	env := newDefaultUpdateEnv(t)
	if code, _, stderr := runDefaultUpdate(t, oldClientPackage(t, env.repo, 1, "4")); code != ExitOK {
		t.Fatal(code, stderr)
	}
	index, _, err := buildEmbeddedForFloorClient("5")
	if err != nil {
		t.Fatal(err)
	}
	minimum, ok := cncfcheck.ExternalIndexMinClient(index.Bytes)
	if !ok || !buildidentity.ValidVersion(minimum) || buildidentity.AtLeast(oldClientFloor, minimum) {
		t.Fatalf("the shipped floor index names minClientVersion %q (present=%t), want one above %s", minimum, ok, oldClientFloor)
	}
	before, err := knowledge.InspectConstraintsProjects(env.store)
	if err != nil || before.State != "READY" || before.TrustStateDigest == "" {
		t.Fatalf("seed status=%+v err=%v", before, err)
	}
	tree := snapshotTree(t, env.data)

	code, out, _ := runDefaultUpdate(t, perProjectPackage(t, env.repo, 2, "5"))
	if code != ExitKnowledgeTooNew || out.ReasonCode != "KNOWLEDGE_TOO_NEW_FOR_THIS_CLIENT" || out.Rejection == nil || out.Rejection.TrustStateAdvanced || out.Rejection.SelectionChanged || out.ImportReceipt != nil {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if !strings.Contains(out.NextAction, "upgrade prufyx to >= "+minimum) {
		t.Fatalf("next action = %q", out.NextAction)
	}
	after, err := knowledge.InspectConstraintsProjects(env.store)
	if err != nil || after.State != "READY" || after.SelectedRevision != "4" || after.SelectedBundleDigest != before.SelectedBundleDigest || after.TrustStateDigest != before.TrustStateDigest {
		t.Fatalf("store changed: before=%+v after=%+v err=%v", before, after, err)
	}
	if got := snapshotTree(t, env.data); !maps.Equal(tree, got) {
		t.Fatalf("data directory changed: %d entries before, %d after", len(tree), len(got))
	}
}

// oldClientPackage is the downlevel package, for import and refusal behaviour
// of a client below the floor only.
func oldClientPackage(t *testing.T, repo *knowledgefixture.ProjectsRepository, version int64, revision string) []byte {
	t.Helper()
	return signedPerProjectPackage(t, repo, version, revision, buildEmbeddedForOldClient)
}

func signedPerProjectPackage(t *testing.T, repo *knowledgefixture.ProjectsRepository, version int64, revision string, build func(string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, error)) []byte {
	t.Helper()
	index, projects, err := build(revision)
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
	// The fixture root is not the official root: drop the pin for this test.
	// The pin is a package variable, so this test cannot run in parallel.
	oldPin := pinnedRootDigest
	pinnedRootDigest = func(string) string { return "" }
	t.Cleanup(func() { pinnedRootDigest = oldPin })
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

// oldClientFloor is a client below both floors.
const oldClientFloor = "v0.1.0-beta.0"

// buildEmbeddedForFloorClient builds the shipped per-project layout for
// clients from the floor.
func buildEmbeddedForFloorClient(revision string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, error) {
	index, projects, _, err := cncfcheck.BuildEmbeddedExternalTargetsPinned(revision, nil, cncfcheck.BoundaryCoveredFloor)
	return index, projects, err
}

// buildEmbeddedForOldClient builds a downlevel package: the embedded pack
// without the listed family and without the declared opt-in level, so its
// index names no minClientVersion. It evaluates line-wide rules under the
// older contract: use it for import and refusal behaviour only, never to
// compare verdicts.
func buildEmbeddedForOldClient(revision string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, error) {
	var none cncfcheck.ExternalTarget
	raw, err := cncfcheck.EmbeddedRulePack()
	if err != nil {
		return none, nil, err
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(raw, &pack); err != nil {
		return none, nil, err
	}
	if section, ok := pack["lineAttestations"]; ok {
		kept, _, err := cncfcheck.ExcludeListedAttestations(section, oldClientFloor)
		if err != nil {
			return none, nil, err
		}
		if len(kept) == 0 {
			delete(pack, "lineAttestations")
		} else {
			pack["lineAttestations"] = kept
		}
	}
	pack["schema"] = json.RawMessage(`""`)
	if raw, err = json.Marshal(pack); err != nil {
		return none, nil, err
	}
	schema, err := cncfcheck.RequiredPackSchema(raw)
	if err != nil {
		return none, nil, err
	}
	if cncfcheck.PackSchemaIsOptIn(schema) {
		return none, nil, fmt.Errorf("the downlevel pack still states the opt-in level %s", schema)
	}
	if pack["schema"], err = json.Marshal(schema); err != nil {
		return none, nil, err
	}
	if raw, err = json.Marshal(pack); err != nil {
		return none, nil, err
	}
	index, projects, _, err := cncfcheck.BuildExternalTargetsFromPackPinned(raw, revision, oldClientFloor)
	if err != nil {
		return none, nil, err
	}
	if minimum, ok := cncfcheck.ExternalIndexMinClient(index.Bytes); ok {
		return none, nil, fmt.Errorf("the downlevel index names minClientVersion %s", minimum)
	}
	return index, projects, nil
}
