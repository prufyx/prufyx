// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/batchcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// packWithActiveCRIORule is the shipped rule pack with the withdrawn CRI-O
// rule active again, at the same review date: what a package signed before
// the withdrawal holds.
func packWithActiveCRIORule(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, item := range pack["entries"].([]any) {
		rule := item.(map[string]any)["rule"].(map[string]any)
		if rule["id"] != "cri-o.artifact-short-name-rejected.1-35" {
			continue
		}
		evidence := rule["evidence"].(map[string]any)
		if evidence["state"] != "withdrawn" {
			t.Fatalf("the shipped rule is %v; this test needs a withdrawn rule", evidence["state"])
		}
		evidence["state"] = "active"
		found++
	}
	if found != 1 {
		t.Fatalf("%d rules", found)
	}
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A signed database imported with `db import` that still holds a withdrawn
// rule as active is chosen on the evidence-date tie, and the withdrawn rule
// still answers UNKNOWN: automatically, with --knowledge-db and in a batch.
func TestSignedStoreCannotUnwithdrawEmbeddedWithdrawal(t *testing.T) {
	useDefaultStoreHome(t)
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	index, projects, err := cncfcheck.BuildExternalTargetsFromPack(packWithActiveCRIORule(t), "7")
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
	store, err := knowledgeauto.EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	rootFile := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	packageFile := writeCNCFFile(t, "package.tar", raw, 0o600)
	pinProjects(t, repo.RootDigest)
	if code, out, stderr := runCNCFCLI(t, "db", "import", packageFile, "--profile", "cncf-projects", "--db-root", store, "--bootstrap-root", rootFile, "--bootstrap-root-digest", repo.RootDigest, "--format", "json"); code != 0 {
		t.Fatalf("import: %d %q\n%s", code, stderr, out)
	}

	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
		`"current":{"components":[{"component":"pkg:github/cri-o/cri-o","version":"1.34.0","facts":[]}]},` +
		`"proposed":{"components":[{"component":"pkg:github/cri-o/cri-o","version":"1.35.0","facts":[` +
		`{"id":"component.crio.artifact_named_reference_is_short","state":"declared","boolValue":false},` +
		`{"id":"component.crio.artifact_named_reference_resolution_planned","state":"declared","boolValue":true}]}]}}`)
	inputFile := writeCNCFFile(t, "crio.json", input, 0o600)
	check := []string{"check", "cncf", "--project", "cri-o", "--input", inputFile, "--format", "json"}
	assertWithdrawn := func(name string, code int, out string) {
		t.Helper()
		if code != 11 || !strings.Contains(out, `"reasonCode":"RULE_EVIDENCE_WITHDRAWN"`) || strings.Contains(out, `"status":"PASS"`) || strings.Contains(out, `"status":"BLOCKED"`) {
			t.Fatalf("%s: exit %d\n%s", name, code, out)
		}
	}

	code, out, stderr := runCNCFCLI(t, check...)
	if !strings.Contains(stderr, "knowledge source: local-db, revision 7") || !strings.Contains(stderr, "a later correction") {
		t.Fatalf("the database was not chosen on the tie: %q", stderr)
	}
	assertWithdrawn("automatic", code, out)

	code, out, _ = runCNCFCLI(t, append(append([]string{}, check...), "--knowledge-db", store)...)
	if !strings.Contains(out, `"origin":"external_signed_local"`) {
		t.Fatalf("explicit database not used:\n%s", out)
	}
	assertWithdrawn("--knowledge-db", code, out)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "crio.json"), input, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(batchcheck.Plan{Schema: batchcheck.PlanSchema, Authority: batchcheck.PlanAuthority,
		Knowledge: batchcheck.KnowledgeSelection{Mode: batchcheck.KnowledgeExternalCNCFEmbeddedCommunity, CNCF: "external_signed_local", CommunityProject: "embedded"},
		Items:     []batchcheck.Item{{ID: "crio", Kind: "cncf", Project: "cri-o", From: "1.34.0", To: "1.35.0", InputPath: "crio.json"}}})
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planFile, plan, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = runCNCFCLI(t, "check", "batch", "--plan", planFile, "--root", root, "--knowledge-db", store, "--format", "json")
	if out == "" {
		t.Fatalf("batch: %d %q", code, stderr)
	}
	assertWithdrawn("batch", code, out)
}
