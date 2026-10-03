// SPDX-License-Identifier: AGPL-3.0-only

package cncfknowledge_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// TestPerProjectStoreEvaluatesLikeSingleTarget imports the embedded pack once
// as a single target and once split per project, and requires identical
// claims. A project absent from the index stays UNKNOWN.
func TestPerProjectStoreEvaluatesLikeSingleTarget(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	dir := t.TempDir()
	root := writePrivate(t, dir, "root.json", repo.Root)

	single, err := cncfcheck.ExportEmbeddedExternalBundle("5")
	if err != nil {
		t.Fatal(err)
	}
	singleRaw, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: map[string][]byte{knowledge.ConstraintsTargetPath: single}})
	if err != nil {
		t.Fatal(err)
	}
	singleStore := filepath.Join(dir, "single")
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: writePrivate(t, dir, "single.tar", singleRaw), StoreRoot: singleStore, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest}); err != nil {
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
	splitRaw, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	splitStore := filepath.Join(dir, "split")
	splitReceipt, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: writePrivate(t, dir, "split.tar", splitRaw), StoreRoot: splitStore, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest})
	if err != nil {
		t.Fatal(err)
	}

	empty := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[]},"proposed":{"components":[]}}`)
	for _, tc := range []struct {
		project string
		input   []byte
	}{{"kyverno", []byte(kyvernoInputTrue)}, {"kyverno", []byte(kyvernoInputFalse)}, {"helm", empty}} {
		a, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: singleStore}, Project: tc.project, Input: tc.input, InputDigest: digest(tc.input)})
		if err != nil {
			t.Fatal(err)
		}
		b, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: splitStore}, Project: tc.project, Input: tc.input, InputDigest: digest(tc.input)})
		if err != nil {
			t.Fatal(err)
		}
		claimsA, _ := json.Marshal(a.Check.Check.Claims)
		claimsB, _ := json.Marshal(b.Check.Check.Claims)
		if !bytes.Equal(claimsA, claimsB) || cncfknowledge.ClaimExit(a) != cncfknowledge.ClaimExit(b) {
			t.Fatalf("%s: layouts disagree:\nsingle=%s\nsplit=%s", tc.project, claimsA, claimsB)
		}
		binding := b.Knowledge.ProjectTarget
		if a.Knowledge.ProjectTarget != nil || binding == nil || binding.Status != "present" || binding.TargetPath != cncfcheck.ProjectTargetPath(tc.project) || b.Check.KnowledgePackDigest != binding.Digest || b.Knowledge.TargetPath != knowledge.ConstraintsProjectsIndexTargetPath || b.Knowledge.BundleDigest != splitReceipt.TrustReceipt.TargetDigest {
			t.Fatalf("%s: binding=%+v knowledge=%+v", tc.project, binding, b.Knowledge)
		}
	}
	if report, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: splitStore}, Project: "kyverno", Input: []byte(kyvernoInputTrue)}); err != nil || len(report.Check.Check.Claims) == 0 {
		t.Fatalf("kyverno claims missing from per-project store: %+v err=%v", report.Check.Check.Claims, err)
	}

	absent := cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: splitStore}, Project: "visual-studio-code-kubernetes-tools", Input: empty, InputDigest: digest(empty)}
	report, err := cncfknowledge.EvaluateCurrent(absent)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != "UNKNOWN" || len(report.Check.Check.Claims) != 0 || cncfknowledge.ClaimExit(report) != 11 || report.Knowledge.ProjectTarget == nil || report.Knowledge.ProjectTarget.Status != "absent_from_index" {
		t.Fatalf("absent project report=%+v", report.Knowledge)
	}

	// Historical replay pins the index identities from the report.
	current := cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: splitStore}, Project: "kyverno", Input: []byte(kyvernoInputTrue), InputDigest: digest([]byte(kyvernoInputTrue))}
	original, err := cncfknowledge.EvaluateCurrent(current)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustMarshalReport(t, original)
	current.Selection = knowledge.SelectionRequest{StoreRoot: splitStore, ExpectedRevision: original.Knowledge.Revision, ExpectedBundleDigest: original.Knowledge.BundleDigest, ExpectedTrustReceiptDigest: original.Knowledge.TrustReceiptDigest}
	replay, err := cncfknowledge.ReplayHistorical(current, append(raw, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if replayRaw, err := cncfknowledge.MarshalHistoricalReplay(replay); err != nil || !bytes.Contains(replayRaw, raw) {
		t.Fatalf("per-project replay err=%v", err)
	}
}
