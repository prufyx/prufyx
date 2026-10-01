// SPDX-License-Identifier: AGPL-3.0-only

package cncfknowledge_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

const (
	kyvernoInputFalse = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.kyverno.execution_surface","state":"declared","enumValue":"reports_controller"},{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":false}]}]}}`
	kyvernoInputTrue  = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.kyverno.execution_surface","state":"declared","enumValue":"reports_controller"},{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":true}]}]}}`
)

type fixtureState struct {
	dir       string
	store     string
	manifest  knowledgefixture.Manifest
	artifacts knowledgefixture.Artifacts
	package2  string
	receipt1  knowledge.ImportReceipt
	receipt2  knowledge.ImportReceipt
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writePrivate(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeFixture(t *testing.T) fixtureState {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateConstraints(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "cncf-store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writePrivate(t, dir, knowledgefixture.RootName, artifacts.Root)
	p1 := writePrivate(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	p2 := writePrivate(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	r1, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureState{dir: dir, store: store, manifest: manifest, artifacts: artifacts, package2: p2, receipt1: r1}
}

func importSecond(t *testing.T, state *fixtureState) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: state.package2, StoreRoot: state.store, ExpectedRevision: "2", ExpectedBundleDigest: state.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	state.receipt2 = receipt
}

func selection(state fixtureState, revision, bundle, receipt string) knowledge.SelectionRequest {
	return knowledge.SelectionRequest{StoreRoot: state.store, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt}
}

func request(state fixtureState, revision, bundle, receipt string, input []byte) cncfknowledge.Request {
	return cncfknowledge.Request{Selection: selection(state, revision, bundle, receipt), Project: "kyverno", Input: input, InputDigest: digest(input)}
}

func TestExternalKnowledgeEndToEndEmptyThenActiveAndNoFallback(t *testing.T) {
	state := makeFixture(t)
	empty := request(state, "1", state.manifest.Revisions[0].BundleDigest, state.receipt1.TrustReceiptDigest, []byte(kyvernoInputFalse))
	report1, err := cncfknowledge.EvaluateCurrent(empty)
	if err != nil {
		t.Fatal(err)
	}
	if report1.Assessment != "UNKNOWN" || len(report1.Check.Check.Claims) != 0 || cncfknowledge.ClaimExit(report1) != 11 {
		t.Fatalf("empty external coverage was not UNKNOWN: %+v", report1.Check.Check.Claims)
	}
	if report1.Knowledge.Purpose != "synthetic_test_only" || report1.Knowledge.TargetPath != knowledge.ConstraintsTargetPath || report1.Knowledge.Revision != "1" || report1.Knowledge.BundleDigest != state.manifest.Revisions[0].BundleDigest || report1.Knowledge.TrustReceiptDigest != state.receipt1.TrustReceiptDigest || report1.Knowledge.EngineCapabilityDigest == "" || report1.Knowledge.TrustSource != "OPERATOR_PROVISIONED" || report1.Knowledge.CurrentNonRevocation != "not_checked_offline" || report1.Check.KnowledgeRevision != "1" || report1.Check.KnowledgePackDigest != report1.Knowledge.BundleDigest || report1.Check.InputFileDigest != digest([]byte(kyvernoInputFalse)) {
		t.Fatalf("incomplete empty binding: %+v", report1.Knowledge)
	}
	importSecond(t, &state)
	active := request(state, "2", state.manifest.Revisions[1].BundleDigest, state.receipt2.TrustReceiptDigest, []byte(kyvernoInputTrue))
	report2, err := cncfknowledge.EvaluateCurrent(active)
	if err != nil {
		t.Fatal(err)
	}
	if len(report2.Check.Check.Claims) != 1 || report2.Check.Check.Claims[0].Status != "BLOCKED" || cncfknowledge.ClaimExit(report2) != 10 {
		t.Fatalf("active Kyverno rule not blocked: %+v", report2.Check.Check.Claims)
	}
	other := active
	other.Project = "helm"
	other.Input = []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[]},"proposed":{"components":[]}}`)
	other.InputDigest = digest(other.Input)
	otherReport, err := cncfknowledge.EvaluateCurrent(other)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherReport.Check.Check.Claims) != 0 || cncfknowledge.ClaimExit(otherReport) != 11 {
		t.Fatalf("external pack fell back to embedded Helm rules: %+v", otherReport.Check.Check.Claims)
	}
	for _, raw := range [][]byte{mustMarshalReport(t, report1), mustMarshalReport(t, report2)} {
		if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("secret")) {
			t.Fatalf("private material crossed report boundary: %s", raw)
		}
	}
}

func TestEvaluateVerifiedRejectsUnissuedCapability(t *testing.T) {
	_, err := cncfknowledge.EvaluateVerified(knowledge.VerifiedRevision{}, cncfknowledge.CheckInput{Project: "kyverno", Input: []byte(kyvernoInputFalse), InputDigest: digest([]byte(kyvernoInputFalse))})
	if !errors.Is(err, cncfknowledge.ErrIntegrity) {
		t.Fatalf("unissued capability error=%v", err)
	}
}

func mustMarshalReport(t *testing.T, report cncfknowledge.Report) []byte {
	t.Helper()
	raw, err := cncfknowledge.MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExternalKnowledgeHistoricalReplayExactPinsAndMutation(t *testing.T) {
	if _, err := cncfknowledge.MarshalReport(cncfknowledge.Report{}); !errors.Is(err, cncfknowledge.ErrIntegrity) {
		t.Fatalf("zero report error=%v", err)
	}
	state := makeFixture(t)
	req := request(state, "1", state.manifest.Revisions[0].BundleDigest, state.receipt1.TrustReceiptDigest, []byte(kyvernoInputFalse))
	req.SelectedRuleID = "kyverno.reports-chunk-size-removed.1-13"
	report, err := cncfknowledge.EvaluateCurrent(req)
	if err != nil {
		t.Fatal(err)
	}
	reportRaw := mustMarshalReport(t, report)
	if report.Check.RequestedRuleID != req.SelectedRuleID || report.Check.SelectedRuleID != "" || len(report.Check.Check.Claims) != 0 {
		t.Fatalf("selected empty external report=%+v", report.Check)
	}
	importSecond(t, &state)
	replay, err := cncfknowledge.ReplayHistorical(req, append(append([]byte(nil), reportRaw...), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	replayRaw, err := cncfknowledge.MarshalHistoricalReplay(replay)
	if err != nil || cncfknowledge.HistoricalClaimExit(replay) != 11 || !bytes.Contains(replayRaw, reportRaw) || !bytes.Contains(replayRaw, []byte(`"currentNonRevocation":"not_checked_offline"`)) {
		t.Fatalf("historical replay=%s err=%v", replayRaw, err)
	}
	mutatedReplay := replay
	mutatedReplay.Status = "PASS"
	if _, err := cncfknowledge.MarshalHistoricalReplay(mutatedReplay); !errors.Is(err, cncfknowledge.ErrIntegrity) {
		t.Fatalf("mutated replay status error=%v", err)
	}
	mutatedReplay = replay
	mutatedReplay.OriginalReport = []byte(`{}\n`)
	if _, err := cncfknowledge.MarshalHistoricalReplay(mutatedReplay); !errors.Is(err, cncfknowledge.ErrIntegrity) {
		t.Fatalf("mutated replay payload error=%v", err)
	}
	for _, bad := range [][]byte{
		reportRaw,
		append(append([]byte(nil), reportRaw...), '\n', '\n'),
		bytes.Replace(reportRaw, []byte(`"assessment":"UNKNOWN"`), []byte(`"assessment":"SAFE"`), 1),
	} {
		if _, err := cncfknowledge.ReplayHistorical(req, bad); err == nil {
			t.Fatal("noncanonical or escalated replay accepted")
		}
	}
	wrong := req
	wrong.Selection.ExpectedTrustReceiptDigest = state.receipt2.TrustReceiptDigest
	if _, err := cncfknowledge.ReplayHistorical(wrong, append(append([]byte(nil), reportRaw...), '\n')); err == nil {
		t.Fatal("mismatched trust receipt pin accepted")
	}
	wrong = req
	wrong.SelectedRuleID = ""
	if _, err := cncfknowledge.ReplayHistorical(wrong, append(append([]byte(nil), reportRaw...), '\n')); err == nil {
		t.Fatal("changed selected rule accepted for replay")
	}
	mutated := report
	mutated.Knowledge.Revision = "2"
	if _, err := cncfknowledge.MarshalReport(mutated); err == nil {
		t.Fatal("mutated report accepted")
	}
}

func TestExternalKnowledgeRejectsInputAndPinIntegrityWithoutEcho(t *testing.T) {
	state := makeFixture(t)
	importSecond(t, &state)
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","secret":"PRIVATE-CNCF-CANARY","current":{"components":[]},"proposed":{"components":[]}}`)
	req := request(state, "2", state.manifest.Revisions[1].BundleDigest, state.receipt2.TrustReceiptDigest, input)
	req.InputDigest = digest([]byte("other"))
	if _, err := cncfknowledge.EvaluateCurrent(req); err == nil || strings.Contains(err.Error(), "PRIVATE-CNCF-CANARY") || strings.Contains(err.Error(), state.store) {
		t.Fatalf("bad input error=%v", err)
	}
	req.InputDigest = digest(input)
	req.Selection.ExpectedBundleDigest = state.manifest.Revisions[0].BundleDigest
	if _, err := cncfknowledge.EvaluateCurrent(req); err == nil {
		t.Fatal("mismatched bundle pin accepted")
	}
	if _, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: state.store}, Project: "kyverno", Input: nil}); !errors.Is(err, cncfknowledge.ErrInvalid) {
		t.Fatalf("invalid request error=%v", err)
	}
}

func TestExternalKnowledgeEmbeddedBehaviorUnchanged(t *testing.T) {
	input := []byte(kyvernoInputTrue)
	report, err := cncfcheck.Check("kyverno", input, time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC))
	if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || report.KnowledgeOrigin != "embedded" || report.SourceAuthority != "PACKAGED_MAINTAINER_REVIEWED_SOURCE_RULES_NOT_RUNTIME_PROOF" {
		t.Fatalf("embedded behavior changed: report=%+v err=%v", report, err)
	}
}
