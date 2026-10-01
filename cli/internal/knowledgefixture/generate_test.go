// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgecheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestSyntheticPackagesDriveEmptyThenActiveKnowledge(t *testing.T) {
	artifacts, err := knowledgefixture.Generate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.PrivateKeysPersisted || manifest.Purpose != "synthetic_test_only" || len(manifest.Revisions) != 2 {
		t.Fatalf("manifest=%#v", manifest)
	}
	for _, raw := range [][]byte{artifacts.Root, artifacts.Revision1, artifacts.Revision2, artifacts.Manifest, artifacts.AdversarialTargetsRollback, artifacts.RootV2RefreshFailure, artifacts.RootV2Continuation} {
		if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte(`"privateKey":`)) {
			t.Fatal("fixture persisted private key material")
		}
	}

	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeFixture(t, dir, knowledgefixture.RootName, artifacts.Root, 0o600)
	package1 := writeFixture(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1, 0o600)
	package2 := writeFixture(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2, 0o600)
	valuesRaw := []byte(`{"syntheticCanary":"` + knowledgefixture.SyntheticCanary() + `","prometheus":{"servicemonitor":{"path":"` + knowledgefixture.SyntheticCanary() + `"}}}`)
	valuesPath := writeFixture(t, dir, "values.json", valuesRaw, 0o600)

	receipt1, err := knowledge.Import(knowledge.ImportRequest{
		PackagePath: package1, StoreRoot: store, BootstrapRootPath: rootPath,
		BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1",
		ExpectedBundleDigest: manifest.Revisions[0].BundleDigest,
	}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	request1 := knowledgecheck.Request{
		Selection:  knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: receipt1.TrustReceiptDigest},
		ValuesPath: valuesPath, From: certmanagervalues.CurrentVersion, To: certmanagervalues.TargetVersion,
	}
	report1, err := knowledgecheck.EvaluateCurrent(request1)
	if err != nil {
		t.Fatal(err)
	}
	if knowledgecheck.ClaimStatus(report1) != "UNKNOWN" {
		t.Fatalf("revision 1 claim=%s", knowledgecheck.ClaimStatus(report1))
	}
	report1Raw, err := knowledgecheck.MarshalReport(report1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(report1Raw, []byte(knowledgefixture.SyntheticCanary())) {
		t.Fatal("private values canary crossed the report boundary")
	}

	receipt2, err := knowledge.Import(knowledge.ImportRequest{
		PackagePath: package2, StoreRoot: store, ExpectedRevision: "2",
		ExpectedBundleDigest: manifest.Revisions[1].BundleDigest,
	}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	request2 := knowledgecheck.Request{
		Selection:  knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest, ExpectedTrustReceiptDigest: receipt2.TrustReceiptDigest},
		ValuesPath: valuesPath, From: certmanagervalues.CurrentVersion, To: certmanagervalues.TargetVersion,
	}
	report2, err := knowledgecheck.EvaluateCurrent(request2)
	if err != nil {
		t.Fatal(err)
	}
	if knowledgecheck.ClaimStatus(report2) != "BLOCKED" {
		t.Fatalf("revision 2 claim=%s", knowledgecheck.ClaimStatus(report2))
	}

	historical, err := knowledgecheck.ReplayHistorical(request1, report1Raw)
	if err != nil {
		t.Fatal(err)
	}
	historicalRaw, err := knowledgecheck.MarshalHistoricalReplay(historical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(historicalRaw, report1Raw) || bytes.Contains(historicalRaw, []byte(knowledgefixture.SyntheticCanary())) {
		t.Fatal("historical wrapper did not retain the exact safe report")
	}

	status, err := knowledge.Inspect(store)
	if err != nil {
		t.Fatal(err)
	}
	if !status.CurrentEligible || status.State != "READY" || status.SelectedRevision != "2" || status.Purpose != "synthetic_test_only" {
		t.Fatalf("status=%#v", status)
	}
}

func TestSyntheticRootRotationFailureRetainsProgressAndContinues(t *testing.T) {
	artifacts, err := knowledgefixture.Generate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = knowledge.Import(knowledge.ImportRequest{
		PackagePath: writeFixture(t, dir, "revision-1.tar", artifacts.Revision1, 0o600), StoreRoot: store,
		BootstrapRootPath: writeFixture(t, dir, "root.json", artifacts.Root, 0o600), BootstrapRootDigest: manifest.BootstrapRoot.Digest,
	}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := knowledge.Import(knowledge.ImportRequest{
		PackagePath: writeFixture(t, dir, "root-v2-refresh-failure.tar", artifacts.RootV2RefreshFailure, 0o600), StoreRoot: store,
	}, knowledgecheck.AdmitBundle)
	if err == nil || !rejected.TrustStateAdvanced || rejected.SelectionChanged {
		t.Fatalf("root rotation failure receipt=%#v err=%v", rejected, err)
	}
	status, err := knowledge.Inspect(store)
	if err != nil || status.State != "TRUST_ADVANCED" || status.RootVersion != 2 || status.CurrentEligible {
		t.Fatalf("retained root-v2 status=%#v err=%v", status, err)
	}
	receipt, err := knowledge.Import(knowledge.ImportRequest{
		PackagePath: writeFixture(t, dir, "root-v2-continuation.tar", artifacts.RootV2Continuation, 0o600), StoreRoot: store,
	}, knowledgecheck.AdmitBundle)
	if err != nil || receipt.Status != "IMPORTED" || receipt.TrustReceipt.KnowledgeRevision != "3" {
		t.Fatalf("root-v2 continuation receipt=%#v err=%v", receipt, err)
	}
	status, err = knowledge.Inspect(store)
	if err != nil || status.State != "READY" || status.RootVersion != 2 || status.SelectedRevision != "3" || !status.CurrentEligible {
		t.Fatalf("continued root-v2 status=%#v err=%v", status, err)
	}
}

func writeFixture(t *testing.T, dir, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
