// SPDX-License-Identifier: AGPL-3.0-only

package knowledge_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgecheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestSignedImportCurrentHistoricalIdempotentAndTrustAdvance(t *testing.T) {
	now := time.Now().UTC()
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = decodeManifest(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := write(t, dir, "root.json", artifacts.Root)
	p1 := write(t, dir, "one.tar", artifacts.Revision1)
	p2 := write(t, dir, "two.tar", artifacts.Revision2)
	r1, err := knowledge.Import(knowledge.ImportRequest{PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := knowledge.OpenSelected(knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: r1.TrustReceiptDigest}, knowledgecheck.AdmitBundle)
	if err != nil || !v1.Valid() {
		t.Fatalf("open one: %v", err)
	}
	reject := func(raw []byte) (knowledge.Admission, error) {
		if bytes.Contains(raw, []byte(`"revision":"2"`)) {
			return knowledge.Admission{}, knowledge.ErrInvalid
		}
		return knowledgecheck.AdmitBundle(raw)
	}
	rejected, err := knowledge.Import(knowledge.ImportRequest{PackagePath: p2, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest}, reject)
	if !errors.Is(err, knowledge.ErrInvalid) || rejected.Status != "REJECTED" || !rejected.TrustStateAdvanced {
		t.Fatalf("rejected receipt=%#v err=%v", rejected, err)
	}
	if _, err = knowledge.OpenSelected(knowledge.SelectionRequest{StoreRoot: store}, knowledgecheck.AdmitBundle); !errors.Is(err, knowledge.ErrTrustAdvanced) {
		t.Fatalf("stale current selection accepted: %v", err)
	}
	historical, err := knowledge.OpenHistorical(knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: r1.TrustReceiptDigest}, v1.VerifiedAt(), knowledgecheck.AdmitBundle)
	if err != nil || !historical.Valid() || historical.Mode() != knowledge.SelectionHistorical {
		t.Fatalf("historical: %v", err)
	}
	importedAt, err := time.Parse(time.RFC3339, r1.TrustReceipt.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = knowledge.OpenHistorical(knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: r1.TrustReceiptDigest}, importedAt.Add(-time.Second), knowledgecheck.AdmitBundle); !errors.Is(err, knowledge.ErrRollback) {
		t.Fatalf("historical evaluation before admission accepted: %v", err)
	}
	if _, err = knowledge.OpenHistorical(knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: r1.TrustReceiptDigest}, time.Now().UTC().Add(time.Hour), knowledgecheck.AdmitBundle); !errors.Is(err, knowledge.ErrInvalid) {
		t.Fatalf("future historical evaluation accepted: %v", err)
	}
	r2, err := knowledge.Import(knowledge.ImportRequest{PackagePath: p2, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	r2again, err := knowledge.Import(knowledge.ImportRequest{PackagePath: p2, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest}, knowledgecheck.AdmitBundle)
	if err != nil || r2again.TrustReceiptDigest != r2.TrustReceiptDigest || r2again.SelectionChanged {
		t.Fatalf("idempotent import: %v", err)
	}
	status, err := knowledge.Inspect(store)
	if err != nil || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != "2" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if r2.TrustReceipt.Purpose != "synthetic_test_only" || r2.TrustReceipt.HasRule != true {
		t.Fatalf("receipt=%#v", r2.TrustReceipt)
	}
	if _, err = knowledge.Import(knowledge.ImportRequest{PackagePath: p1, StoreRoot: store}, knowledgecheck.AdmitBundle); !errors.Is(err, knowledge.ErrRollback) {
		t.Fatalf("old timestamp accepted: %v", err)
	}
	after, err := knowledge.Inspect(store)
	if err != nil {
		t.Fatal(err)
	}
	if after.TimestampVersion != 2 || after.SnapshotVersion != 2 || after.TargetsVersion != 2 {
		t.Fatalf("rollback lost role floors: %#v", after)
	}
}

func TestInspectUninitializedIsBoundedStatus(t *testing.T) {
	store := filepath.Join(t.TempDir(), "new-store")
	status, err := knowledge.Inspect(store)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "NO_SELECTION" || status.CurrentEligible || status.TrustSource != "none" {
		t.Fatalf("status=%#v", status)
	}
}

func TestRetryRecoversAfterFloorPublicationBeforeSelection(t *testing.T) {
	now := time.Now().UTC()
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var m knowledgefixture.Manifest
	if err = decodeManifest(a.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	_, err = knowledge.Import(knowledge.ImportRequest{PackagePath: write(t, dir, "one.tar", a.Revision1), StoreRoot: store, BootstrapRootPath: write(t, dir, "root.json", a.Root), BootstrapRootDigest: m.BootstrapRoot.Digest}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(store, "admissions", strings.TrimPrefix(m.Revisions[1].BundleDigest, "sha256:"))
	if err = os.Symlink(dir, bundleDir); err != nil {
		t.Fatal(err)
	}
	req := knowledge.ImportRequest{PackagePath: write(t, dir, "two.tar", a.Revision2), StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: m.Revisions[1].BundleDigest}
	if _, err = knowledge.Import(req, knowledgecheck.AdmitBundle); err == nil {
		t.Fatal("publication fault did not fail")
	}
	if err = os.Remove(bundleDir); err != nil {
		t.Fatal(err)
	}
	receipt, err := knowledge.Import(req, knowledgecheck.AdmitBundle)
	if err != nil || receipt.Status != "IMPORTED" {
		t.Fatalf("retry=%#v err=%v", receipt, err)
	}
	status, err := knowledge.Inspect(store)
	if err != nil || status.State != "READY" || status.SelectedRevision != "2" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestPartialTUFProgressPreservesAcceptedRoleFloors(t *testing.T) {
	now := time.Now().UTC()
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var m knowledgefixture.Manifest
	if err = decodeManifest(a.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	_, err = knowledge.Import(knowledge.ImportRequest{PackagePath: write(t, dir, "one.tar", a.Revision1), StoreRoot: store, BootstrapRootPath: write(t, dir, "root.json", a.Root), BootstrapRootDigest: m.BootstrapRoot.Digest}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	_, err = knowledge.Import(knowledge.ImportRequest{PackagePath: write(t, dir, "two.tar", a.Revision2), StoreRoot: store}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := knowledge.Import(knowledge.ImportRequest{PackagePath: write(t, dir, "rollback.tar", a.AdversarialTargetsRollback), StoreRoot: store}, knowledgecheck.AdmitBundle)
	if !errors.Is(err, knowledge.ErrRollback) || !rejected.TrustStateAdvanced {
		t.Fatalf("receipt=%#v err=%v", rejected, err)
	}
	status, err := knowledge.Inspect(store)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "TRUST_ADVANCED" || status.TimestampVersion != 3 || status.SnapshotVersion != 2 || status.TargetsVersion != 2 {
		t.Fatalf("partial floors=%#v", status)
	}
}

func TestInspectRejectsDeletedClockAndCorruptAdmission(t *testing.T) {
	now := time.Now().UTC()
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var m knowledgefixture.Manifest
	if err = decodeManifest(a.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	receipt, err := knowledge.Import(knowledge.ImportRequest{PackagePath: write(t, dir, "one.tar", a.Revision1), StoreRoot: store, BootstrapRootPath: write(t, dir, "root.json", a.Root), BootstrapRootDigest: m.BootstrapRoot.Digest}, knowledgecheck.AdmitBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(store, "clock-floor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = knowledge.Inspect(store); !errors.Is(err, knowledge.ErrIntegrity) {
		t.Fatalf("deleted clock accepted: %v", err)
	}
	// Restore by copying the immutable import verification time in canonical form.
	clock := []byte(`{"apiVersion":"prufyx.io/knowledge-clock-floor/v1","checkedAt":"` + receipt.TrustReceipt.VerifiedAt + `"}` + "\n")
	if err = os.WriteFile(filepath.Join(store, "clock-floor.json"), clock, 0o600); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(store, "admissions", strings.TrimPrefix(receipt.TrustReceipt.TargetDigest, "sha256:"), strings.TrimPrefix(receipt.TrustReceiptDigest, "sha256:"), "target.json")
	if err = os.WriteFile(rel, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := knowledge.Inspect(store)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "INTEGRITY_FAILURE" || status.CurrentEligible {
		t.Fatalf("corruption hidden: %#v", status)
	}
}

func write(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
func decodeManifest(raw []byte, out any) error { return json.Unmarshal(raw, out) }
