// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestReleasePlanAssertionsUpgradeManualSelectionAndRemainIdempotent(t *testing.T) {
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
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	pkg := writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1)
	store := filepath.Join(dir, "store")
	manual := ImportRequest{
		PackagePath: pkg, StoreRoot: store, BootstrapRootPath: root,
		BootstrapRootDigest:   manifest.BootstrapRoot.Digest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
	}
	first, err := ImportConstraints(manual)
	if err != nil {
		t.Fatal(err)
	}
	if first.TrustReceipt.APIVersion != trustReceiptV1 || first.TrustReceipt.ExpectedVerificationAssertionsDigest != "" {
		t.Fatalf("manual import changed v1 receipt: %+v", first.TrustReceipt)
	}

	verified, err := VerifyConstraints(VerifyRequest{
		PackagePath: pkg, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertions := verificationAssertionsFromReceipt(verified)
	planned := manual
	planned.BootstrapRootPath = ""
	planned.BootstrapRootDigest = ""
	planned.ExpectedVerification = &assertions
	upgraded, err := ImportConstraints(planned)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.TrustReceipt.APIVersion != trustReceiptV2 || upgraded.TrustReceipt.ExpectedVerificationAssertionsDigest == "" || !upgraded.SelectionChanged || upgraded.TrustReceiptDigest == first.TrustReceiptDigest {
		t.Fatalf("manual selection was not truthfully upgraded: %+v", upgraded)
	}
	again, err := ImportConstraints(planned)
	if err != nil {
		t.Fatal(err)
	}
	if again.SelectionChanged || again.TrustReceiptDigest != upgraded.TrustReceiptDigest || again.TrustReceipt.ExpectedVerificationAssertionsDigest != upgraded.TrustReceipt.ExpectedVerificationAssertionsDigest {
		t.Fatalf("assertion-bound import was not idempotent: %+v", again)
	}

	manualAgain := planned
	manualAgain.ExpectedVerification = nil
	manualReuse, err := ImportConstraints(manualAgain)
	if err != nil {
		t.Fatal(err)
	}
	if manualReuse.SelectionChanged || manualReuse.TrustReceiptDigest != upgraded.TrustReceiptDigest {
		t.Fatalf("manual request did not reuse valid v2 selection: %+v", manualReuse)
	}
}

func TestVersionedAssertionRecordsFailClosed(t *testing.T) {
	validDigest := digestBytes([]byte("assertions"))
	pending := importPending{
		APIVersion: pendingV1, InitialRootDigest: validDigest, PackageDigest: validDigest,
		StartedAt: "2030-01-01T00:00:00Z",
	}
	pendingV1Raw, err := marshalCanonical(pending)
	if err != nil {
		t.Fatal(err)
	}
	pendingExplicitEmpty := bytes.Replace(pendingV1Raw, []byte(`,"startedAt"`), []byte(`,"expectedVerificationAssertionsDigest":"","startedAt"`), 1)
	pending.APIVersion = pendingV2
	pendingV2Missing, err := marshalCanonical(pending)
	if err != nil {
		t.Fatal(err)
	}
	pending.ExpectedVerificationAssertionsDigest = "sha256:invalid"
	pendingV2Invalid, err := marshalCanonical(pending)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"v1 explicit empty assertion": pendingExplicitEmpty,
		"v2 missing assertion":        pendingV2Missing,
		"v2 invalid assertion":        pendingV2Invalid,
	} {
		t.Run("pending "+name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			store, err := ensureStoreRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.write("import-pending.json", raw, true); err != nil {
				t.Fatal(err)
			}
			if _, err := loadImportPending(store); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("record accepted: %v", err)
			}
		})
	}

	receipt := TrustReceipt{APIVersion: trustReceiptV1}
	receiptV1Raw, err := marshalCanonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptExplicitEmpty := bytes.Replace(receiptV1Raw, []byte(`}`), []byte(`,"expectedVerificationAssertionsDigest":""}`), 1)
	var decoded TrustReceipt
	if decodeCanonicalStrict(receiptExplicitEmpty, &decoded) == nil {
		t.Fatal("v1 trust receipt with explicit assertion field was accepted")
	}
	receipt.APIVersion = trustReceiptV2
	if receiptAssertionVersion(receipt) {
		t.Fatal("v2 trust receipt without assertion digest was accepted")
	}
	receipt.ExpectedVerificationAssertionsDigest = "sha256:invalid"
	if receiptAssertionVersion(receipt) {
		t.Fatal("v2 trust receipt with invalid assertion digest was accepted")
	}
}

func TestReleasePlanRecoveryKeepsExactAssertionIdentity(t *testing.T) {
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
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	pkg := writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1)
	verified, err := VerifyConstraints(VerifyRequest{
		PackagePath: pkg, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertions := verificationAssertionsFromReceipt(verified)
	req := ImportRequest{
		PackagePath: pkg, StoreRoot: filepath.Join(dir, "store"), BootstrapRootPath: root,
		BootstrapRootDigest:   manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
		ExpectedVerification:  &assertions,
	}
	cut, err := fixedConstraintsImport(t, req, now, "selection-published")
	if !errors.Is(err, ErrRecoveryRequired) || !cut.SelectionChanged {
		t.Fatalf("selection cut receipt=%+v err=%v", cut, err)
	}
	store, err := ensureStoreRoot(req.StoreRoot)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := loadImportPending(store)
	if err != nil || pending == nil || pending.APIVersion != pendingV2 || pending.ExpectedVerificationAssertionsDigest == "" {
		store.Close()
		t.Fatalf("v2 pending identity missing: %+v err=%v", pending, err)
	}
	assertionDigest := pending.ExpectedVerificationAssertionsDigest
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	withoutAssertions := req
	withoutAssertions.ExpectedVerification = nil
	if _, err := fixedConstraintsImport(t, withoutAssertions, now, ""); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("mismatched recovery accepted: %v", err)
	}
	recovered, err := fixedConstraintsImport(t, req, now, "")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.TrustReceipt.APIVersion != trustReceiptV2 || recovered.TrustReceipt.ExpectedVerificationAssertionsDigest != assertionDigest {
		t.Fatalf("recovery lost assertions: %+v", recovered)
	}
	store, err = ensureStoreRoot(req.StoreRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if pending, err = loadImportPending(store); err != nil || pending != nil {
		t.Fatalf("completed recovery left pending=%+v err=%v", pending, err)
	}
}

func TestStoredV2ReceiptAssertionDigestBindsValidatedFields(t *testing.T) {
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
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	pkg := writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1)
	verified, err := VerifyConstraints(VerifyRequest{
		PackagePath: pkg, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertions := verificationAssertionsFromReceipt(verified)
	storeRoot := filepath.Join(dir, "store")
	if _, err := ImportConstraints(ImportRequest{
		PackagePath: pkg, StoreRoot: storeRoot, BootstrapRootPath: root,
		BootstrapRootDigest:   manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: manifest.Revisions[0].PackageDigest,
		ExpectedRevision:      manifest.Revisions[0].Revision,
		ExpectedBundleDigest:  manifest.Revisions[0].BundleDigest,
		ExpectedVerification:  &assertions,
	}); err != nil {
		t.Fatal(err)
	}

	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	selection, err := loadSelection(store)
	if err != nil {
		t.Fatal(err)
	}
	profile := constraintsProfile()
	if err := validateStoredSelection(store, selection, profile, profile.admit); err != nil {
		t.Fatalf("valid v2 stored selection rejected: %v", err)
	}
	rel := admissionRelative(selection.BundleDigest, selection.TrustReceiptDigest)
	target, err := store.read(rel+"/target.json", maxPackageEntry)
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := store.read(rel+"/trust-receipt.json", maxStateFile)
	if err != nil {
		t.Fatal(err)
	}
	var receipt TrustReceipt
	if err := decodeCanonicalStrict(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.ExpectedVerificationAssertionsDigest = digestBytes([]byte("different but syntactically valid assertion identity"))
	tamperedRaw, err := marshalCanonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	tampered := selection
	tampered.TrustReceiptDigest = digestBytes(tamperedRaw)
	if err := persistAdmission(store, admissionRelative(tampered.BundleDigest, tampered.TrustReceiptDigest), target, tamperedRaw, tampered.TrustStateDigest); err != nil {
		t.Fatal(err)
	}
	if err := validateStoredSelection(store, tampered, profile, profile.admit); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("stored v2 receipt with inconsistent assertion identity accepted: %v", err)
	}
}

func verificationAssertionsFromReceipt(receipt PackageVerificationReceipt) VerificationAssertions {
	return VerificationAssertions{
		PublisherInitialRootDigest: receipt.InitialRootDigest,
		RootHistory:                append([]RootHistoryEntry(nil), receipt.RootHistory...),
		Root:                       receipt.Root,
		Timestamp:                  receipt.Timestamp,
		Snapshot:                   receipt.Snapshot,
		Targets:                    receipt.Targets,
		TargetPath:                 receipt.TargetPath,
		Purpose:                    receipt.Purpose,
		EngineCapabilityDigest:     receipt.EngineCapabilityDigest,
	}
}
