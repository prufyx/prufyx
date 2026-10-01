// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var constraintsProcessCut = errors.New("generic constraints process cut")

type constraintsFixtureState struct {
	dir       string
	store     string
	root      string
	p1        string
	p2        string
	manifest  knowledgefixture.Manifest
	artifacts knowledgefixture.Artifacts
}

func makeConstraintsFixture(t *testing.T) constraintsFixtureState {
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
	return constraintsFixtureState{
		dir: dir, store: filepath.Join(dir, "constraints-store"),
		root:     writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root),
		p1:       writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1),
		p2:       writeConstraintsFixtureFile(t, dir, "revision-2.tar", artifacts.Revision2),
		manifest: manifest, artifacts: artifacts,
	}
}

func writeConstraintsFixtureFile(t *testing.T, dir, name string, raw []byte) string {
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

func constraintsBundleDigest(t *testing.T, packagePath string) string {
	t.Helper()
	pkg, err := readImportPackageForProfile(packagePath, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range pkg.files {
		if strings.HasPrefix(name, "targets/knowledge/") {
			return digestBytes(raw)
		}
	}
	t.Fatal("generic target missing from package")
	return ""
}

func fixedConstraintsImport(t *testing.T, req ImportRequest, at time.Time, stage string) (ImportReceipt, error) {
	t.Helper()
	p := constraintsProfile()
	var hook importTestHook
	if stage != "" {
		hook = func(got string, _ *storeFS) error {
			if got == stage {
				return constraintsProcessCut
			}
			return nil
		}
	}
	return importWithProfile(req, p, p.admit, at.UTC(), &at, hook)
}

func constraintsInitialRequest(state constraintsFixtureState) ImportRequest {
	return ImportRequest{PackagePath: state.p1, StoreRoot: state.store, BootstrapRootPath: state.root, BootstrapRootDigest: state.manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: state.manifest.Revisions[0].BundleDigest}
}

func constraintsUpgradeRequest(state constraintsFixtureState) ImportRequest {
	return ImportRequest{PackagePath: state.p2, StoreRoot: state.store, ExpectedRevision: "2", ExpectedBundleDigest: state.manifest.Revisions[1].BundleDigest}
}

func TestConstraintsInterruptedImportsRequireExactRetry(t *testing.T) {
	stages := []string{"pending-published", "floor-state-published", "trust-pointer-published", "admission-published", "selection-published"}
	for _, established := range []bool{false, true} {
		mode := "initial"
		if established {
			mode = "upgrade"
		}
		for _, stage := range stages {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				state := makeConstraintsFixture(t)
				now := time.Now().UTC().Truncate(time.Second)
				if established {
					if _, err := fixedConstraintsImport(t, constraintsInitialRequest(state), now, ""); err != nil {
						t.Fatal(err)
					}
				}
				req := constraintsInitialRequest(state)
				if established {
					req = constraintsUpgradeRequest(state)
				}
				if _, err := fixedConstraintsImport(t, req, now, stage); !errors.Is(err, constraintsProcessCut) {
					t.Fatalf("cut error=%v", err)
				}
				status, err := InspectConstraints(state.store)
				if err != nil || status.State != "RECOVERY_REQUIRED" || status.CurrentEligible {
					t.Fatalf("recovery status=%+v err=%v", status, err)
				}
				wrongPackage := req
				wrongPackage.PackagePath = state.p2
				if established {
					wrongPackage.PackagePath = state.p1
				}
				if _, err := ImportConstraints(wrongPackage); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("different package resumed transaction: %v", err)
				}
				wrongAssertions := req
				wrongAssertions.ExpectedRevision = ""
				if _, err := ImportConstraints(wrongAssertions); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("different assertions resumed transaction: %v", err)
				}
				receipt, err := ImportConstraints(req)
				if err != nil || receipt.Status != "IMPORTED" {
					t.Fatalf("exact retry receipt=%+v err=%v", receipt, err)
				}
				if _, err := os.Stat(filepath.Join(state.store, "import-pending.json")); !os.IsNotExist(err) {
					t.Fatalf("pending marker remains: %v", err)
				}
			})
		}
	}
}

func TestConstraintsSemanticRejectionRetainsTrustAndHistoricalSelection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateConstraintsSemantic(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	p1 := writeConstraintsFixtureFile(t, dir, "one.tar", artifacts.Revision1)
	p2 := writeConstraintsFixtureFile(t, dir, "bad-two.tar", artifacts.Revision2)
	first, err := fixedConstraintsImport(t, ImportRequest{PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: artifacts.RootDigest, ExpectedRevision: "1", ExpectedBundleDigest: artifacts.Revision1Digest}, now, "")
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := ImportConstraints(ImportRequest{PackagePath: p2, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: artifacts.Revision2Digest})
	if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || !rejected.TrustStateAdvanced || rejected.SelectionChanged {
		t.Fatalf("semantic rejection receipt=%+v err=%v", rejected, err)
	}
	status, err := InspectConstraints(store)
	if err != nil || status.State != "TRUST_ADVANCED" || status.SelectedRevision != "1" || status.CurrentEligible {
		t.Fatalf("post-rejection status=%+v err=%v", status, err)
	}
	if _, err := OpenSelectedConstraints(SelectionRequest{StoreRoot: store}); !errors.Is(err, ErrTrustAdvanced) {
		t.Fatalf("current selection was usable after trust advance: %v", err)
	}
	verifiedAt, err := time.Parse(time.RFC3339, first.TrustReceipt.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := OpenHistoricalConstraints(SelectionRequest{StoreRoot: store, ExpectedRevision: "1", ExpectedBundleDigest: artifacts.Revision1Digest, ExpectedTrustReceiptDigest: first.TrustReceiptDigest}, verifiedAt)
	if err != nil || !historical.Valid() || historical.Mode() != SelectionHistorical {
		t.Fatalf("historical selection unavailable: %+v err=%v", historical, err)
	}
}

func TestConstraintsRollbackClockFloorAndSameRevisionConflict(t *testing.T) {
	state := makeConstraintsFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := fixedConstraintsImport(t, constraintsInitialRequest(state), now, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fixedConstraintsImport(t, constraintsUpgradeRequest(state), now.Add(-time.Second), ""); !errors.Is(err, ErrRollback) {
		t.Fatalf("clock-floor rollback accepted: %v", err)
	}
	if _, err := ImportConstraints(constraintsUpgradeRequest(state)); err != nil {
		t.Fatal(err)
	}
	oldRequest := constraintsInitialRequest(state)
	oldRequest.BootstrapRootPath = ""
	oldRequest.BootstrapRootDigest = ""
	if _, err := ImportConstraints(oldRequest); !errors.Is(err, ErrRollback) {
		t.Fatalf("old revision accepted: %v", err)
	}

	store, err := ensureStoreRoot(state.store)
	if err != nil {
		t.Fatal(err)
	}
	before, err := loadCurrentTrustForProfile(store, constraintsProfile())
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := readImportPackageForProfile(state.p2, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := metadata.Timestamp().FromBytes(pkg.files["metadata/timestamp.json"])
	if err != nil || len(timestamp.Signatures) == 0 {
		t.Fatalf("timestamp fixture: %v", err)
	}
	timestamp.Signatures[0].Signature[0] ^= 0xff
	timestamp.Signed.Expires = timestamp.Signed.Expires.Add(time.Second)
	mutatedTimestamp, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	pkg.files["metadata/timestamp.json"] = mutatedTimestamp
	candidate := writeConstraintsFixtureFile(t, state.dir, "same-version-different.tar", canonicalPackageBytes(t, pkg.files))
	rejected, err := ImportConstraints(ImportRequest{PackagePath: candidate, StoreRoot: state.store})
	if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || rejected.TrustStateAdvanced {
		t.Fatalf("same-version conflict receipt=%+v err=%v", rejected, err)
	}
	store, err = ensureStoreRoot(state.store)
	if err != nil {
		t.Fatal(err)
	}
	after, err := loadCurrentTrustForProfile(store, constraintsProfile())
	store.Close()
	if err != nil || after.stateDigest != before.stateDigest || !bytes.Equal(after.timestamp, before.timestamp) {
		t.Fatalf("same-version conflict changed trust err=%v", err)
	}
}

func TestConstraintsFreshTUFRejectsSemanticConflictAndRollback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateConstraintsSemantic(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	p1 := writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1)
	p2 := writeConstraintsFixtureFile(t, dir, "revision-2.tar", artifacts.ValidRevision2)
	if _, err := fixedConstraintsImport(t, ImportRequest{
		PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: artifacts.RootDigest,
		ExpectedRevision: "1", ExpectedBundleDigest: artifacts.Revision1Digest,
	}, now, ""); err != nil {
		t.Fatal(err)
	}
	selected, err := fixedConstraintsImport(t, ImportRequest{
		PackagePath: p2, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: artifacts.ValidRevision2Digest,
	}, now, "")
	if err != nil {
		t.Fatal(err)
	}
	p3 := writeConstraintsFixtureFile(t, dir, "revision-3-semantic-conflict.tar", artifacts.Revision3)
	p4 := writeConstraintsFixtureFile(t, dir, "revision-4-semantic-rollback.tar", artifacts.Revision4)

	conflict, err := ImportConstraints(ImportRequest{
		PackagePath: p3, StoreRoot: store, ExpectedRevision: "2",
		ExpectedBundleDigest: constraintsBundleDigest(t, p3),
	})
	if !errors.Is(err, ErrRollback) || conflict.Status != "REJECTED" || !conflict.TrustStateAdvanced || conflict.SelectionChanged {
		t.Fatalf("fresh TUF same-revision conflict receipt=%+v err=%v", conflict, err)
	}
	status, err := InspectConstraints(store)
	if err != nil || status.State != "TRUST_ADVANCED" || status.SelectedRevision != "2" || status.CurrentEligible {
		t.Fatalf("selection changed after same-revision conflict: %+v err=%v", status, err)
	}

	rollback, err := ImportConstraints(ImportRequest{
		PackagePath: p4, StoreRoot: store, ExpectedRevision: "1",
		ExpectedBundleDigest: constraintsBundleDigest(t, p4),
	})
	if !errors.Is(err, ErrRollback) || rollback.Status != "REJECTED" || !rollback.TrustStateAdvanced || rollback.SelectionChanged {
		t.Fatalf("fresh TUF semantic rollback receipt=%+v err=%v", rollback, err)
	}
	status, err = InspectConstraints(store)
	if err != nil || status.State != "TRUST_ADVANCED" || status.SelectedRevision != "2" || status.CurrentEligible {
		t.Fatalf("selection changed after semantic rollback: %+v err=%v", status, err)
	}
	if selected.TrustReceiptDigest == "" {
		t.Fatal("selected revision did not provide historical receipt pin")
	}
}

func TestConstraintsRootRotationRecoveryKeepsGenericProfileBound(t *testing.T) {
	state := makeConstraintsFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := fixedConstraintsImport(t, constraintsInitialRequest(state), now, ""); err != nil {
		t.Fatal(err)
	}
	failurePath := writeConstraintsFixtureFile(t, state.dir, "root-2-refresh-failure.tar", state.artifacts.RootV2RefreshFailure)
	continuationPath := writeConstraintsFixtureFile(t, state.dir, "root-2-continuation.tar", state.artifacts.RootV2Continuation)
	failure := ImportRequest{PackagePath: failurePath, StoreRoot: state.store}
	continuation := ImportRequest{PackagePath: continuationPath, StoreRoot: state.store}
	if _, err := fixedConstraintsImport(t, failure, now, "refresh-returned"); !errors.Is(err, constraintsProcessCut) {
		t.Fatalf("root rotation cut error=%v", err)
	}
	if _, err := ImportConstraints(continuation); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("different root-rotation package resumed transaction: %v", err)
	}
	rejected, err := ImportConstraints(failure)
	if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || !rejected.TrustStateAdvanced || rejected.SelectionChanged {
		t.Fatalf("root rotation rejection receipt=%+v err=%v", rejected, err)
	}
	status, err := InspectConstraints(state.store)
	if err != nil || status.RootVersion != 2 || status.State != "TRUST_ADVANCED" || status.CurrentEligible {
		t.Fatalf("root rotation trust status=%+v err=%v", status, err)
	}
	if _, err := ImportConstraints(continuation); err != nil {
		t.Fatalf("root rotation continuation: %v", err)
	}
	status, err = InspectConstraints(state.store)
	if err != nil || status.RootVersion != 2 || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != "3" {
		t.Fatalf("root rotation final status=%+v err=%v", status, err)
	}
}

func TestConstraintsCurrentOpenRejectsExpiredTUFMetadata(t *testing.T) {
	generatedAt := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateConstraints(generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root)
	packagePath := writeConstraintsFixtureFile(t, dir, "revision-1.tar", artifacts.Revision1)
	req := ImportRequest{PackagePath: packagePath, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}
	if _, err := fixedConstraintsImport(t, req, generatedAt, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSelectedConstraints(SelectionRequest{StoreRoot: store}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired current metadata accepted: %v", err)
	}
}

func TestConstraintsProfileMixingAndMarkerDeletionFailClosed(t *testing.T) {
	state := makeConstraintsFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := fixedConstraintsImport(t, constraintsInitialRequest(state), now, ""); err != nil {
		t.Fatal(err)
	}
	marker, err := markerBytes(constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state.store, "profile.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectConstraints(state.store); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("deleted generic marker accepted: %v", err)
	}
	if _, err := ImportConstraints(constraintsUpgradeRequest(state)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("deleted generic marker accepted by import: %v", err)
	}
	if err := os.WriteFile(filepath.Join(state.store, "profile.json"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ImportRequest{PackagePath: state.p1, StoreRoot: state.store}, func([]byte) (Admission, error) { return Admission{}, nil }); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("cert route accepted generic marker: %v", err)
	}
	status, err := InspectConstraints(state.store)
	if err != nil || status.SelectedRevision != "1" || status.State != "READY" {
		t.Fatalf("marker restoration changed generic selection: %+v err=%v", status, err)
	}
}
