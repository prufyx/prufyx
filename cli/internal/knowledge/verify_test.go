// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestVerifyConstraintsUsesExplicitBootstrapWithoutStore(t *testing.T) {
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
	pkg := writeConstraintsFixtureFile(t, dir, "package.tar", artifacts.Revision2)
	sentinel := filepath.Join(dir, "caller-store")
	if err := os.Mkdir(sentinel, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = writeConstraintsFixtureFile(t, sentinel, "sentinel", []byte("unchanged\n"))
	temp := filepath.Join(dir, "verifier-temp")
	if err := os.Mkdir(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", temp)
	before := snapshotVerifyTree(t, dir)
	req := VerifyRequest{
		PackagePath: pkg, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedPackageDigest: digestBytes(artifacts.Revision2), ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest,
	}
	first, err := VerifyConstraints(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyConstraints(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "VERIFIED" || first.Profile != "cncf" || first.TrustSource != "OPERATOR_PROVISIONED" || first.Purpose != "synthetic_test_only" || first.KnowledgeRevision != "2" || first.PackageDigest != req.ExpectedPackageDigest || first.TargetDigest != req.ExpectedBundleDigest || first.TargetPath != ConstraintsTargetPath || first.TargetLength < 1 || first.NetworkUsed || first.StoreUsed || first.StoreChanged || first.RollbackAgainstStoreChecked || first.ImportEligibility != "NOT_EVALUATED" {
		t.Fatalf("verification receipt=%+v", first)
	}
	first.VerifiedAt = ""
	second.VerifiedAt = ""
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("stable identities differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if after := snapshotVerifyTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("caller input/store tree changed:\nbefore=%v\nafter=%v", before, after)
	}
}

type verifyTreeEntry struct {
	Mode   os.FileMode
	Size   int64
	Digest [sha256.Size]byte
}

func snapshotVerifyTree(t *testing.T, root string) map[string]verifyTreeEntry {
	t.Helper()
	result := map[string]verifyTreeEntry{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := verifyTreeEntry{Mode: info.Mode(), Size: info.Size()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.Digest = sha256.Sum256(raw)
		}
		result[rel] = item
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestVerifyConstraintsRejectsInvalidInputsWithoutCreatingStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid, err := knowledgefixture.GenerateConstraints(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(valid.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := writeConstraintsFixtureFile(t, dir, "root.json", valid.Root)
	pkg := writeConstraintsFixtureFile(t, dir, "package.tar", valid.Revision1)
	base := VerifyRequest{PackagePath: pkg, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest}
	cases := []struct {
		name string
		edit func(*VerifyRequest)
		want error
	}{
		{"root required", func(r *VerifyRequest) { r.BootstrapRootPath = ""; r.BootstrapRootDigest = "" }, ErrInvalid},
		{"root digest mismatch", func(r *VerifyRequest) { r.BootstrapRootDigest = digestBytes([]byte("wrong")) }, ErrIntegrity},
		{"package digest mismatch", func(r *VerifyRequest) { r.ExpectedPackageDigest = digestBytes([]byte("wrong")) }, ErrIntegrity},
		{"bundle digest mismatch", func(r *VerifyRequest) { r.ExpectedBundleDigest = digestBytes([]byte("wrong")) }, ErrIntegrity},
		{"revision mismatch", func(r *VerifyRequest) { r.ExpectedRevision = "2" }, ErrIntegrity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.edit(&req)
			if _, err := VerifyConstraints(req); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
	trailing := writeConstraintsFixtureFile(t, dir, "trailing.tar", append(append([]byte(nil), valid.Revision1...), 'x'))
	bad := base
	bad.PackagePath = trailing
	if _, err := VerifyConstraints(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing package error=%v", err)
	}
	semantic, err := knowledgefixture.GenerateConstraintsSemantic(now)
	if err != nil {
		t.Fatal(err)
	}
	bad.BootstrapRootPath = writeConstraintsFixtureFile(t, dir, "semantic-root.json", semantic.Root)
	bad.BootstrapRootDigest = semantic.RootDigest
	bad.PackagePath = writeConstraintsFixtureFile(t, dir, "semantic.tar", semantic.Revision2)
	if _, err := VerifyConstraints(bad); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("semantic package error=%v", err)
	}
	expired, err := knowledgefixture.GenerateConstraints(now.Add(-25 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var expiredManifest knowledgefixture.Manifest
	if err := json.Unmarshal(expired.Manifest, &expiredManifest); err != nil {
		t.Fatal(err)
	}
	bad = VerifyRequest{
		PackagePath:         writeConstraintsFixtureFile(t, dir, "expired.tar", expired.Revision1),
		BootstrapRootPath:   writeConstraintsFixtureFile(t, dir, "expired-root.json", expired.Root),
		BootstrapRootDigest: expiredManifest.BootstrapRoot.Digest,
	}
	if _, err := VerifyConstraints(bad); !errors.Is(err, ErrExpired) && !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expired package error=%v", err)
	}
}

func TestVerifyConstraintsAuthenticatesRootRotationFromBootstrap(t *testing.T) {
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	failure := writeConstraintsFixtureFile(t, dir, "failure.tar", artifacts.RootV2RefreshFailure)
	continuation := writeConstraintsFixtureFile(t, dir, "continuation.tar", artifacts.RootV2Continuation)
	failurePkg, err := readImportPackageForProfile(failure, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	continuationPkg, err := readImportPackageForProfile(continuation, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	continuationPkg.files["metadata/2.root.json"] = failurePkg.files["metadata/2.root.json"]
	rotated := writeConstraintsFixtureFile(t, dir, "rotated.tar", canonicalPackageBytes(t, continuationPkg.files))
	receipt, err := VerifyConstraints(VerifyRequest{
		PackagePath:         rotated,
		BootstrapRootPath:   writeConstraintsFixtureFile(t, dir, "root.json", artifacts.Root),
		BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedRevision:    "3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Root.Version != 2 || len(receipt.RootHistory) != 2 || receipt.RootHistory[0].Version != 1 || receipt.RootHistory[1].Version != 2 {
		t.Fatalf("root rotation receipt=%+v", receipt)
	}
}
