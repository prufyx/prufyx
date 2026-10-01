// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestValidateImportAssertionsDoesNotTouchStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, artifacts.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	rootDigest := digestBytes(artifacts.Root)
	cases := []ImportRequest{
		{ExpectedRevision: "01"},
		{ExpectedBundleDigest: "sha256:not-a-digest"},
		{BootstrapRootPath: rootPath},
		{BootstrapRootDigest: rootDigest},
		{BootstrapRootPath: rootPath, BootstrapRootDigest: digestBytes([]byte("wrong root"))},
	}
	for i, req := range cases {
		if err := ValidateImportAssertions(req); err == nil {
			t.Errorf("case %d unexpectedly accepted", i)
		}
	}
}

func TestPinnedDigestRejectsBeforeStoreCreation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	packagePath := filepath.Join(dir, "revision.tar")
	if err := os.WriteFile(packagePath, artifacts.Revision1, 0o600); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, artifacts.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []ImportRequest{
		{ExpectedPackageDigest: digestBytes(artifacts.Revision2)},
		{ExpectedPackageDigest: "sha256:not-a-digest"},
		{ExpectedPackageDigest: digestBytes(artifacts.Revision1), ExpectedRevision: "01"},
		{ExpectedPackageDigest: digestBytes(artifacts.Revision1), BootstrapRootPath: rootPath},
		{ExpectedPackageDigest: digestBytes(artifacts.Revision1), BootstrapRootPath: rootPath, BootstrapRootDigest: digestBytes([]byte("wrong root"))},
	}
	for i, base := range cases {
		base.PackagePath = packagePath
		base.StoreRoot = filepath.Join(dir, fmt.Sprintf("store-%d", i))
		if err := os.Mkdir(base.StoreRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err = Import(base, journalAdmission)
		if err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
		info, statErr := os.Stat(base.StoreRoot)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("case %d store disappeared after preflight rejection: %v", i, statErr)
		}
		entries, readErr := os.ReadDir(base.StoreRoot)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("case %d store was mutated on preflight rejection: read=%v entries=%v", i, readErr, entries)
		}
	}
}

func TestPinnedPackageRemainsInMemoryAfterPathReplacement(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	packagePath := filepath.Join(dir, "revision.tar")
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(packagePath, artifacts.Revision1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, artifacts.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := readImportPackageForProfile(packagePath, certManagerProfile())
	if err != nil {
		t.Fatal(err)
	}
	var originalTargetDigest string
	for name, raw := range original.files {
		if strings.HasPrefix(name, "targets/knowledge/") {
			originalTargetDigest = digestBytes(raw)
			break
		}
	}
	if originalTargetDigest == "" {
		t.Fatal("original target missing")
	}
	storeRoot := filepath.Join(dir, "store")
	replaced := false
	hook := func(stage string, _ *storeFS) error {
		if stage == "pending-published" && !replaced {
			replaced = true
			return os.WriteFile(packagePath, artifacts.Revision2, 0o600)
		}
		return nil
	}
	receipt, err := importWithRefTime(ImportRequest{
		PackagePath: packagePath, StoreRoot: storeRoot,
		BootstrapRootPath: rootPath, BootstrapRootDigest: digestBytes(artifacts.Root),
		ExpectedPackageDigest: digestBytes(artifacts.Revision1),
	}, journalAdmission, now, &now, hook)
	if err != nil || receipt.Status != "IMPORTED" || receipt.TrustReceipt.KnowledgeRevision != "1" || receipt.TrustReceipt.TargetDigest != originalTargetDigest || !replaced {
		t.Fatalf("pinned import receipt=%#v err=%v replaced=%v", receipt, err, replaced)
	}
}
