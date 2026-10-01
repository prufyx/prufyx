// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

func TestSIGKILLInsideRefreshReplaysAcceptedRootRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(a.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	storeRoot := filepath.Join(dir, "store")
	root := writeJournalFile(t, dir, "root.json", a.Root)
	if _, err = Import(ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-1.tar", a.Revision1), StoreRoot: storeRoot, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest}, journalAdmission); err != nil {
		t.Fatal(err)
	}
	failure := ImportRequest{PackagePath: writeJournalFile(t, dir, "root2-failure.tar", a.RootV2RefreshFailure), StoreRoot: storeRoot}
	continuation := ImportRequest{PackagePath: writeJournalFile(t, dir, "root2-continuation.tar", a.RootV2Continuation), StoreRoot: storeRoot}
	killImportProcess(t, failure, "refresh-timestamp-fetch", filepath.Join(dir, "ready-root2"))
	if _, err = Import(continuation, journalAdmission); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("different package discarded interrupted root progress: %v", err)
	}
	rejected, err := Import(failure, journalAdmission)
	if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || !rejected.TrustStateAdvanced {
		t.Fatalf("root refresh receipt=%#v err=%v", rejected, err)
	}
	status, err := Inspect(storeRoot)
	if err != nil || status.RootVersion != 2 || status.State != "TRUST_ADVANCED" || status.CurrentEligible {
		t.Fatalf("root2 status=%#v err=%v", status, err)
	}
	if _, err = Import(continuation, journalAdmission); err != nil {
		t.Fatalf("root2 continuation: %v", err)
	}
	status, err = Inspect(storeRoot)
	if err != nil || status.RootVersion != 2 || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != "3" {
		t.Fatalf("continued status=%#v err=%v", status, err)
	}
}

func TestStoredRootChainRejectsLatestSelfSignedRootWithoutPinnedRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(a.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	storeRoot := filepath.Join(dir, "store")
	root := writeJournalFile(t, dir, "root.json", a.Root)
	if _, err = Import(ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-1.tar", a.Revision1), StoreRoot: storeRoot, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest}, journalAdmission); err != nil {
		t.Fatal(err)
	}
	if _, err = Import(ImportRequest{PackagePath: writeJournalFile(t, dir, "root2-failure.tar", a.RootV2RefreshFailure), StoreRoot: storeRoot}, journalAdmission); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("root2 failure package: %v", err)
	}
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	material, err := loadCurrentTrust(store)
	if err != nil || material.state.Root.Version != 2 {
		t.Fatalf("load root2: %v", err)
	}
	root1, err := metadata.Root().FromBytes(material.rootHistory[1])
	if err != nil {
		t.Fatal(err)
	}
	root2, err := metadata.Root().FromBytes(material.rootHistory[2])
	if err != nil {
		t.Fatal(err)
	}
	oldIDs := map[string]bool{}
	for _, id := range root1.Signed.Roles[metadata.ROOT].KeyIDs {
		oldIDs[id] = true
	}
	var retained []metadata.Signature
	for _, signature := range root2.Signatures {
		if !oldIDs[signature.KeyID] {
			retained = append(retained, signature)
		}
	}
	if len(retained) == 0 || len(retained) == len(root2.Signatures) {
		t.Fatal("fixture did not contain distinct old-root and self signatures")
	}
	root2.Signatures = retained
	tamperedRoot, err := root2.ToBytes(false)
	if err != nil || validateTUFJSON(tamperedRoot) != nil {
		t.Fatalf("tampered root shape: %v", err)
	}
	if _, err = trustedmetadata.New(tamperedRoot); err != nil {
		t.Fatalf("latest root is not independently self-trusted: %v", err)
	}
	tampered := *material
	tampered.rootHistory = make(map[int64][]byte, len(material.rootHistory))
	for version, raw := range material.rootHistory {
		tampered.rootHistory[version] = append([]byte(nil), raw...)
	}
	tampered.rootHistory[2] = tamperedRoot
	tampered.root = tamperedRoot
	tampered.state.RootHistory = append([]RootHistoryEntry(nil), material.state.RootHistory...)
	newRootDigest := digestBytes(tamperedRoot)
	tampered.state.RootHistory[len(tampered.state.RootHistory)-1].Digest = newRootDigest
	tampered.state.Root.Digest = newRootDigest
	stateRaw, err := marshalCanonical(tampered.state)
	if err != nil {
		t.Fatal(err)
	}
	tampered.stateDigest = digestBytes(stateRaw)
	writeUncheckedTrustMaterial(t, store, &tampered, stateRaw)
	if _, err = loadCurrentTrust(store); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("self-trusted root bypassed pinned rotation chain: %v", err)
	}
}

func TestRejectedRawDifferentSameVersionRetainsExactAcceptedTimestamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(a.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	storeRoot := filepath.Join(dir, "store")
	root := writeJournalFile(t, dir, "root.json", a.Root)
	if _, err = Import(ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-1.tar", a.Revision1), StoreRoot: storeRoot, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest}, journalAdmission); err != nil {
		t.Fatal(err)
	}
	revision2 := writeJournalFile(t, dir, "revision-2.tar", a.Revision2)
	if _, err = Import(ImportRequest{PackagePath: revision2, StoreRoot: storeRoot}, journalAdmission); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	before, err := loadCurrentTrust(store)
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := readImportPackage(revision2)
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := metadata.Timestamp().FromBytes(pkg.files["metadata/timestamp.json"])
	if err != nil {
		t.Fatal(err)
	}
	if len(timestamp.Signatures) != 1 || len(timestamp.Signatures[0].Signature) == 0 {
		t.Fatal("fixture timestamp signature shape changed")
	}
	timestamp.Signatures[0].Signature[0] ^= 0xff
	timestamp.Signed.Expires = timestamp.Signed.Expires.Add(time.Second)
	candidate, err := timestamp.ToBytes(false)
	if err != nil || bytes.Equal(candidate, before.timestamp) || validateTUFJSON(candidate) != nil {
		t.Fatalf("candidate bytes: %v", err)
	}
	pkg.files["metadata/timestamp.json"] = candidate
	candidatePath := writeJournalFile(t, dir, "same-version-different.tar", canonicalPackageBytes(t, pkg.files))
	rejected, err := Import(ImportRequest{PackagePath: candidatePath, StoreRoot: storeRoot}, journalAdmission)
	if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || rejected.TrustStateAdvanced {
		t.Fatalf("same-version receipt=%#v err=%v", rejected, err)
	}
	store, err = ensureStoreRoot(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	after, err := loadCurrentTrust(store)
	store.Close()
	if err != nil || !bytes.Equal(after.timestamp, before.timestamp) || after.stateDigest != before.stateDigest {
		t.Fatalf("accepted timestamp changed err=%v", err)
	}
}

func writeUncheckedTrustMaterial(t *testing.T, store *storeFS, material *trustMaterial, stateRaw []byte) {
	t.Helper()
	dir := "trust/states/" + strings.TrimPrefix(material.stateDigest, "sha256:")
	if err := store.write(dir+"/state.json", stateRaw, true); err != nil {
		t.Fatal(err)
	}
	versions := make([]int64, 0, len(material.rootHistory))
	for version := range material.rootHistory {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, version := range versions {
		if err := store.write(fmt.Sprintf("%s/roots/%d.root.json", dir, version), material.rootHistory[version], true); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string][]byte{"root.json": material.root, "timestamp.json": material.timestamp, "snapshot.json": material.snapshot, "targets.json": material.targets} {
		if len(raw) > 0 {
			if err := store.write(dir+"/"+name, raw, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	pointer, err := marshalCanonical(digestPointer{APIVersion: trustStateAPIVersion, Digest: material.stateDigest})
	if err != nil || store.write("trust/current.json", pointer, false) != nil {
		t.Fatalf("current pointer: %v", err)
	}
}

func canonicalPackageBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	for _, name := range names {
		raw := files[name]
		header := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := w.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
