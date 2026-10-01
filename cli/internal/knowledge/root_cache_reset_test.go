// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type cacheResetKey struct {
	id     string
	key    *metadata.Key
	signer signature.Signer
}

type cacheResetAuthority struct {
	keys      []*cacheResetKey
	threshold int
}

type cacheResetPolicy struct {
	root, timestamp, snapshot, targets cacheResetAuthority
}

type cacheResetFixture struct {
	now                  time.Time
	base, away, snapOnly cacheResetPolicy
	root1, root2, root3  []byte
	bundle100, bundle101 []byte
}

func TestRootCacheResetProductionImport(t *testing.T) {
	t.Run("away-back-reset-survives-crash-reopen-and-continuation", func(t *testing.T) {
		fixture := newCacheResetFixture(t)
		dir := t.TempDir()
		store := filepath.Join(dir, "store")
		importCacheResetPackage(t, store, fixture.now, fixture.root1, fixture.bundle100, 100, fixture.base, nil, "100")

		// The final root returns to the original key IDs, but an intermediate
		// authenticated hop changed both update authorities. The timestamp is
		// signed by the intermediate authority and therefore fails under root 3.
		failureRoles := makeCacheResetRoles(t, fixture.now, 101, fixture.bundle101, fixture.away)
		failure := cacheResetPackage(t, fixture.bundle101, failureRoles, map[int64][]byte{2: fixture.root2, 3: fixture.root3})
		failurePath := writeJournalFile(t, dir, "away-back-failure.tar", failure)
		cut, err := fixedConstraintsImport(t, ImportRequest{PackagePath: failurePath, StoreRoot: store}, fixture.now, "trust-pointer-published")
		if !errors.Is(err, constraintsProcessCut) || !errors.Is(err, ErrRecoveryRequired) || !cut.TrustStateAdvanced || cut.SelectionChanged {
			t.Fatalf("crash receipt=%+v err=%v", cut, err)
		}
		material := loadCacheResetMaterial(t, store)
		if material.state.Root.Version != 3 || material.state.Timestamp.Version != 0 || material.state.Snapshot.Version != 0 || material.state.Targets.Version != 0 || material.state.RevisionFloor != "100" || len(material.rootHistory) != 3 {
			t.Fatalf("durable reset state=%+v history=%d", material.state, len(material.rootHistory))
		}
		if _, err := os.Stat(filepath.Join(store, "import-pending.json")); err != nil {
			t.Fatalf("crash did not retain recovery marker: %v", err)
		}

		// Resume the exact interrupted package to clear recovery. Its old root
		// members are not replayed from root 3, and the persisted missing suffix
		// prevents the pre-rotation metadata from being restored.
		rejected, err := fixedConstraintsImport(t, ImportRequest{PackagePath: failurePath, StoreRoot: store}, fixture.now.Add(time.Second), "")
		if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || rejected.TrustStateAdvanced || rejected.SelectionChanged {
			t.Fatalf("resumed failure receipt=%+v err=%v", rejected, err)
		}
		material = loadCacheResetMaterial(t, store)
		if material.state.Root.Version != 3 || material.state.Timestamp.Version != 0 || material.state.RevisionFloor != "100" {
			t.Fatalf("resumed durable state=%+v", material.state)
		}

		// With no successor root supplied, fresh version-2 role metadata is now
		// valid under root 3. Knowledge revision 101 still advances independently
		// from the reset TUF role versions.
		continuationRoles := makeCacheResetRoles(t, fixture.now, 2, fixture.bundle101, fixture.base)
		continuation := cacheResetPackage(t, fixture.bundle101, continuationRoles, nil)
		continuationPath := writeJournalFile(t, dir, "continuation.tar", continuation)
		imported, err := fixedConstraintsImport(t, ImportRequest{PackagePath: continuationPath, StoreRoot: store, ExpectedRevision: "101", ExpectedBundleDigest: digestBytes(fixture.bundle101)}, fixture.now.Add(2*time.Second), "")
		if err != nil || imported.Status != "IMPORTED" || !imported.TrustStateAdvanced || !imported.SelectionChanged || imported.TrustReceipt.Root.Version != 3 || imported.TrustReceipt.Timestamp.Version != 2 || imported.TrustReceipt.Snapshot.Version != 2 || imported.TrustReceipt.Targets.Version != 2 || imported.TrustReceipt.KnowledgeRevision != "101" {
			t.Fatalf("continuation receipt=%+v err=%v", imported, err)
		}
		status, err := InspectConstraints(store)
		if err != nil || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != "101" {
			t.Fatalf("continuation status=%+v err=%v", status, err)
		}
	})

	t.Run("unchanged-authority-retains-role-version-floors", func(t *testing.T) {
		fixture := newCacheResetFixture(t)
		dir := t.TempDir()
		store := filepath.Join(dir, "store")
		importCacheResetPackage(t, store, fixture.now, fixture.root1, fixture.bundle100, 100, fixture.base, nil, "100")
		root2 := makeCacheResetRoot(t, fixture.now, 2, fixture.base)
		lowRoles := makeCacheResetRoles(t, fixture.now, 2, fixture.bundle101, fixture.base)
		low := writeJournalFile(t, dir, "unchanged-low.tar", cacheResetPackage(t, fixture.bundle101, lowRoles, map[int64][]byte{2: root2}))
		rejected, err := fixedConstraintsImport(t, ImportRequest{PackagePath: low, StoreRoot: store}, fixture.now, "")
		if !errors.Is(err, ErrRollback) || rejected.Status != "REJECTED" || !rejected.TrustStateAdvanced || rejected.SelectionChanged {
			t.Fatalf("unchanged-authority receipt=%+v err=%v", rejected, err)
		}
		material := loadCacheResetMaterial(t, store)
		if material.state.Root.Version != 2 || material.state.Timestamp.Version != 100 || material.state.Snapshot.Version != 100 || material.state.Targets.Version != 100 || material.state.RevisionFloor != "100" {
			t.Fatalf("unchanged-authority state=%+v", material.state)
		}
	})

	t.Run("snapshot-key-rotation-resets-joint-cache", func(t *testing.T) {
		fixture := newCacheResetFixture(t)
		dir := t.TempDir()
		store := filepath.Join(dir, "store")
		importCacheResetPackage(t, store, fixture.now, fixture.root1, fixture.bundle100, 100, fixture.base, nil, "100")
		root2 := makeCacheResetRoot(t, fixture.now, 2, fixture.snapOnly)
		lowRoles := makeCacheResetRoles(t, fixture.now, 2, fixture.bundle101, fixture.snapOnly)
		low := writeJournalFile(t, dir, "snapshot-rotation.tar", cacheResetPackage(t, fixture.bundle101, lowRoles, map[int64][]byte{2: root2}))
		imported, err := fixedConstraintsImport(t, ImportRequest{PackagePath: low, StoreRoot: store, ExpectedRevision: "101", ExpectedBundleDigest: digestBytes(fixture.bundle101)}, fixture.now, "")
		if err != nil || imported.Status != "IMPORTED" || !imported.SelectionChanged || imported.TrustReceipt.Root.Version != 2 || imported.TrustReceipt.Timestamp.Version != 2 || imported.TrustReceipt.Snapshot.Version != 2 || imported.TrustReceipt.Targets.Version != 2 {
			t.Fatalf("snapshot rotation receipt=%+v err=%v", imported, err)
		}
	})

	t.Run("invalid-first-successor-cannot-reset-or-advance", func(t *testing.T) {
		fixture := newCacheResetFixture(t)
		dir := t.TempDir()
		store := filepath.Join(dir, "store")
		importCacheResetPackage(t, store, fixture.now, fixture.root1, fixture.bundle100, 100, fixture.base, nil, "100")
		invalidRoot := corruptCacheResetRoot(t, fixture.root2)
		lowRoles := makeCacheResetRoles(t, fixture.now, 2, fixture.bundle101, fixture.away)
		low := writeJournalFile(t, dir, "invalid-root.tar", cacheResetPackage(t, fixture.bundle101, lowRoles, map[int64][]byte{2: invalidRoot}))
		rejected, err := fixedConstraintsImport(t, ImportRequest{PackagePath: low, StoreRoot: store}, fixture.now, "")
		if !errors.Is(err, ErrIntegrity) || rejected.Status != "REJECTED" || rejected.TrustStateAdvanced || rejected.SelectionChanged {
			t.Fatalf("invalid-root receipt=%+v err=%v", rejected, err)
		}
		material := loadCacheResetMaterial(t, store)
		if material.state.Root.Version != 1 || material.state.Timestamp.Version != 100 || material.state.Snapshot.Version != 100 || material.state.Targets.Version != 100 {
			t.Fatalf("invalid-root state=%+v", material.state)
		}
	})

	t.Run("nonconsecutive-offer-is-unused-and-does-not-reset", func(t *testing.T) {
		fixture := newCacheResetFixture(t)
		dir := t.TempDir()
		store := filepath.Join(dir, "store")
		importCacheResetPackage(t, store, fixture.now, fixture.root1, fixture.bundle100, 100, fixture.base, nil, "100")
		highRoles := makeCacheResetRoles(t, fixture.now, 100, fixture.bundle100, fixture.base)
		gap := writeJournalFile(t, dir, "gap-root.tar", cacheResetPackage(t, fixture.bundle100, highRoles, map[int64][]byte{3: fixture.root3}))
		rejected, err := fixedConstraintsImport(t, ImportRequest{PackagePath: gap, StoreRoot: store}, fixture.now, "")
		if !errors.Is(err, ErrInvalid) || rejected.Status != "REJECTED" || rejected.TrustStateAdvanced || rejected.SelectionChanged {
			t.Fatalf("gap receipt=%+v err=%v", rejected, err)
		}
		material := loadCacheResetMaterial(t, store)
		if material.state.Root.Version != 1 || material.state.Timestamp.Version != 100 || material.state.Snapshot.Version != 100 || material.state.Targets.Version != 100 {
			t.Fatalf("gap state=%+v", material.state)
		}
	})
}

func TestRootChainRotatesUpdateAuthorityBoundaries(t *testing.T) {
	fixture := newCacheResetFixture(t)
	if !rootChainRotatesUpdateAuthority(fixture.root1, map[string][]byte{"metadata/2.root.json": fixture.root2, "metadata/3.root.json": fixture.root3}) {
		t.Fatal("away/back chain did not make reset sticky")
	}
	if rootChainRotatesUpdateAuthority(fixture.root1, map[string][]byte{"metadata/3.root.json": fixture.root3}) {
		t.Fatal("nonconsecutive root authorized reset")
	}
	if rootChainRotatesUpdateAuthority(fixture.root1, map[string][]byte{"metadata/2.root.json": corruptCacheResetRoot(t, fixture.root2)}) {
		t.Fatal("invalid root authorized reset")
	}
	if !rootChainRotatesUpdateAuthority(fixture.root1, map[string][]byte{"metadata/2.root.json": fixture.root2, "metadata/3.root.json": corruptCacheResetRoot(t, fixture.root3)}) {
		t.Fatal("invalid later root erased an earlier authenticated reset")
	}
	targetsOnly := fixture.base
	targetsOnly.targets = cacheResetAuthority{keys: []*cacheResetKey{newCacheResetKey(t)}, threshold: 1}
	if rootChainRotatesUpdateAuthority(fixture.root1, map[string][]byte{"metadata/2.root.json": makeCacheResetRoot(t, fixture.now, 2, targetsOnly)}) {
		t.Fatal("targets-only authority change reset timestamp and snapshot")
	}
	threshold := fixture.base
	threshold.timestamp = cacheResetAuthority{keys: append([]*cacheResetKey(nil), fixture.base.timestamp.keys...), threshold: 1}
	extra := newCacheResetKey(t)
	threshold.timestamp.keys = append(threshold.timestamp.keys, extra)
	rootWithTwo := makeCacheResetRoot(t, fixture.now, 1, threshold)
	threshold.timestamp.threshold = 2
	rootWithHigherThreshold := makeCacheResetRoot(t, fixture.now, 2, threshold)
	if rootChainRotatesUpdateAuthority(rootWithTwo, map[string][]byte{"metadata/2.root.json": rootWithHigherThreshold}) {
		t.Fatal("threshold-only change reset the cache")
	}
}

type cacheResetRoles struct {
	timestamp, snapshot, targets []byte
}

func newCacheResetFixture(t *testing.T) cacheResetFixture {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	rootKey, timestampA, timestampB := newCacheResetKey(t), newCacheResetKey(t), newCacheResetKey(t)
	snapshotA, snapshotB, targetsKey := newCacheResetKey(t), newCacheResetKey(t), newCacheResetKey(t)
	one := func(key *cacheResetKey) cacheResetAuthority {
		return cacheResetAuthority{keys: []*cacheResetKey{key}, threshold: 1}
	}
	base := cacheResetPolicy{root: one(rootKey), timestamp: one(timestampA), snapshot: one(snapshotA), targets: one(targetsKey)}
	away := base
	away.timestamp, away.snapshot = one(timestampB), one(snapshotB)
	snapOnly := base
	snapOnly.snapshot = one(snapshotB)
	return cacheResetFixture{
		now: now, base: base, away: away, snapOnly: snapOnly,
		root1: makeCacheResetRoot(t, now, 1, base), root2: makeCacheResetRoot(t, now, 2, away), root3: makeCacheResetRoot(t, now, 3, base),
		bundle100: cacheResetBundle(t, now, "100"), bundle101: cacheResetBundle(t, now, "101"),
	}
}

func newCacheResetKey(t *testing.T) *cacheResetKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	key, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.ID()
	if err != nil {
		t.Fatal(err)
	}
	return &cacheResetKey{id: id, key: key, signer: signer}
}

func makeCacheResetRoot(t *testing.T, now time.Time, version int64, policy cacheResetPolicy) []byte {
	t.Helper()
	value := metadata.Root(now.Add(48 * time.Hour))
	value.Signed.Version = version
	value.Signed.ConsistentSnapshot = true
	roles := map[string]cacheResetAuthority{metadata.ROOT: policy.root, metadata.TIMESTAMP: policy.timestamp, metadata.SNAPSHOT: policy.snapshot, metadata.TARGETS: policy.targets}
	for _, roleName := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		authority := roles[roleName]
		for _, key := range authority.keys {
			if err := value.Signed.AddKey(key.key, roleName); err != nil {
				t.Fatal(err)
			}
		}
		value.Signed.Roles[roleName].Threshold = authority.threshold
	}
	for _, key := range policy.root.keys[:policy.root.threshold] {
		if _, err := value.Sign(key.signer); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := value.ToBytes(false)
	if err != nil || validateTUFJSON(raw) != nil {
		t.Fatalf("root bytes: %v", err)
	}
	return raw
}

func makeCacheResetRoles(t *testing.T, now time.Time, version int64, target []byte, policy cacheResetPolicy) cacheResetRoles {
	t.Helper()
	info, err := metadata.TargetFile().FromBytes(ConstraintsTargetPath, target, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	targets := metadata.Targets(now.Add(24 * time.Hour))
	targets.Signed.Version = version
	targets.Signed.Targets[ConstraintsTargetPath] = info
	signCacheResetRole(t, targets, policy.targets)
	targetsRaw, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadata.Snapshot(now.Add(24 * time.Hour))
	snapshot.Signed.Version = version
	snapshot.Signed.Meta["targets.json"] = cacheResetMeta(version, targetsRaw)
	signCacheResetRole(t, snapshot, policy.snapshot)
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := metadata.Timestamp(now.Add(24 * time.Hour))
	timestamp.Signed.Version = version
	timestamp.Signed.Meta["snapshot.json"] = cacheResetMeta(version, snapshotRaw)
	signCacheResetRole(t, timestamp, policy.timestamp)
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return cacheResetRoles{timestamp: timestampRaw, snapshot: snapshotRaw, targets: targetsRaw}
}

type cacheResetSignable interface {
	metadata.RootType | metadata.TimestampType | metadata.SnapshotType | metadata.TargetsType
}

func signCacheResetRole[T cacheResetSignable](t *testing.T, value *metadata.Metadata[T], authority cacheResetAuthority) {
	t.Helper()
	for _, key := range authority.keys[:authority.threshold] {
		if _, err := value.Sign(key.signer); err != nil {
			t.Fatal(err)
		}
	}
}

func cacheResetMeta(version int64, raw []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(raw)
	return &metadata.MetaFiles{Version: version, Length: int64(len(raw)), Hashes: metadata.Hashes{"sha256": metadata.HexBytes(sum[:])}}
}

func cacheResetPackage(t *testing.T, target []byte, roles cacheResetRoles, roots map[int64][]byte) []byte {
	t.Helper()
	digest := strings.TrimPrefix(digestBytes(target), "sha256:")
	files := map[string][]byte{
		"metadata/timestamp.json": roles.timestamp,
		fmt.Sprintf("metadata/%d.snapshot.json", parsedVersion(roles.snapshot, "snapshot")): roles.snapshot,
		fmt.Sprintf("metadata/%d.targets.json", parsedVersion(roles.targets, "targets")):    roles.targets,
		fmt.Sprintf("targets/knowledge/%s.constraints.v1.json", digest):                     target,
	}
	for version, raw := range roots {
		files[fmt.Sprintf("metadata/%d.root.json", version)] = raw
	}
	return canonicalPackageBytes(t, files)
}

func cacheResetBundle(t *testing.T, now time.Time, revision string) []byte {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateConstraints(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := writeJournalFile(t, dir, "fixture.tar", artifacts.Revision2)
	pkg, err := readImportPackageForProfile(path, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	var target []byte
	for name, raw := range pkg.files {
		if strings.HasPrefix(name, "targets/knowledge/") {
			target = raw
			break
		}
	}
	var document map[string]any
	if len(target) == 0 || json.Unmarshal(target, &document) != nil {
		t.Fatal("fixture target unavailable")
	}
	document["revision"] = revision
	pack, ok := document["pack"].(map[string]any)
	if !ok {
		t.Fatal("fixture pack unavailable")
	}
	pack["revision"] = revision
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := constraintsProfile().admit(raw)
	if err != nil || admission.Revision != revision {
		t.Fatalf("bundle admission=%+v err=%v", admission, err)
	}
	return raw
}

func importCacheResetPackage(t *testing.T, store string, now time.Time, root, bundle []byte, roleVersion int64, policy cacheResetPolicy, roots map[int64][]byte, revision string) ImportReceipt {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, root, 0o600); err != nil {
		t.Fatal(err)
	}
	roles := makeCacheResetRoles(t, now, roleVersion, bundle, policy)
	pkg := writeJournalFile(t, dir, "package.tar", cacheResetPackage(t, bundle, roles, roots))
	receipt, err := fixedConstraintsImport(t, ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: rootPath, BootstrapRootDigest: digestBytes(root), ExpectedRevision: revision, ExpectedBundleDigest: digestBytes(bundle)}, now, "")
	if err != nil || receipt.Status != "IMPORTED" {
		t.Fatalf("initial import receipt=%+v err=%v", receipt, err)
	}
	return receipt
}

func loadCacheResetMaterial(t *testing.T, storeRoot string) *trustMaterial {
	t.Helper()
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	material, err := loadCurrentTrustForProfile(store, constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func corruptCacheResetRoot(t *testing.T, raw []byte) []byte {
	t.Helper()
	value, err := metadata.Root().FromBytes(raw)
	if err != nil || len(value.Signatures) != 1 || len(value.Signatures[0].Signature) == 0 {
		t.Fatalf("root signature: %v", err)
	}
	value.Signatures[0].Signature[0] ^= 0xff
	corrupt, err := value.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return corrupt
}
