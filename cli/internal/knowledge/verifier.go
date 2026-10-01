// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type trustMaterial struct {
	state       trustState
	stateDigest string
	rootHistory map[int64][]byte
	root        []byte
	timestamp   []byte
	snapshot    []byte
	targets     []byte
}

type verificationResult struct {
	material   trustMaterial
	target     []byte
	targetInfo *metadata.TargetFiles
	verifiedAt time.Time
	refreshErr error
	served     map[string][]byte
}

func verifyPackage(pkg importPackage, prior *trustMaterial, bootstrap []byte, initialDigest string, testRefTime *time.Time, fetchHook func(string) error) (verificationResult, error) {
	return verifyPackageForProfile(pkg, certManagerProfile(), prior, bootstrap, initialDigest, testRefTime, fetchHook)
}

func verifyPackageForProfile(pkg importPackage, profile profileSpec, prior *trustMaterial, bootstrap []byte, initialDigest string, testRefTime *time.Time, fetchHook func(string) error) (verificationResult, error) {
	if !profile.valid() {
		return verificationResult{}, ErrIntegrity
	}
	var localRoot []byte
	if prior == nil {
		localRoot = append([]byte(nil), bootstrap...)
	} else {
		localRoot = append([]byte(nil), prior.root...)
		initialDigest = prior.state.InitialRootDigest
	}
	if len(localRoot) == 0 {
		return verificationResult{}, fmt.Errorf("trusted root required: %w", ErrInvalid)
	}
	if err := validateTUFJSON(localRoot); err != nil {
		return verificationResult{}, fmt.Errorf("trusted root JSON: %w", ErrIntegrity)
	}
	parsedRoot, err := metadata.Root().FromBytes(localRoot)
	if err != nil || validateRootPolicy(parsedRoot) != nil {
		return verificationResult{}, fmt.Errorf("trusted root policy: %w", ErrIntegrity)
	}
	if digestBytes(localRoot) != initialDigest && prior == nil {
		return verificationResult{}, fmt.Errorf("initial root digest: %w", ErrIntegrity)
	}

	// The updater's cache is disposable and outside the durable store. TUF
	// authenticates every byte read back from it, so same-UID interference can
	// only make verification fail; it cannot authenticate different package
	// bytes or change durable trust state by itself.
	txn, err := os.MkdirTemp("", "prufyx-knowledge-verify-")
	if err != nil {
		return verificationResult{}, err
	}
	defer os.RemoveAll(txn)
	metaDir := filepath.Join(txn, "metadata")
	targetDir := filepath.Join(txn, "targets")
	if err := os.Mkdir(metaDir, 0o700); err != nil {
		return verificationResult{}, err
	}
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		return verificationResult{}, err
	}
	resetDownstreamCache := rootChainRotatesUpdateAuthority(localRoot, pkg.files)
	if prior != nil {
		for name, raw := range map[string][]byte{"timestamp.json": prior.timestamp, "snapshot.json": prior.snapshot, "targets.json": prior.targets} {
			if resetDownstreamCache && (name == "timestamp.json" || name == "snapshot.json") {
				continue
			}
			if len(raw) > 0 {
				if err := os.WriteFile(filepath.Join(metaDir, name), raw, 0o600); err != nil {
					return verificationResult{}, err
				}
			}
		}
	}

	fetcher := newMemoryFetcher(pkg, fetchHook)
	cfg := &config.UpdaterConfig{Fetcher: fetcher, LocalTrustedRoot: append([]byte(nil), localRoot...), LocalMetadataDir: metaDir, LocalTargetsDir: targetDir, RemoteMetadataURL: "https://offline.invalid/metadata", RemoteTargetsURL: "https://offline.invalid/targets", MaxRootRotations: 8, MaxDelegations: 0, RootMaxLength: rootMetadataMaxBytes, TimestampMaxLength: 64 << 10, SnapshotMaxLength: 256 << 10, TargetsMaxLength: 256 << 10, DisableLocalCache: false, PrefixTargetsWithHash: true, UnsafeLocalMode: false}
	u, err := updater.New(cfg)
	if err != nil {
		return verificationResult{}, err
	}
	if testRefTime != nil {
		u.UnsafeSetRefTime(testRefTime.UTC())
	}
	refreshErr := u.Refresh()
	trusted := u.GetTrustedMetadataSet()
	accepted, err := acceptedCacheBytes(metaDir, localRoot, profile)
	if err != nil {
		return verificationResult{}, err
	}
	material, err := materialFromTrusted(trusted, prior, pkg, initialDigest, localRoot, accepted, resetDownstreamCache)
	if err != nil {
		return verificationResult{}, err
	}
	result := verificationResult{material: material, verifiedAt: trusted.RefTime.UTC(), refreshErr: refreshErr, served: fetcher.served}
	if refreshErr != nil {
		return result, nil
	}
	if err := validateTrustedSetForProfile(trusted, profile); err != nil {
		result.refreshErr = err
		return result, nil
	}
	info, err := u.GetTargetInfo(profile.targetPath)
	if err != nil {
		result.refreshErr = err
		return result, nil
	}
	if len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256Size {
		result.refreshErr = fmt.Errorf("target hash policy: %w", ErrIntegrity)
		return result, nil
	}
	_, target, err := u.DownloadTarget(info, filepath.Join(targetDir, "knowledge.json"), "https://offline.invalid/targets")
	if err != nil {
		result.refreshErr = err
		return result, nil
	}
	result.target = append([]byte(nil), target...)
	result.targetInfo = info
	return result, nil
}

const (
	sha256Size           = 32
	rootMetadataMaxBytes = 128 << 10
)

func materialFromTrusted(trusted trustedmetadata.TrustedMetadata, prior *trustMaterial, pkg importPackage, initialDigest string, initialRoot []byte, accepted map[string][]byte, resetDownstreamCache bool) (trustMaterial, error) {
	if trusted.Root == nil {
		return trustMaterial{}, ErrIntegrity
	}
	history := map[int64][]byte{}
	if prior != nil {
		for version, raw := range prior.rootHistory {
			history[version] = append([]byte(nil), raw...)
		}
	}
	bootstrapVersion := int64(0)
	if prior != nil {
		bootstrapVersion = prior.state.Root.Version
	} else {
		parsed, err := metadata.Root().FromBytes(initialRoot)
		if err != nil {
			return trustMaterial{}, ErrIntegrity
		}
		bootstrapVersion = parsed.Signed.Version
		history[bootstrapVersion] = append([]byte(nil), initialRoot...)
	}
	for version := bootstrapVersion + 1; version <= trusted.Root.Signed.Version; version++ {
		raw, ok := pkg.files[fmt.Sprintf("metadata/%d.root.json", version)]
		if !ok {
			return trustMaterial{}, fmt.Errorf("accepted root bytes missing: %w", ErrIntegrity)
		}
		history[version] = append([]byte(nil), raw...)
	}
	rootRaw := accepted["root"]
	acceptedRoot, acceptedRootErr := metadata.Root().FromBytes(rootRaw)
	if len(rootRaw) == 0 || acceptedRootErr != nil || !reflect.DeepEqual(acceptedRoot, trusted.Root) {
		return trustMaterial{}, fmt.Errorf("current root bytes missing: %w", ErrIntegrity)
	}
	history[trusted.Root.Signed.Version] = append([]byte(nil), rootRaw...)
	state := trustState{APIVersion: trustStateAPIVersion, InitialRootDigest: initialDigest}
	if prior != nil {
		state.RevisionFloor = prior.state.RevisionFloor
		state.RevisionFloorBundleDigest = prior.state.RevisionFloorBundleDigest
	}
	material := trustMaterial{state: state, rootHistory: history, root: append([]byte(nil), rootRaw...)}
	material.timestamp = trustedTimestampRaw(trusted.Timestamp, accepted["timestamp"])
	material.snapshot = trustedVersionedRaw(trusted.Snapshot, "snapshot", accepted["snapshot"])
	material.targets = trustedVersionedRaw(trusted.Targets[metadata.TARGETS], "targets", accepted["targets"])
	if prior != nil && !resetDownstreamCache {
		if trusted.Timestamp == nil && roleAuthorityUnchanged(prior.root, rootRaw, metadata.TIMESTAMP) {
			material.timestamp = append([]byte(nil), prior.timestamp...)
			material.state.Timestamp = prior.state.Timestamp
		}
		if len(material.timestamp) > 0 && trusted.Snapshot == nil && roleAuthorityUnchanged(prior.root, rootRaw, metadata.SNAPSHOT) {
			material.snapshot = append([]byte(nil), prior.snapshot...)
			material.state.Snapshot = prior.state.Snapshot
		}
		if len(material.snapshot) > 0 && trusted.Targets[metadata.TARGETS] == nil && roleAuthorityUnchanged(prior.root, rootRaw, metadata.TARGETS) {
			material.targets = append([]byte(nil), prior.targets...)
			material.state.Targets = prior.state.Targets
		}
	}
	if trusted.Timestamp != nil && len(material.timestamp) == 0 || trusted.Snapshot != nil && len(material.snapshot) == 0 || trusted.Targets[metadata.TARGETS] != nil && len(material.targets) == 0 {
		return trustMaterial{}, ErrIntegrity
	}
	material.state.Root = roleReceipt(trusted.Root, material.root)
	if trusted.Timestamp != nil {
		material.state.Timestamp = roleReceipt(trusted.Timestamp, material.timestamp)
	}
	if trusted.Snapshot != nil {
		material.state.Snapshot = roleReceipt(trusted.Snapshot, material.snapshot)
	}
	if trusted.Targets[metadata.TARGETS] != nil {
		material.state.Targets = roleReceipt(trusted.Targets[metadata.TARGETS], material.targets)
	}
	versions := make([]int64, 0, len(history))
	for version := range history {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, version := range versions {
		material.state.RootHistory = append(material.state.RootHistory, RootHistoryEntry{Version: version, Digest: digestBytes(history[version])})
	}
	raw, err := marshalCanonical(material.state)
	if err != nil {
		return trustMaterial{}, err
	}
	material.stateDigest = digestBytes(raw)
	return material, nil
}

func roleAuthorityUnchanged(oldRaw, newRaw []byte, roleName string) bool {
	oldRoot, e1 := metadata.Root().FromBytes(oldRaw)
	newRoot, e2 := metadata.Root().FromBytes(newRaw)
	if e1 != nil || e2 != nil {
		return false
	}
	oldRole, ok1 := oldRoot.Signed.Roles[roleName]
	newRole, ok2 := newRoot.Signed.Roles[roleName]
	if !ok1 || !ok2 || !reflect.DeepEqual(oldRole, newRole) {
		return false
	}
	for _, id := range oldRole.KeyIDs {
		if !reflect.DeepEqual(oldRoot.Signed.Keys[id], newRoot.Signed.Keys[id]) {
			return false
		}
	}
	return true
}

func priorValue(prior *trustMaterial, name string) []byte {
	if prior == nil {
		return nil
	}
	switch name {
	case "timestamp":
		return prior.timestamp
	case "snapshot":
		return prior.snapshot
	case "targets":
		return prior.targets
	}
	return nil
}

type versionedRole interface {
	metadata.SnapshotType | metadata.TargetsType
}

func versionedRoleRaw[T versionedRole](role *metadata.Metadata[T], name string, pkg importPackage, prior []byte) []byte {
	if role == nil {
		return nil
	}
	version := roleVersion(role.Signed)
	if raw := pkg.files[fmt.Sprintf("metadata/%d.%s.json", version, name)]; len(raw) > 0 {
		return append([]byte(nil), raw...)
	}
	if parsedVersion(prior, name) == version {
		return append([]byte(nil), prior...)
	}
	return nil
}

func trustedVersionedRaw[T versionedRole](role *metadata.Metadata[T], name string, accepted []byte) []byte {
	if role == nil {
		return nil
	}
	if parsed := parseVersionedRole[T](accepted, name); parsed != nil && reflect.DeepEqual(parsed, role) {
		return append([]byte(nil), accepted...)
	}
	return nil
}

func parseVersionedRole[T versionedRole](raw []byte, name string) *metadata.Metadata[T] {
	if len(raw) == 0 {
		return nil
	}
	var value any
	var err error
	if name == "snapshot" {
		value, err = metadata.Snapshot().FromBytes(raw)
	} else {
		value, err = metadata.Targets().FromBytes(raw)
	}
	if err != nil {
		return nil
	}
	typed, ok := value.(*metadata.Metadata[T])
	if !ok {
		return nil
	}
	return typed
}

func trustedTimestampRaw(role *metadata.Metadata[metadata.TimestampType], accepted []byte) []byte {
	if role == nil {
		return nil
	}
	parsed, err := metadata.Timestamp().FromBytes(accepted)
	if err == nil && reflect.DeepEqual(parsed, role) {
		return append([]byte(nil), accepted...)
	}
	return nil
}

func acceptedCacheBytes(metaDir string, root []byte, profile profileSpec) (map[string][]byte, error) {
	result := map[string][]byte{"root": append([]byte(nil), root...)}
	for _, name := range []string{"root", "timestamp", "snapshot", "targets"} {
		raw, _, err := currentbundle.ReadBoundedFileInfo(filepath.Join(metaDir, name+".json"), maxStateFile)
		if err == nil {
			if validateTUFJSONForTarget(raw, profile.targetPath) != nil {
				return nil, ErrIntegrity
			}
			result[name] = raw
		}
		// Cached roles are optional: an interrupted updater can leave any role
		// absent or unreadable. Only accepted, independently validated bytes are
		// returned; the caller will verify required metadata before use.
	}
	return result, nil
}

func roleRaw(role *metadata.Metadata[metadata.TimestampType], name string, pkg importPackage, prior []byte) []byte {
	if role == nil {
		return nil
	}
	if raw := pkg.files[name]; len(raw) > 0 && parsedVersion(raw, "timestamp") == role.Signed.Version {
		return append([]byte(nil), raw...)
	}
	if parsedVersion(prior, "timestamp") == role.Signed.Version {
		return append([]byte(nil), prior...)
	}
	return nil
}

func parsedVersion(raw []byte, name string) int64 {
	if len(raw) == 0 {
		return 0
	}
	switch name {
	case "timestamp":
		v, _ := metadata.Timestamp().FromBytes(raw)
		if v != nil {
			return v.Signed.Version
		}
	case "snapshot":
		v, _ := metadata.Snapshot().FromBytes(raw)
		if v != nil {
			return v.Signed.Version
		}
	case "targets":
		v, _ := metadata.Targets().FromBytes(raw)
		if v != nil {
			return v.Signed.Version
		}
	}
	return 0
}

func roleVersion[T versionedRole](value T) int64 {
	raw, _ := json.Marshal(value)
	var header struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(raw, &header)
	return header.Version
}

type receiptRole interface {
	metadata.RootType | metadata.TimestampType | metadata.SnapshotType | metadata.TargetsType
}

func roleReceipt[T receiptRole](role *metadata.Metadata[T], raw []byte) RoleReceipt {
	if role == nil || len(raw) == 0 {
		return RoleReceipt{}
	}
	encoded, _ := json.Marshal(role.Signed)
	var header struct {
		Version int64     `json:"version"`
		Expires time.Time `json:"expires"`
	}
	_ = json.Unmarshal(encoded, &header)
	return RoleReceipt{Version: header.Version, Digest: digestBytes(raw), Expires: header.Expires.UTC().Format(time.RFC3339)}
}

func roleReceiptFromRaw(name string, raw []byte) RoleReceipt {
	switch name {
	case "root":
		v, e := metadata.Root().FromBytes(raw)
		if e == nil {
			return roleReceipt(v, raw)
		}
	case "timestamp":
		v, e := metadata.Timestamp().FromBytes(raw)
		if e == nil {
			return roleReceipt(v, raw)
		}
	case "snapshot":
		v, e := metadata.Snapshot().FromBytes(raw)
		if e == nil {
			return roleReceipt(v, raw)
		}
	case "targets":
		v, e := metadata.Targets().FromBytes(raw)
		if e == nil {
			return roleReceipt(v, raw)
		}
	}
	return RoleReceipt{}
}

func validateRootPolicy(root *metadata.Metadata[metadata.RootType]) error {
	if root == nil || validateSignatures(root) != nil || root.Signed.Type != metadata.ROOT || root.Signed.Version < 1 || root.Signed.Version > maxRevision || root.Signed.Expires.IsZero() || !root.Signed.ConsistentSnapshot || len(root.UnrecognizedFields) != 0 || len(root.Signed.UnrecognizedFields) != 0 || len(root.Signed.Roles) != 4 || !strings.HasPrefix(root.Signed.SpecVersion, "1.0.") {
		return ErrIntegrity
	}
	for _, name := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		role, ok := root.Signed.Roles[name]
		if !ok || role == nil || role.Threshold < 1 || role.Threshold > len(role.KeyIDs) || len(role.UnrecognizedFields) != 0 {
			return ErrIntegrity
		}
		seen := map[string]bool{}
		for _, id := range role.KeyIDs {
			key := root.Signed.Keys[id]
			if !hexKeyRE.MatchString(id) || seen[id] || key == nil || key.Type != metadata.KeyTypeEd25519 || key.Scheme != metadata.KeySchemeEd25519 || len(key.UnrecognizedFields) != 0 || len(key.Value.UnrecognizedFields) != 0 {
				return ErrIntegrity
			}
			seen[id] = true
		}
	}
	for id, key := range root.Signed.Keys {
		if key == nil {
			return ErrIntegrity
		}
		computed, computeErr := key.ID()
		if !hexKeyRE.MatchString(id) || computeErr != nil || computed != id || key.Type != metadata.KeyTypeEd25519 || key.Scheme != metadata.KeySchemeEd25519 {
			return ErrIntegrity
		}
	}
	return nil
}

func validateTrustedSet(trusted trustedmetadata.TrustedMetadata) error {
	return validateTrustedSetForProfile(trusted, certManagerProfile())
}

func validateTrustedSetForProfile(trusted trustedmetadata.TrustedMetadata, profile profileSpec) error {
	if !profile.valid() {
		return ErrIntegrity
	}
	if err := validateRootPolicy(trusted.Root); err != nil || trusted.Timestamp == nil || trusted.Snapshot == nil || trusted.Targets[metadata.TARGETS] == nil || validateSignatures(trusted.Timestamp) != nil || validateSignatures(trusted.Snapshot) != nil || validateSignatures(trusted.Targets[metadata.TARGETS]) != nil {
		return ErrIntegrity
	}
	if trusted.Timestamp.Signed.Type != metadata.TIMESTAMP || trusted.Timestamp.Signed.Version < 1 || trusted.Timestamp.Signed.Version > maxRevision || trusted.Timestamp.Signed.Expires.IsZero() || !strings.HasPrefix(trusted.Timestamp.Signed.SpecVersion, "1.0.") || trusted.Snapshot.Signed.Type != metadata.SNAPSHOT || trusted.Snapshot.Signed.Version < 1 || trusted.Snapshot.Signed.Version > maxRevision || trusted.Snapshot.Signed.Expires.IsZero() || !strings.HasPrefix(trusted.Snapshot.Signed.SpecVersion, "1.0.") || trusted.Targets[metadata.TARGETS].Signed.Type != metadata.TARGETS || trusted.Targets[metadata.TARGETS].Signed.Version < 1 || trusted.Targets[metadata.TARGETS].Signed.Version > maxRevision || trusted.Targets[metadata.TARGETS].Signed.Expires.IsZero() || !strings.HasPrefix(trusted.Targets[metadata.TARGETS].Signed.SpecVersion, "1.0.") {
		return ErrIntegrity
	}
	if len(trusted.Timestamp.UnrecognizedFields) != 0 || len(trusted.Timestamp.Signed.UnrecognizedFields) != 0 || len(trusted.Timestamp.Signed.Meta) != 1 || trusted.Timestamp.Signed.Meta["snapshot.json"] == nil {
		return ErrIntegrity
	}
	if len(trusted.Snapshot.UnrecognizedFields) != 0 || len(trusted.Snapshot.Signed.UnrecognizedFields) != 0 || len(trusted.Snapshot.Signed.Meta) != 1 || trusted.Snapshot.Signed.Meta["targets.json"] == nil {
		return ErrIntegrity
	}
	targets := trusted.Targets[metadata.TARGETS]
	if len(targets.UnrecognizedFields) != 0 || len(targets.Signed.UnrecognizedFields) != 0 || targets.Signed.Delegations != nil || len(targets.Signed.Targets) != 1 || targets.Signed.Targets[profile.targetPath] == nil {
		return ErrIntegrity
	}
	for _, metaFile := range []*metadata.MetaFiles{trusted.Timestamp.Signed.Meta["snapshot.json"], trusted.Snapshot.Signed.Meta["targets.json"]} {
		if metaFile.Version < 1 || metaFile.Length < 1 || len(metaFile.Hashes) != 1 || len(metaFile.Hashes["sha256"]) != sha256Size || len(metaFile.UnrecognizedFields) != 0 {
			return ErrIntegrity
		}
	}
	target := targets.Signed.Targets[profile.targetPath]
	if target.Length < 1 || target.Length > profile.maxTarget || len(target.Hashes) != 1 || len(target.Hashes["sha256"]) != sha256Size || target.Custom != nil || len(target.UnrecognizedFields) != 0 {
		return ErrIntegrity
	}
	return nil
}

func validateSignatures[T receiptRole](role *metadata.Metadata[T]) error {
	if role == nil || len(role.Signatures) < 1 || len(role.Signatures) > 32 {
		return ErrIntegrity
	}
	for _, s := range role.Signatures {
		if !hexKeyRE.MatchString(s.KeyID) || len(s.Signature) == 0 || len(s.UnrecognizedFields) != 0 {
			return ErrIntegrity
		}
	}
	return nil
}

func classifyTUFError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, &metadata.ErrExpiredMetadata{}) {
		return fmt.Errorf("TUF metadata expired: %w", ErrExpired)
	}
	if errors.Is(err, &metadata.ErrBadVersionNumber{}) || errors.Is(err, &metadata.ErrEqualVersionNumber{}) {
		return fmt.Errorf("TUF rollback/version failure: %w", ErrRollback)
	}
	return fmt.Errorf("TUF verification: %w", ErrIntegrity)
}

func ensureAllPackageMembersUsed(pkg importPackage, served map[string][]byte, accepted *trustMaterial) error {
	for name := range pkg.files {
		if _, ok := served[name]; !ok {
			allowed := false
			if accepted != nil {
				switch name {
				case fmt.Sprintf("metadata/%d.snapshot.json", accepted.state.Snapshot.Version):
					allowed = bytes.Equal(pkg.files[name], accepted.snapshot)
				case fmt.Sprintf("metadata/%d.targets.json", accepted.state.Targets.Version):
					allowed = bytes.Equal(pkg.files[name], accepted.targets)
				}
			}
			if !allowed {
				return fmt.Errorf("unused package member %s: %w", name, ErrInvalid)
			}
		}
	}
	return nil
}
