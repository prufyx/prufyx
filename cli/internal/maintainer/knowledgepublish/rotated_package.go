// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepack"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// RotatedFinalizePackageOptions binds one package to its independently pinned
// initial root and its complete ordered successor sequence.
type RotatedFinalizePackageOptions struct {
	InitialRoot, Target, Targets, Snapshot, Timestamp []byte
	InitialRootDigest                                 string
	SuccessorRoots                                    [][]byte
}

type admittedRootMember struct {
	version int64
	raw     []byte
	digest  string
}

// FinalizeRotatedPackage creates a manual package for exactly one current root.
// It does not issue a release plan or make an initialized-store eligibility claim.
func FinalizeRotatedPackage(opts RotatedFinalizePackageOptions) ([]byte, FinalizationReceipt, error) {
	initial, initialDigest, err := admitRoot(opts.InitialRoot, opts.InitialRootDigest)
	if err != nil || len(opts.SuccessorRoots) == 0 || len(opts.SuccessorRoots) > 8 {
		return nil, FinalizationReceipt{}, ErrRejected
	}
	final, members, err := admitSuccessorRoots(opts.InitialRoot, opts.SuccessorRoots)
	if err != nil {
		return nil, FinalizationReceipt{}, ErrRejected
	}
	packageRaw, receipt, err := finalizeAdmittedPackage(opts.InitialRoot, initialDigest, final, members, opts.Target, opts.Targets, opts.Snapshot, opts.Timestamp)
	if err != nil || !validRotatedReceipt(receipt, initial, initialDigest, final, members) {
		return nil, FinalizationReceipt{}, ErrRejected
	}
	return packageRaw, receipt, nil
}

func admitSuccessorRoots(initial []byte, successors [][]byte) (*metadata.Metadata[metadata.RootType], []admittedRootMember, error) {
	trusted, err := trustedmetadata.New(initial)
	if err != nil {
		return nil, nil, ErrRejected
	}
	members := make([]admittedRootMember, 0, len(successors))
	for _, raw := range successors {
		if len(raw) == 0 || len(raw) > MaxRootBytes {
			return nil, nil, ErrRejected
		}
		candidate, err := metadata.Root().FromBytes(raw)
		if err != nil || rootPolicy(candidate, true) != nil || candidate.Signed.Version != trusted.Root.Signed.Version+1 {
			return nil, nil, ErrRejected
		}
		canonical, err := candidate.ToBytes(false)
		if err != nil || !bytes.Equal(raw, canonical) {
			return nil, nil, ErrRejected
		}
		if _, err = trusted.UpdateRoot(raw); err != nil || rootPolicy(trusted.Root, true) != nil {
			return nil, nil, ErrRejected
		}
		members = append(members, admittedRootMember{version: candidate.Signed.Version, raw: bytes.Clone(raw), digest: digest(raw)})
	}
	return trusted.Root, members, nil
}

func finalizeAdmittedPackage(initialRaw []byte, initialDigest string, authority *metadata.Metadata[metadata.RootType], successors []admittedRootMember, targetRaw, targetsRaw, snapshotRaw, timestampRaw []byte) ([]byte, FinalizationReceipt, error) {
	targetDigest, admission, err := admitTarget(targetRaw)
	if err != nil {
		return nil, FinalizationReceipt{}, err
	}
	targets, snapshot, err := admitTargetsSnapshot(authority, targetRaw, targetsRaw, snapshotRaw)
	if err != nil || validateSnapshot(snapshot, targetsRaw, targets.Signed.Version) != nil {
		return nil, FinalizationReceipt{}, fmt.Errorf("signed target chain: %w", ErrRejected)
	}
	timestamp, err := parseTimestamp(timestampRaw, true)
	if err != nil || authority.VerifyDelegate(metadata.TIMESTAMP, timestamp) != nil || validateTimestamp(timestamp, snapshotRaw, snapshot.Signed.Version) != nil {
		return nil, FinalizationReceipt{}, fmt.Errorf("signed timestamp: %w", ErrRejected)
	}
	txn, err := os.MkdirTemp("", "prufyx-knowledge-publish-")
	if err != nil {
		return nil, FinalizationReceipt{}, fmt.Errorf("publisher workspace: %w", err)
	}
	defer os.RemoveAll(txn)
	if err := os.Chmod(txn, 0o700); err != nil {
		return nil, FinalizationReceipt{}, err
	}
	repository := filepath.Join(txn, "repository")
	if err := os.MkdirAll(filepath.Join(repository, "targets", "knowledge"), 0o700); err != nil {
		return nil, FinalizationReceipt{}, err
	}
	if err := os.Mkdir(filepath.Join(repository, "metadata"), 0o700); err != nil {
		return nil, FinalizationReceipt{}, err
	}
	entries := map[string][]byte{
		filepath.Join("metadata", fmt.Sprintf("%d.targets.json", targets.Signed.Version)):                                                     targetsRaw,
		filepath.Join("metadata", fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)):                                                   snapshotRaw,
		filepath.Join("metadata", "timestamp.json"):                                                                                           timestampRaw,
		filepath.Join("targets", "knowledge", strings.TrimPrefix(targetDigest, "sha256:")+"."+filepath.Base(knowledge.ConstraintsTargetPath)): targetRaw,
	}
	for _, successor := range successors {
		entries[filepath.Join("metadata", fmt.Sprintf("%d.root.json", successor.version))] = successor.raw
	}
	for name, raw := range entries {
		if err := os.WriteFile(filepath.Join(repository, name), raw, 0o600); err != nil {
			return nil, FinalizationReceipt{}, fmt.Errorf("stage repository: %w", err)
		}
	}
	packageRaw, err := knowledgepack.PackageDirectory(repository, "cncf")
	if err != nil {
		return nil, FinalizationReceipt{}, err
	}
	rootPath, packagePath := filepath.Join(txn, "root.json"), filepath.Join(txn, "package.tar")
	if err := os.WriteFile(rootPath, initialRaw, 0o600); err != nil {
		return nil, FinalizationReceipt{}, err
	}
	if err := os.WriteFile(packagePath, packageRaw, 0o600); err != nil {
		return nil, FinalizationReceipt{}, err
	}
	verification, err := knowledge.VerifyConstraints(knowledge.VerifyRequest{PackagePath: packagePath, BootstrapRootPath: rootPath, BootstrapRootDigest: initialDigest, ExpectedPackageDigest: digest(packageRaw), ExpectedRevision: admission.Revision, ExpectedBundleDigest: targetDigest})
	if err != nil {
		return nil, FinalizationReceipt{}, fmt.Errorf("consumer verification: %w", err)
	}
	if verification.Root.Version != authority.Signed.Version || verification.Root.Digest != digestRoot(authority) ||
		verification.Targets.Version != targets.Signed.Version || verification.Targets.Digest != digest(targetsRaw) ||
		verification.Snapshot.Version != snapshot.Signed.Version || verification.Snapshot.Digest != digest(snapshotRaw) ||
		verification.Timestamp.Version != timestamp.Signed.Version || verification.Timestamp.Digest != digest(timestampRaw) {
		return nil, FinalizationReceipt{}, fmt.Errorf("consumer verification receipt: %w", ErrRejected)
	}
	return packageRaw, FinalizationReceipt{Schema: FinalReceiptSchema, Status: "VERIFIED_FOR_PACKAGING", Profile: "cncf", RootDigest: initialDigest, TargetDigest: targetDigest, PackageDigest: digest(packageRaw), KnowledgeRevision: admission.Revision, CapabilityDigest: admission.EngineCapabilityDigest, Verification: verification}, nil
}

func digestRoot(root *metadata.Metadata[metadata.RootType]) string {
	raw, err := root.ToBytes(false)
	if err != nil {
		return ""
	}
	return digest(raw)
}

func validRotatedReceipt(receipt FinalizationReceipt, initial *metadata.Metadata[metadata.RootType], initialDigest string, final *metadata.Metadata[metadata.RootType], successors []admittedRootMember) bool {
	v := receipt.Verification
	if receipt.Schema != FinalReceiptSchema || receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.Profile != "cncf" || receipt.NetworkUsed || receipt.KeysHandled || receipt.RootDigest != initialDigest || v.APIVersion != "prufyx.io/knowledge-package-verification/v1" || v.Status != "VERIFIED" || v.Profile != "cncf" || v.TrustSource != "OPERATOR_PROVISIONED" || v.InitialRootDigest != initialDigest || v.NetworkUsed || v.StoreUsed || v.StoreChanged || v.RollbackAgainstStoreChecked || v.ImportEligibility != "NOT_EVALUATED" || v.Purpose != "operator_provided" || len(v.RootHistory) != len(successors)+1 || v.RootHistory[0].Version != initial.Signed.Version || v.RootHistory[0].Digest != initialDigest || v.Root.Version != final.Signed.Version || receipt.PackageDigest != v.PackageDigest || receipt.TargetDigest != v.TargetDigest || receipt.KnowledgeRevision != v.KnowledgeRevision || receipt.CapabilityDigest != v.EngineCapabilityDigest {
		return false
	}
	for i, successor := range successors {
		if v.RootHistory[i+1].Version != successor.version || v.RootHistory[i+1].Digest != successor.digest {
			return false
		}
	}
	return true
}
