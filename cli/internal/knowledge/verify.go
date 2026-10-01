// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

// Verify authenticates and semantically validates one package against an
// explicit bootstrap root without opening or mutating a knowledge store.
func Verify(req VerifyRequest, admit AdmitFunc) (PackageVerificationReceipt, error) {
	return verifyForProfile(req, certManagerProfile(), admit)
}

// VerifyConstraints verifies the fixed generic CNCF target and schema.
func VerifyConstraints(req VerifyRequest) (PackageVerificationReceipt, error) {
	p := constraintsProfile()
	return verifyForProfile(req, p, p.admit)
}

// VerifySPIFFEX509SVID verifies the isolated conformance-profile target.
func VerifySPIFFEX509SVID(req VerifyRequest) (PackageVerificationReceipt, error) {
	p := spiffeX509SVIDProfile()
	return verifyForProfile(req, p, p.admit)
}

// VerifyCloudEventsStructuredJSON verifies the isolated conformance-profile target.
func VerifyCloudEventsStructuredJSON(req VerifyRequest) (PackageVerificationReceipt, error) {
	p := cloudEventsStructuredJSONProfile()
	return verifyForProfile(req, p, p.admit)
}

// VerifyTiKVGCPV2WIFBackup verifies the isolated target-preflight profile.
func VerifyTiKVGCPV2WIFBackup(req VerifyRequest) (PackageVerificationReceipt, error) {
	p := tikvGCPV2WIFBackupProfile()
	return verifyForProfile(req, p, p.admit)
}

func verifyForProfile(req VerifyRequest, profile profileSpec, admit AdmitFunc) (PackageVerificationReceipt, error) {
	if !profile.valid() || admit == nil || req.PackagePath == "" || req.BootstrapRootPath == "" || req.BootstrapRootDigest == "" {
		return PackageVerificationReceipt{}, fmt.Errorf("verification context: %w", ErrInvalid)
	}
	assertions := ImportRequest{
		BootstrapRootPath: req.BootstrapRootPath, BootstrapRootDigest: req.BootstrapRootDigest,
		ExpectedPackageDigest: req.ExpectedPackageDigest, ExpectedRevision: req.ExpectedRevision,
		ExpectedBundleDigest: req.ExpectedBundleDigest,
	}
	if err := ValidateImportAssertions(assertions); err != nil {
		return PackageVerificationReceipt{}, err
	}
	initialDigest, err := normalizeDigest(req.BootstrapRootDigest)
	if err != nil {
		return PackageVerificationReceipt{}, err
	}
	bootstrap, info, err := currentbundle.ReadBoundedFileInfo(req.BootstrapRootPath, 128<<10)
	if err != nil || info == nil || !info.Mode().IsRegular() || digestBytes(bootstrap) != initialDigest {
		return PackageVerificationReceipt{}, fmt.Errorf("bootstrap root admission: %w", ErrIntegrity)
	}
	pkg, err := readImportPackageForProfile(req.PackagePath, profile)
	if err != nil {
		return PackageVerificationReceipt{}, err
	}
	if req.ExpectedPackageDigest != "" {
		expected, normalizeErr := normalizeDigest(req.ExpectedPackageDigest)
		if normalizeErr != nil || expected != pkg.digest {
			return PackageVerificationReceipt{}, fmt.Errorf("expected package digest: %w", ErrIntegrity)
		}
		req.ExpectedPackageDigest = expected
	}
	if req.ExpectedBundleDigest != "" {
		expected, normalizeErr := normalizeDigest(req.ExpectedBundleDigest)
		if normalizeErr != nil {
			return PackageVerificationReceipt{}, normalizeErr
		}
		req.ExpectedBundleDigest = expected
	}
	verified, err := verifyPackageForProfile(pkg, profile, nil, bootstrap, initialDigest, nil, nil)
	if err != nil {
		return PackageVerificationReceipt{}, err
	}
	if verified.refreshErr != nil {
		return PackageVerificationReceipt{}, classifyTUFError(verified.refreshErr)
	}
	if err := ensureAllPackageMembersUsed(pkg, verified.served, &verified.material); err != nil {
		return PackageVerificationReceipt{}, err
	}
	targetDigest := digestBytes(verified.target)
	if req.ExpectedBundleDigest != "" && req.ExpectedBundleDigest != targetDigest {
		return PackageVerificationReceipt{}, fmt.Errorf("expected bundle digest: %w", ErrIntegrity)
	}
	admission, err := admit(append([]byte(nil), verified.target...))
	if err != nil {
		return PackageVerificationReceipt{}, fmt.Errorf("semantic admission: %w", err)
	}
	if err := validateAdmissionForProfile(admission, profile); err != nil {
		return PackageVerificationReceipt{}, err
	}
	if req.ExpectedRevision != "" && req.ExpectedRevision != admission.Revision {
		return PackageVerificationReceipt{}, fmt.Errorf("expected revision: %w", ErrIntegrity)
	}
	profileName := profile.cliName
	state := verified.material.state
	return PackageVerificationReceipt{
		APIVersion: "prufyx.io/knowledge-package-verification/v1", Status: "VERIFIED", Profile: profileName,
		VerifiedAt: verified.verifiedAt.Format(time.RFC3339), TrustSource: "OPERATOR_PROVISIONED",
		InitialRootDigest: initialDigest, RootHistory: append([]RootHistoryEntry(nil), state.RootHistory...),
		Root: state.Root, Timestamp: state.Timestamp, Snapshot: state.Snapshot, Targets: state.Targets,
		PackageDigest: pkg.digest, TargetPath: profile.targetPath, TargetLength: int64(len(verified.target)), TargetDigest: targetDigest,
		KnowledgeRevision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest,
		HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt,
		ExpectedPackageDigest: req.ExpectedPackageDigest, ExpectedRevision: req.ExpectedRevision, ExpectedBundleDigest: req.ExpectedBundleDigest,
		NetworkUsed: false, StoreUsed: false, StoreChanged: false, RollbackAgainstStoreChecked: false, ImportEligibility: "NOT_EVALUATED",
	}, nil
}
