// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const maxStateFile = 1 << 20

func Import(req ImportRequest, admit AdmitFunc) (ImportReceipt, error) {
	return importWithRefTime(req, admit, time.Time{}, nil, nil)
}

// ImportConstraints imports the fixed generic CNCF target using the same
// offline TUF lifecycle as the legacy cert-manager profile.
func ImportConstraints(req ImportRequest) (ImportReceipt, error) {
	p := constraintsProfile()
	return importWithProfile(req, p, p.admit, time.Time{}, nil, nil)
}

// ImportSPIFFEX509SVID imports the isolated conformance-profile target.
func ImportSPIFFEX509SVID(req ImportRequest) (ImportReceipt, error) {
	p := spiffeX509SVIDProfile()
	return importWithProfile(req, p, p.admit, time.Time{}, nil, nil)
}

// ImportCloudEventsStructuredJSON imports the isolated conformance-profile target.
func ImportCloudEventsStructuredJSON(req ImportRequest) (ImportReceipt, error) {
	p := cloudEventsStructuredJSONProfile()
	return importWithProfile(req, p, p.admit, time.Time{}, nil, nil)
}

// ImportTiKVGCPV2WIFBackup imports the isolated target-preflight profile.
func ImportTiKVGCPV2WIFBackup(req ImportRequest) (ImportReceipt, error) {
	p := tikvGCPV2WIFBackupProfile()
	return importWithProfile(req, p, p.admit, time.Time{}, nil, nil)
}

func importAt(req ImportRequest, admit AdmitFunc, now time.Time) (ImportReceipt, error) {
	return importWithRefTime(req, admit, now, &now, nil)
}

type importTestHook func(stage string, store *storeFS) error

func importWithRefTime(req ImportRequest, admit AdmitFunc, now time.Time, testRefTime *time.Time, hook importTestHook) (ImportReceipt, error) {
	return importWithProfile(req, certManagerProfile(), admit, now, testRefTime, hook)
}

func importWithProfile(req ImportRequest, profile profileSpec, admit AdmitFunc, now time.Time, testRefTime *time.Time, hook importTestHook) (ImportReceipt, error) {
	if !profile.valid() || admit == nil || (testRefTime != nil && (now.IsZero() || now.Location() != time.UTC)) {
		return ImportReceipt{}, fmt.Errorf("import context: %w", ErrInvalid)
	}
	// Snapshot caller-owned assertion memory once so the digest and every later
	// comparison refer to the same immutable request within this transaction.
	if req.ExpectedVerification != nil {
		assertions := *req.ExpectedVerification
		assertions.RootHistory = append([]RootHistoryEntry(nil), req.ExpectedVerification.RootHistory...)
		req.ExpectedVerification = &assertions
	}
	// A pinned package is read and canonically parsed before opening the store.
	// Keep that exact in-memory package for the complete transaction so a
	// replacement at PackagePath cannot change what is admitted. Empty pins
	// retain the legacy ordering below.
	var pinnedPackage *importPackage
	if req.ExpectedPackageDigest != "" || req.ExpectedVerification != nil {
		if err := ValidateImportAssertions(req); err != nil {
			return ImportReceipt{}, err
		}
	}
	expectedVerificationDigest, err := verificationAssertionsDigest(req.ExpectedVerification)
	if err != nil {
		return ImportReceipt{}, err
	}
	if req.ExpectedPackageDigest != "" {
		expected, err := normalizeDigest(req.ExpectedPackageDigest)
		if err != nil {
			return ImportReceipt{}, fmt.Errorf("expected package digest: %w", err)
		}
		parsed, err := readImportPackageForProfile(req.PackagePath, profile)
		if err != nil {
			return ImportReceipt{}, err
		}
		if parsed.digest != expected {
			return ImportReceipt{}, fmt.Errorf("expected package digest: %w", ErrIntegrity)
		}
		pinnedPackage = &parsed
	}
	store, err := ensureStoreRoot(req.StoreRoot)
	if err != nil {
		return ImportReceipt{}, err
	}
	defer store.Close()
	lock, err := store.lock(5 * time.Second)
	if err != nil {
		return ImportReceipt{}, err
	}
	defer unlockStore(lock)
	if err := checkProfileMarker(store, profile, profile.marked()); err != nil {
		return ImportReceipt{}, err
	}
	if testRefTime == nil {
		now = time.Now().UTC()
	}

	prior, err := loadCurrentTrustForProfile(store, profile)
	if err != nil && !errors.Is(err, ErrNoSelection) {
		return ImportReceipt{}, err
	}
	pending, err := loadImportPending(store)
	if err != nil {
		return ImportReceipt{}, err
	}
	if _, floorReadErr := store.read("clock-floor.json", 4096); floorReadErr == nil {
		floor, parseErr := loadClockFloor(store)
		if parseErr != nil {
			return ImportReceipt{}, ErrIntegrity
		}
		if now.Before(floor) {
			return ImportReceipt{}, fmt.Errorf("verification clock rollback: %w", ErrRollback)
		}
	} else if !os.IsNotExist(floorReadErr) || prior != nil {
		return ImportReceipt{}, ErrIntegrity
	}
	var bootstrap []byte
	var initialDigest string
	if prior == nil {
		empty, checkErr := store.emptyForProfile(profile)
		if checkErr != nil {
			return ImportReceipt{}, checkErr
		}
		if !empty && (pending == nil || !store.pendingRecoveryShapeForProfile(profile)) {
			return ImportReceipt{}, fmt.Errorf("existing store missing trust pointer: %w", ErrIntegrity)
		}
		if req.BootstrapRootPath == "" || req.BootstrapRootDigest == "" {
			return ImportReceipt{}, fmt.Errorf("initial root and digest required: %w", ErrInvalid)
		}
		initialDigest, err = normalizeDigest(req.BootstrapRootDigest)
		if err != nil {
			return ImportReceipt{}, err
		}
		bootstrap, _, err = currentbundle.ReadBoundedFileInfo(req.BootstrapRootPath, 128<<10)
		if err != nil || digestBytes(bootstrap) != initialDigest {
			return ImportReceipt{}, fmt.Errorf("initial root admission: %w", ErrIntegrity)
		}
	} else {
		initialDigest = prior.state.InitialRootDigest
		if req.BootstrapRootPath != "" || req.BootstrapRootDigest != "" {
			if pending == nil {
				return ImportReceipt{}, fmt.Errorf("initial root already established: %w", ErrInvalid)
			}
			provided, e := normalizeDigest(req.BootstrapRootDigest)
			if e != nil || provided != initialDigest || req.BootstrapRootPath == "" {
				return ImportReceipt{}, ErrIntegrity
			}
			bootstrap, _, e = currentbundle.ReadBoundedFileInfo(req.BootstrapRootPath, 128<<10)
			if e != nil || digestBytes(bootstrap) != initialDigest {
				return ImportReceipt{}, ErrIntegrity
			}
		}
	}
	var pkg importPackage
	if pinnedPackage != nil {
		pkg = *pinnedPackage
	} else {
		pkg, err = readImportPackageForProfile(req.PackagePath, profile)
		if err != nil {
			return ImportReceipt{}, err
		}
	}
	if req.ExpectedRevision != "" {
		if _, e := parseRevision(req.ExpectedRevision); e != nil {
			return ImportReceipt{}, e
		}
	}
	if req.ExpectedBundleDigest != "" {
		normalized, e := normalizeDigest(req.ExpectedBundleDigest)
		if e != nil {
			return ImportReceipt{}, e
		}
		req.ExpectedBundleDigest = normalized
	}
	if pending != nil && prior != nil && pending.AcceptedTrustStateDigest == prior.stateDigest && pending.PackageDigest == pkg.digest && pending.InitialRootDigest == initialDigest && pending.ExpectedRevision == req.ExpectedRevision && pending.ExpectedBundleDigest == req.ExpectedBundleDigest && pending.ExpectedVerificationAssertionsDigest == expectedVerificationDigest {
		if selected, e := loadSelection(store); e == nil && selectionCommitted(store, selected, pending, profile, admit) {
			if e = runImportHook(hook, "before-completed-recovery-clear", store); e != nil {
				return durableFailureReceipt(store, pending, profile, admit, errors.Join(e, ErrRecoveryRequired))
			}
			if e = store.remove("import-pending.json"); e != nil {
				return durableFailureReceipt(store, pending, profile, admit, fmt.Errorf("clear completed import recovery: %w", ErrRecoveryRequired))
			}
			pending = nil
		}
	}
	priorDigest := ""
	if prior != nil {
		priorDigest = prior.stateDigest
	}
	priorSelection, e := selectionDigestForProfile(store, profile, admit)
	if e != nil {
		return ImportReceipt{}, e
	}
	transaction := importPending{PriorTrustStateDigest: priorDigest, PriorSelectionDigest: priorSelection, InitialRootDigest: initialDigest, PackageDigest: pkg.digest, ExpectedRevision: req.ExpectedRevision, ExpectedBundleDigest: req.ExpectedBundleDigest, ExpectedVerificationAssertionsDigest: expectedVerificationDigest, StartedAt: now.Format(time.RFC3339)}
	active, beginErr := beginImportTransaction(store, transaction)
	if beginErr != nil {
		return ImportReceipt{}, beginErr
	}
	if err = runImportHook(hook, "pending-published", store); err != nil {
		return ImportReceipt{}, err
	}
	started, e := parseTime(active.StartedAt)
	if e != nil || now.Before(started) {
		return ImportReceipt{}, fmt.Errorf("import recovery clock: %w", ErrRollback)
	}
	if err = persistClockFloor(store, now); err != nil {
		return ImportReceipt{}, err
	}
	refTime := &now
	verified, err := verifyPackageForProfile(pkg, profile, prior, bootstrap, initialDigest, refTime, func(name string) error {
		if name == "metadata/timestamp.json" {
			return runImportHook(hook, "refresh-timestamp-fetch", store)
		}
		return nil
	})
	if err != nil {
		return ImportReceipt{}, err
	}
	if err = runImportHook(hook, "refresh-returned", store); err != nil {
		return ImportReceipt{}, err
	}
	failureReceipt := func(cause error) (ImportReceipt, error) {
		return durableFailureReceipt(store, active, profile, admit, cause)
	}
	finish := func(receipt ImportReceipt, result error) (ImportReceipt, error) {
		if finishErr := runImportHook(hook, "before-pending-clear", store); finishErr != nil {
			return failureReceipt(errors.Join(result, finishErr))
		}
		if finishErr := store.remove("import-pending.json"); finishErr != nil {
			return failureReceipt(errors.Join(result, fmt.Errorf("clear completed import recovery: %w", ErrRecoveryRequired)))
		}
		return receipt, result
	}
	stateRawBeforeAdmission, err := marshalCanonical(verified.material.state)
	if err != nil {
		return ImportReceipt{}, err
	}
	verified.material.stateDigest = digestBytes(stateRawBeforeAdmission)
	trustChanged, err := persistTrustMaterial(store, verified.material, now, func(stage string) error {
		return runImportHook(hook, "metadata-"+stage, store)
	})
	if err != nil {
		return failureReceipt(err)
	}
	if err = runImportHook(hook, "trust-pointer-published", store); err != nil {
		return failureReceipt(err)
	}
	rejected := ImportReceipt{APIVersion: "prufyx.io/knowledge-import-receipt/v1", Status: "REJECTED", TrustStateAdvanced: trustChanged, SelectionChanged: false, TrustStateDigest: verified.material.stateDigest}
	if verified.refreshErr != nil {
		return finish(rejected, classifyTUFError(verified.refreshErr))
	}
	if err := ensureAllPackageMembersUsed(pkg, verified.served, &verified.material); err != nil {
		return finish(rejected, err)
	}
	if req.ExpectedVerification != nil && !verificationTrustMatches(req.ExpectedVerification, verified.material.state) {
		return finish(rejected, fmt.Errorf("expected verified trust identity: %w", ErrIntegrity))
	}
	bundleDigest := digestBytes(verified.target)
	if req.ExpectedBundleDigest != "" {
		expected, err := normalizeDigest(req.ExpectedBundleDigest)
		if err != nil || expected != bundleDigest {
			return finish(rejected, fmt.Errorf("expected bundle digest: %w", ErrIntegrity))
		}
		req.ExpectedBundleDigest = expected
	}
	admission, err := admit(append([]byte(nil), verified.target...))
	if err != nil {
		return finish(rejected, fmt.Errorf("semantic admission: %w", err))
	}
	if err := validateAdmissionForProfile(admission, profile); err != nil {
		return finish(rejected, err)
	}
	if req.ExpectedRevision != "" && req.ExpectedRevision != admission.Revision {
		return finish(rejected, fmt.Errorf("expected revision: %w", ErrIntegrity))
	}
	if req.ExpectedVerification != nil && !verificationAdmissionMatches(req.ExpectedVerification, profile.targetPath, admission) {
		return finish(rejected, fmt.Errorf("expected verified target identity: %w", ErrIntegrity))
	}
	previousFloor := verified.material.state.RevisionFloor
	if err := enforceRevisionFloor(previousFloor, verified.material.state.RevisionFloorBundleDigest, admission.Revision, bundleDigest); err != nil {
		return finish(rejected, err)
	}
	verified.material.state.RevisionFloor = admission.Revision
	verified.material.state.RevisionFloorBundleDigest = bundleDigest
	stateRaw, _ := marshalCanonical(verified.material.state)
	verified.material.stateDigest = digestBytes(stateRaw)
	trustChangedAfterAdmission, err := persistTrustMaterial(store, verified.material, now, func(stage string) error {
		return runImportHook(hook, "floor-"+stage, store)
	})
	if err != nil {
		return failureReceipt(err)
	}
	trustChanged = trustChanged || trustChangedAfterAdmission
	if err = runImportHook(hook, "revision-floor-pointer-published", store); err != nil {
		return failureReceipt(err)
	}
	rejected.TrustStateAdvanced = trustChanged
	rejected.TrustStateDigest = verified.material.stateDigest
	if existing, loadErr := loadSelection(store); loadErr == nil && existing.Revision == admission.Revision && existing.BundleDigest == bundleDigest && existing.TrustStateDigest == verified.material.stateDigest {
		rel := admissionRelative(existing.BundleDigest, existing.TrustReceiptDigest)
		target, targetErr := store.read(rel+"/target.json", maxPackageEntry)
		receiptRaw, receiptErr := store.read(rel+"/trust-receipt.json", maxStateFile)
		var old TrustReceipt
		validExisting := targetErr == nil && receiptErr == nil && digestBytes(target) == bundleDigest && digestBytes(receiptRaw) == existing.TrustReceiptDigest && decodeCanonicalStrict(receiptRaw, &old) == nil && validateTrustReceiptForProfile(old, existing, &verified.material, int64(len(target)), profile) == nil && admissionMatchesReceipt(admission, old)
		if !validExisting {
			return rejected, ErrIntegrity
		}
		if expectedVerificationDigest == "" || old.ExpectedVerificationAssertionsDigest == expectedVerificationDigest {
			return finish(ImportReceipt{APIVersion: "prufyx.io/knowledge-import-receipt/v1", Status: "IMPORTED", TrustStateAdvanced: trustChanged, SelectionChanged: false, TrustStateDigest: verified.material.stateDigest, TrustReceipt: old, TrustReceiptDigest: existing.TrustReceiptDigest, AdmissionPath: rel}, nil)
		}
		// A valid manual v1 admission does not claim it checked a later release
		// plan. Fall through after re-verifying this request and mint a v2
		// receipt bound to the exact assertions instead of invalidating the old
		// admission or reusing it with a false verification claim.
	}
	receiptVersion := trustReceiptV1
	if expectedVerificationDigest != "" {
		receiptVersion = trustReceiptV2
	}
	receipt := TrustReceipt{
		APIVersion: receiptVersion, TrustSource: "OPERATOR_PROVISIONED",
		VerifiedAt: verified.verifiedAt.Format(time.RFC3339), InitialRootDigest: verified.material.state.InitialRootDigest,
		RootHistory: append([]RootHistoryEntry(nil), verified.material.state.RootHistory...), Root: verified.material.state.Root,
		Timestamp: verified.material.state.Timestamp, Snapshot: verified.material.state.Snapshot, Targets: verified.material.state.Targets,
		TargetPath: profile.targetPath, TargetLength: int64(len(verified.target)), TargetDigest: bundleDigest,
		KnowledgeRevision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule,
		RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt,
		ExpectedRevision: req.ExpectedRevision, ExpectedBundleDigest: req.ExpectedBundleDigest,
		ExpectedVerificationAssertionsDigest: expectedVerificationDigest,
	}
	receiptRaw, err := marshalCanonical(receipt)
	if err != nil {
		return failureReceipt(err)
	}
	receiptDigest := digestBytes(receiptRaw)
	relative := filepath.Join("admissions", strings.TrimPrefix(bundleDigest, "sha256:"), strings.TrimPrefix(receiptDigest, "sha256:"))
	if err := persistAdmission(store, filepath.ToSlash(relative), verified.target, receiptRaw, verified.material.stateDigest); err != nil {
		return failureReceipt(err)
	}
	if err = runImportHook(hook, "admission-published", store); err != nil {
		return failureReceipt(err)
	}
	selection := selectionPointer{APIVersion: selectionAPIVersion, Revision: admission.Revision, BundleDigest: bundleDigest, TrustReceiptDigest: receiptDigest, TrustStateDigest: verified.material.stateDigest}
	selectionRaw, _ := marshalCanonical(selection)
	if err := store.write("selection.json", selectionRaw, false); err != nil {
		return failureReceipt(err)
	}
	if err = runImportHook(hook, "selection-published", store); err != nil {
		return failureReceipt(err)
	}
	return finish(ImportReceipt{APIVersion: "prufyx.io/knowledge-import-receipt/v1", Status: "IMPORTED", TrustStateAdvanced: trustChanged, SelectionChanged: true, TrustStateDigest: verified.material.stateDigest, TrustReceipt: receipt, TrustReceiptDigest: receiptDigest, AdmissionPath: filepath.ToSlash(relative)}, nil)
}

func durableFailureReceipt(store *storeFS, active *importPending, profile profileSpec, admit AdmitFunc, cause error) (ImportReceipt, error) {
	cause = errors.Join(cause, ErrRecoveryRequired)
	current, err := loadCurrentTrustForProfile(store, profile)
	if err != nil {
		if errors.Is(err, ErrNoSelection) && active.PriorTrustStateDigest == "" {
			return ImportReceipt{}, cause
		}
		return ImportReceipt{}, errors.Join(cause, fmt.Errorf("read durable trust outcome: %w", ErrIntegrity))
	}
	selectedDigest, err := selectionDigestForProfile(store, profile, admit)
	if err != nil || selectedDigest == "" && active.PriorSelectionDigest != "" {
		return ImportReceipt{}, errors.Join(cause, fmt.Errorf("read durable selection outcome: %w", ErrIntegrity))
	}
	return ImportReceipt{
		APIVersion: "prufyx.io/knowledge-import-receipt/v1", Status: "REJECTED",
		TrustStateAdvanced: current.stateDigest != active.PriorTrustStateDigest,
		SelectionChanged:   selectedDigest != active.PriorSelectionDigest,
		TrustStateDigest:   current.stateDigest,
	}, cause
}

func runImportHook(hook importTestHook, stage string, store *storeFS) error {
	if hook == nil {
		return nil
	}
	return hook(stage, store)
}

func selectionCommitted(store *storeFS, selected selectionPointer, pending *importPending, profile profileSpec, admit AdmitFunc) bool {
	if pending == nil || admit == nil || selected.TrustStateDigest != pending.AcceptedTrustStateDigest || pending.ExpectedRevision != "" && selected.Revision != pending.ExpectedRevision || pending.ExpectedBundleDigest != "" && selected.BundleDigest != pending.ExpectedBundleDigest {
		return false
	}
	if validateStoredSelection(store, selected, profile, admit) != nil {
		return false
	}
	if pending.ExpectedVerificationAssertionsDigest == "" {
		return true
	}
	rel := admissionRelative(selected.BundleDigest, selected.TrustReceiptDigest)
	receiptRaw, err := store.read(rel+"/trust-receipt.json", maxStateFile)
	var receipt TrustReceipt
	return err == nil && decodeCanonicalStrict(receiptRaw, &receipt) == nil && receipt.APIVersion == trustReceiptV2 && receipt.ExpectedVerificationAssertionsDigest == pending.ExpectedVerificationAssertionsDigest
}

func validateStoredSelection(store *storeFS, selected selectionPointer, profile profileSpec, admit AdmitFunc) error {
	if admit == nil {
		return ErrIntegrity
	}
	material, err := loadTrustByDigestForProfile(store, selected.TrustStateDigest, profile)
	if err != nil {
		return ErrIntegrity
	}
	rel := admissionRelative(selected.BundleDigest, selected.TrustReceiptDigest)
	target, targetErr := store.read(rel+"/target.json", maxPackageEntry)
	receiptRaw, receiptErr := store.read(rel+"/trust-receipt.json", maxStateFile)
	binding, bindingErr := loadDigestPointer(store, rel+"/trust-state.json")
	var receipt TrustReceipt
	if targetErr != nil || receiptErr != nil || bindingErr != nil || binding != selected.TrustStateDigest || digestBytes(target) != selected.BundleDigest || digestBytes(receiptRaw) != selected.TrustReceiptDigest || decodeCanonicalStrict(receiptRaw, &receipt) != nil || validateTrustReceiptForProfile(receipt, selected, material, int64(len(target)), profile) != nil {
		return ErrIntegrity
	}
	verifiedAt, err := parseTime(receipt.VerifiedAt)
	if err != nil {
		return ErrIntegrity
	}
	verified, err := verifyPackageForProfile(packageFromStoredForProfile(material, target, selected.BundleDigest, profile), profile, material, nil, "", &verifiedAt, nil)
	if err != nil || verified.refreshErr != nil || digestBytes(verified.target) != selected.BundleDigest || verified.material.stateDigest != selected.TrustStateDigest {
		return ErrIntegrity
	}
	admission, err := admit(append([]byte(nil), target...))
	if err != nil || validateAdmissionForProfile(admission, profile) != nil || !admissionMatchesReceipt(admission, receipt) || receipt.TargetPath != profile.targetPath {
		return ErrIntegrity
	}
	return nil
}

func validateAdmission(a Admission) error {
	if _, err := parseRevision(a.Revision); err != nil {
		return fmt.Errorf("admission revision: %w", err)
	}
	if a.Purpose != "synthetic_test_only" && a.Purpose != "operator_provided" {
		return fmt.Errorf("admission purpose: %w", ErrInvalid)
	}
	for _, value := range []string{a.EngineCapabilityDigest} {
		if normalized, err := normalizeDigest(value); err != nil || normalized != value {
			return fmt.Errorf("admission digest: %w", ErrInvalid)
		}
	}
	if a.HasRule {
		if normalized, err := normalizeDigest(a.RuleDigest); err != nil || normalized != a.RuleDigest {
			return fmt.Errorf("admission rule digest: %w", ErrInvalid)
		}
		if _, err := parseTime(a.EvidenceExpiresAt); err != nil {
			return fmt.Errorf("evidence expiry: %w", err)
		}
	} else if a.RuleDigest != "" || a.EvidenceExpiresAt != "" {
		return fmt.Errorf("empty coverage fields: %w", ErrInvalid)
	}
	return nil
}

func validateAdmissionForProfile(a Admission, profile profileSpec) error {
	if !profile.valid() || validateAdmission(a) != nil {
		return ErrIntegrity
	}
	return nil
}

func enforceRevisionFloor(floor, floorDigest, next, digest string) error {
	n, _ := parseRevision(next)
	if floor == "" {
		return nil
	}
	f, err := parseRevision(floor)
	if err != nil {
		return ErrIntegrity
	}
	if n < f {
		return ErrRollback
	}
	if n == f {
		if floorDigest != digest {
			return ErrRollback
		}
	}
	return nil
}
