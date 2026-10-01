// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"
)

const genericIntegrityNextAction = "inspect store integrity; use a matching CLI capability, or provision a separate store with an independently verified bootstrap; preserve the old store"

func OpenSelected(req SelectionRequest, admit AdmitFunc) (VerifiedRevision, error) {
	return openRevision(req, certManagerProfile(), time.Time{}, SelectionCurrent, admit)
}

// OpenSelectedConstraints opens the selected fixed generic CNCF revision.
func OpenSelectedConstraints(req SelectionRequest) (VerifiedRevision, error) {
	p := constraintsProfile()
	return openRevision(req, p, time.Time{}, SelectionCurrent, p.admit)
}

// OpenSelectedSPIFFEX509SVID opens the selected isolated conformance profile.
func OpenSelectedSPIFFEX509SVID(req SelectionRequest) (VerifiedRevision, error) {
	p := spiffeX509SVIDProfile()
	return openRevision(req, p, time.Time{}, SelectionCurrent, p.admit)
}

// OpenSelectedCloudEventsStructuredJSON opens the selected isolated conformance profile.
func OpenSelectedCloudEventsStructuredJSON(req SelectionRequest) (VerifiedRevision, error) {
	p := cloudEventsStructuredJSONProfile()
	return openRevision(req, p, time.Time{}, SelectionCurrent, p.admit)
}

// OpenSelectedTiKVGCPV2WIFBackup opens the selected isolated target-preflight profile.
func OpenSelectedTiKVGCPV2WIFBackup(req SelectionRequest) (VerifiedRevision, error) {
	p := tikvGCPV2WIFBackupProfile()
	return openRevision(req, p, time.Time{}, SelectionCurrent, p.admit)
}

func OpenHistorical(req SelectionRequest, evaluatedAt time.Time, admit AdmitFunc) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	return openRevision(req, certManagerProfile(), evaluatedAt, SelectionHistorical, admit)
}

// OpenHistoricalConstraints revalidates an exact historical generic revision.
func OpenHistoricalConstraints(req SelectionRequest, evaluatedAt time.Time) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	p := constraintsProfile()
	return openRevision(req, p, evaluatedAt, SelectionHistorical, p.admit)
}

// OpenHistoricalSPIFFEX509SVID revalidates one exact saved profile revision.
func OpenHistoricalSPIFFEX509SVID(req SelectionRequest, evaluatedAt time.Time) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	p := spiffeX509SVIDProfile()
	return openRevision(req, p, evaluatedAt, SelectionHistorical, p.admit)
}

// OpenHistoricalCloudEventsStructuredJSON revalidates one exact saved profile revision.
func OpenHistoricalCloudEventsStructuredJSON(req SelectionRequest, evaluatedAt time.Time) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	p := cloudEventsStructuredJSONProfile()
	return openRevision(req, p, evaluatedAt, SelectionHistorical, p.admit)
}

// OpenHistoricalTiKVGCPV2WIFBackup revalidates one exact saved profile revision.
func OpenHistoricalTiKVGCPV2WIFBackup(req SelectionRequest, evaluatedAt time.Time) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	p := tikvGCPV2WIFBackupProfile()
	return openRevision(req, p, evaluatedAt, SelectionHistorical, p.admit)
}

func openRevision(req SelectionRequest, profile profileSpec, evaluatedAt time.Time, mode SelectionMode, admit AdmitFunc) (VerifiedRevision, error) {
	if !profile.valid() || admit == nil {
		return VerifiedRevision{}, ErrInvalid
	}
	store, err := ensureStoreRoot(req.StoreRoot)
	if err != nil {
		return VerifiedRevision{}, err
	}
	defer store.Close()
	lock, err := store.lock(5 * time.Second)
	if err != nil {
		return VerifiedRevision{}, err
	}
	defer unlockStore(lock)
	if err := checkProfileMarker(store, profile, false); err != nil {
		return VerifiedRevision{}, err
	}
	actualNow := time.Now().UTC()
	if mode == SelectionCurrent {
		evaluatedAt = actualNow
		pending, e := loadImportPending(store)
		if e != nil {
			return VerifiedRevision{}, e
		}
		if pending != nil {
			return VerifiedRevision{}, ErrRecoveryRequired
		}
	} else if evaluatedAt.After(actualNow) {
		return VerifiedRevision{}, fmt.Errorf("historical evaluation time is in the future: %w", ErrInvalid)
	}
	var selection selectionPointer
	if mode == SelectionHistorical {
		bundle, e := normalizeDigest(req.ExpectedBundleDigest)
		if e != nil {
			return VerifiedRevision{}, ErrInvalid
		}
		receipt, e := normalizeDigest(req.ExpectedTrustReceiptDigest)
		if e != nil {
			return VerifiedRevision{}, ErrInvalid
		}
		if _, e = parseRevision(req.ExpectedRevision); e != nil {
			return VerifiedRevision{}, ErrInvalid
		}
		selection = selectionPointer{APIVersion: selectionAPIVersion, Revision: req.ExpectedRevision, BundleDigest: bundle, TrustReceiptDigest: receipt}
		binding, e := loadDigestPointer(store, admissionRelative(bundle, receipt)+"/trust-state.json")
		if e != nil {
			return VerifiedRevision{}, ErrIntegrity
		}
		selection.TrustStateDigest = binding
	} else {
		selection, err = loadSelection(store)
		if err != nil {
			return VerifiedRevision{}, err
		}
		if err = assertSelection(selection, req, mode); err != nil {
			return VerifiedRevision{}, err
		}
		current, e := loadCurrentTrustForProfile(store, profile)
		if e != nil {
			return VerifiedRevision{}, fmt.Errorf("current trust state: %w", e)
		}
		if current.stateDigest != selection.TrustStateDigest {
			return VerifiedRevision{}, ErrTrustAdvanced
		}
	}
	selectedState, err := loadTrustByDigestForProfile(store, selection.TrustStateDigest, profile)
	if err != nil {
		return VerifiedRevision{}, fmt.Errorf("selected trust state: %w", err)
	}
	if mode == SelectionCurrent {
		floor, e := loadClockFloor(store)
		if e != nil {
			return VerifiedRevision{}, e
		}
		if evaluatedAt.Before(floor) {
			return VerifiedRevision{}, fmt.Errorf("current check clock rollback: %w", ErrRollback)
		}
	}
	rel := admissionRelative(selection.BundleDigest, selection.TrustReceiptDigest)
	target, err := store.read(rel+"/target.json", maxPackageEntry)
	if err != nil || digestBytes(target) != selection.BundleDigest {
		return VerifiedRevision{}, ErrIntegrity
	}
	receiptRaw, err := store.read(rel+"/trust-receipt.json", maxStateFile)
	if err != nil || digestBytes(receiptRaw) != selection.TrustReceiptDigest {
		return VerifiedRevision{}, ErrIntegrity
	}
	var receipt TrustReceipt
	if decodeCanonicalStrict(receiptRaw, &receipt) != nil || validateTrustReceiptForProfile(receipt, selection, selectedState, int64(len(target)), profile) != nil {
		return VerifiedRevision{}, ErrIntegrity
	}
	receiptVerifiedAt, err := parseTime(receipt.VerifiedAt)
	if err != nil || evaluatedAt.Before(receiptVerifiedAt) {
		return VerifiedRevision{}, fmt.Errorf("evaluation precedes knowledge admission: %w", ErrRollback)
	}
	binding, err := loadDigestPointer(store, rel+"/trust-state.json")
	if err != nil || binding != selection.TrustStateDigest {
		return VerifiedRevision{}, ErrIntegrity
	}
	admission, err := admit(append([]byte(nil), target...))
	if err != nil || validateAdmissionForProfile(admission, profile) != nil || !admissionMatchesReceipt(admission, receipt) {
		return VerifiedRevision{}, ErrIntegrity
	}
	pkg := packageFromStoredForProfile(selectedState, target, selection.BundleDigest, profile)
	ref := &evaluatedAt
	verified, err := verifyPackageForProfile(pkg, profile, selectedState, nil, "", ref, nil)
	if err != nil {
		return VerifiedRevision{}, err
	}
	if verified.refreshErr != nil {
		return VerifiedRevision{}, classifyTUFError(verified.refreshErr)
	}
	if digestBytes(verified.target) != selection.BundleDigest || verified.material.stateDigest != selection.TrustStateDigest {
		return VerifiedRevision{}, fmt.Errorf("revalidated trust state: %w", ErrIntegrity)
	}
	v := VerifiedRevision{bytes: append([]byte(nil), target...), revision: selection.Revision, bundleDigest: selection.BundleDigest, trustReceipt: receipt, trustReceiptDigest: selection.TrustReceiptDigest, verifiedAt: evaluatedAt, mode: mode, profile: profile.id, seal: &verifiedSeal{}}
	if !v.Valid() {
		return VerifiedRevision{}, ErrIntegrity
	}
	if mode == SelectionCurrent {
		if err := persistClockFloor(store, evaluatedAt); err != nil {
			return VerifiedRevision{}, err
		}
	}
	return v, nil
}

func Inspect(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, certManagerProfile())
}

// InspectConstraints reports the fixed generic CNCF store without creating a
// profile marker from a read path.
func InspectConstraints(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, constraintsProfile())
}

// InspectSPIFFEX509SVID reports the isolated conformance store.
func InspectSPIFFEX509SVID(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, spiffeX509SVIDProfile())
}

// InspectCloudEventsStructuredJSON reports the isolated conformance store.
func InspectCloudEventsStructuredJSON(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, cloudEventsStructuredJSONProfile())
}

// InspectTiKVGCPV2WIFBackup reports the isolated target-preflight store.
func InspectTiKVGCPV2WIFBackup(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, tikvGCPV2WIFBackupProfile())
}

func inspectProfile(storeRoot string, profile profileSpec) (Status, error) {
	if !profile.valid() {
		return Status{}, ErrIntegrity
	}
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		return Status{}, err
	}
	defer store.Close()
	lock, err := store.lock(5 * time.Second)
	if err != nil {
		return Status{}, err
	}
	defer unlockStore(lock)
	now := time.Now().UTC()
	if err := checkProfileMarker(store, profile, false); err != nil {
		if profile.marked() && errors.Is(err, ErrNoSelection) {
			return Status{APIVersion: "prufyx.io/knowledge-status/v1", State: "NO_SELECTION", Reason: "no operator trust root or knowledge revision is established", NextAction: "import a signed package with an explicit bootstrap root", CheckedAt: now.Format(time.RFC3339), TrustSource: "none", CurrentEligible: false, Freshness: "not_established", TrustFreshness: "not_established", SourceEvidenceFreshness: "not_established", NetworkChecked: false, CurrentNonRevocation: "not_checked_offline"}, nil
		}
		return Status{}, err
	}
	pending, pendingErr := loadImportPending(store)
	if pendingErr != nil {
		return Status{}, pendingErr
	}
	material, err := loadCurrentTrustForProfile(store, profile)
	if err != nil {
		if errors.Is(err, ErrNoSelection) {
			if pending != nil {
				return Status{APIVersion: "prufyx.io/knowledge-status/v1", State: "RECOVERY_REQUIRED", Reason: "an interrupted knowledge import must be resumed", NextAction: "retry the exact same signed package and bootstrap root", CheckedAt: now.Format(time.RFC3339), TrustSource: "none", CurrentEligible: false, Freshness: "not_established", TrustFreshness: "not_established", SourceEvidenceFreshness: "not_established", NetworkChecked: false, CurrentNonRevocation: "not_checked_offline"}, nil
			}
			empty, checkErr := store.emptyForProfile(profile)
			if checkErr != nil || !empty {
				return Status{}, ErrIntegrity
			}
			return Status{APIVersion: "prufyx.io/knowledge-status/v1", State: "NO_SELECTION", Reason: "no operator trust root or knowledge revision is established", NextAction: "import a signed package with an explicit bootstrap root", CheckedAt: now.Format(time.RFC3339), TrustSource: "none", CurrentEligible: false, Freshness: "not_established", TrustFreshness: "not_established", SourceEvidenceFreshness: "not_established", NetworkChecked: false, CurrentNonRevocation: "not_checked_offline"}, nil
		}
		return Status{}, err
	}
	floor, err := loadClockFloor(store)
	if err != nil {
		return Status{}, err
	}
	if now.Before(floor) {
		return Status{}, fmt.Errorf("status clock rollback: %w", ErrRollback)
	}
	s := Status{APIVersion: "prufyx.io/knowledge-status/v1", State: "NO_SELECTION", Reason: "no verified knowledge revision is selected", NextAction: "import a valid signed knowledge package", CheckedAt: now.Format(time.RFC3339), TrustSource: "OPERATOR_PROVISIONED", TrustStateDigest: material.stateDigest, RootVersion: material.state.Root.Version, TimestampVersion: material.state.Timestamp.Version, SnapshotVersion: material.state.Snapshot.Version, TargetsVersion: material.state.Targets.Version, NetworkChecked: false, CurrentNonRevocation: "not_checked_offline", Freshness: "fresh", TrustFreshness: "fresh", SourceEvidenceFreshness: "not_assessed"}
	for _, role := range []RoleReceipt{material.state.Root, material.state.Timestamp, material.state.Snapshot, material.state.Targets} {
		if role.Version == 0 {
			continue
		}
		expiry, e := parseTime(role.Expires)
		if e != nil {
			return Status{}, ErrIntegrity
		}
		if !now.Before(expiry) {
			s.Freshness = "expired"
		}
	}
	selection, e := loadSelection(store)
	if e == nil {
		s.SelectedRevision = selection.Revision
		s.SelectedBundleDigest = selection.BundleDigest
		s.TrustReceiptDigest = selection.TrustReceiptDigest
		integrityOK := false
		selectedMaterial, selectedMaterialErr := loadTrustByDigestForProfile(store, selection.TrustStateDigest, profile)
		rel := admissionRelative(selection.BundleDigest, selection.TrustReceiptDigest)
		if raw, x := store.read(rel+"/trust-receipt.json", maxStateFile); x == nil {
			var receipt TrustReceipt
			target, targetErr := store.read(rel+"/target.json", maxPackageEntry)
			binding, bindingErr := loadDigestPointer(store, rel+"/trust-state.json")
			if selectedMaterialErr == nil && decodeCanonicalStrict(raw, &receipt) == nil && digestBytes(raw) == selection.TrustReceiptDigest && targetErr == nil && digestBytes(target) == selection.BundleDigest && bindingErr == nil && binding == selection.TrustStateDigest && validateTrustReceiptForProfile(receipt, selection, selectedMaterial, int64(len(target)), profile) == nil {
				s.Purpose = receipt.Purpose
				admissionOK := true
				if profile.admit != nil {
					admitted, admissionErr := profile.admit(append([]byte(nil), target...))
					admissionOK = admissionErr == nil && validateAdmissionForProfile(admitted, profile) == nil && admissionMatchesReceipt(admitted, receipt)
				}
				if admissionOK {
					verified, verifyErr := verifyPackageForProfile(packageFromStoredForProfile(selectedMaterial, target, selection.BundleDigest, profile), profile, selectedMaterial, nil, "", &now, nil)
					stateMatches := verifyErr == nil && verified.material.stateDigest == selectedMaterial.stateDigest
					if stateMatches && verified.refreshErr == nil && digestBytes(verified.target) == selection.BundleDigest {
						integrityOK = true
					} else if stateMatches && errors.Is(classifyTUFError(verified.refreshErr), ErrExpired) {
						integrityOK = true
						s.Freshness = "expired"
					}
					if stateMatches && (verified.refreshErr == nil || errors.Is(classifyTUFError(verified.refreshErr), ErrExpired)) {
						projectSourceEvidenceFreshness(&s, receipt, now)
					}
				}
			}
		}
		s.CurrentEligible = integrityOK && selection.TrustStateDigest == material.stateDigest && s.Freshness == "fresh"
		if !integrityOK {
			s.SourceEvidenceFreshness = "not_assessed"
			s.SourceEvidenceExpiresAt = ""
			s.Freshness = "integrity_failure"
			s.State = "INTEGRITY_FAILURE"
			s.Reason = "selected knowledge admission failed integrity checks"
			if profile.marked() {
				s.NextAction = genericIntegrityNextAction
			} else {
				s.NextAction = "inspect the store and re-import a valid signed package"
			}
		} else if selection.TrustStateDigest != material.stateDigest {
			s.State = "TRUST_ADVANCED"
			s.Reason = "trusted metadata advanced beyond the selected revision"
			s.NextAction = "import a valid package matching the current trusted metadata"
		} else if s.Freshness == "expired" {
			s.State = "EXPIRED"
			s.Reason = "trusted metadata is expired at the current local time"
			s.NextAction = "provision and import a fresh signed package"
		} else {
			s.State = "READY"
			s.Reason = "selected revision is verified for current offline use"
			s.NextAction = "none"
		}
	} else if !errors.Is(e, ErrNoSelection) {
		return Status{}, e
	}
	if err := persistClockFloor(store, now); err != nil {
		return Status{}, err
	}
	if pending != nil {
		s.State = "RECOVERY_REQUIRED"
		s.Reason = "an interrupted knowledge import must be resumed"
		s.NextAction = "retry the exact same signed package"
		s.CurrentEligible = false
	}
	s.TrustFreshness = s.Freshness
	return s, nil
}

// projectSourceEvidenceFreshness projects the trusted receipt's aggregate
// expiry without claiming that it proves current review or per-rule usability.
// A future earliest expiry proves only that covered entries are not expired;
// a past earliest expiry proves only that some or all entries may be expired.
func projectSourceEvidenceFreshness(status *Status, receipt TrustReceipt, now time.Time) {
	status.SourceEvidenceExpiresAt = receipt.EvidenceExpiresAt
	if receipt.EvidenceExpiresAt == "" {
		status.SourceEvidenceFreshness = "no_rules"
		return
	}
	expiresAt, err := parseTime(receipt.EvidenceExpiresAt)
	if err != nil {
		status.SourceEvidenceFreshness = "not_assessed"
		status.SourceEvidenceExpiresAt = ""
		return
	}
	if now.Before(expiresAt) {
		status.SourceEvidenceFreshness = "not_expired"
		return
	}
	status.SourceEvidenceFreshness = "some_or_all_expired"
}

func assertSelection(s selectionPointer, req SelectionRequest, mode SelectionMode) error {
	if req.ExpectedRevision != "" && req.ExpectedRevision != s.Revision {
		return ErrIntegrity
	}
	if req.ExpectedBundleDigest != "" {
		v, e := normalizeDigest(req.ExpectedBundleDigest)
		if e != nil || v != s.BundleDigest {
			return ErrIntegrity
		}
	}
	if req.ExpectedTrustReceiptDigest != "" {
		v, e := normalizeDigest(req.ExpectedTrustReceiptDigest)
		if e != nil || v != s.TrustReceiptDigest {
			return ErrIntegrity
		}
	}
	if mode == SelectionHistorical && (req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "") {
		return ErrInvalid
	}
	return nil
}
func admissionRelative(bundle, receipt string) string {
	return "admissions/" + strings.TrimPrefix(bundle, "sha256:") + "/" + strings.TrimPrefix(receipt, "sha256:")
}
func admissionMatchesReceipt(a Admission, r TrustReceipt) bool {
	return a.Revision == r.KnowledgeRevision && a.Purpose == r.Purpose && a.EngineCapabilityDigest == r.EngineCapabilityDigest && a.HasRule == r.HasRule && a.RuleDigest == r.RuleDigest && a.EvidenceExpiresAt == r.EvidenceExpiresAt
}
func validateTrustReceipt(r TrustReceipt, s selectionPointer, material *trustMaterial, targetLength int64) error {
	return validateTrustReceiptForProfile(r, s, material, targetLength, certManagerProfile())
}

func validateTrustReceiptForProfile(r TrustReceipt, s selectionPointer, material *trustMaterial, targetLength int64, profile profileSpec) error {
	if !profile.valid() || material == nil || !receiptAssertionVersion(r) || r.TrustSource != "OPERATOR_PROVISIONED" || r.TargetPath != profile.targetPath || r.TargetDigest != s.BundleDigest || r.KnowledgeRevision != s.Revision || r.TargetLength != targetLength || r.TargetLength < 1 || r.TargetLength > profile.maxTarget || r.InitialRootDigest != material.state.InitialRootDigest || !reflect.DeepEqual(r.RootHistory, material.state.RootHistory) || r.Root != material.state.Root || r.Timestamp != material.state.Timestamp || r.Snapshot != material.state.Snapshot || r.Targets != material.state.Targets || r.ExpectedRevision != "" && r.ExpectedRevision != s.Revision || r.ExpectedBundleDigest != "" && r.ExpectedBundleDigest != s.BundleDigest {
		return ErrIntegrity
	}
	if r.APIVersion == trustReceiptV2 {
		assertionDigest, err := VerificationAssertionsDigest(VerificationAssertions{
			PublisherInitialRootDigest: r.InitialRootDigest,
			RootHistory:                append([]RootHistoryEntry(nil), r.RootHistory...),
			Root:                       r.Root,
			Timestamp:                  r.Timestamp,
			Snapshot:                   r.Snapshot,
			Targets:                    r.Targets,
			TargetPath:                 r.TargetPath,
			Purpose:                    r.Purpose,
			EngineCapabilityDigest:     r.EngineCapabilityDigest,
		})
		if err != nil || assertionDigest != r.ExpectedVerificationAssertionsDigest {
			return ErrIntegrity
		}
	}
	verifiedAt, e := parseTime(r.VerifiedAt)
	if e != nil {
		return e
	}
	for _, role := range []RoleReceipt{r.Root, r.Timestamp, r.Snapshot, r.Targets} {
		if role.Version == 0 {
			continue
		}
		expires, parseErr := parseTime(role.Expires)
		if parseErr != nil || !verifiedAt.Before(expires) {
			return ErrIntegrity
		}
	}
	if validateAdmission(Admission{Revision: r.KnowledgeRevision, Purpose: r.Purpose, EngineCapabilityDigest: r.EngineCapabilityDigest, HasRule: r.HasRule, RuleDigest: r.RuleDigest, EvidenceExpiresAt: r.EvidenceExpiresAt}) != nil {
		return ErrIntegrity
	}
	return nil
}
func packageFromStored(m *trustMaterial, target []byte, bundle string) importPackage {
	return packageFromStoredForProfile(m, target, bundle, certManagerProfile())
}

func packageFromStoredForProfile(m *trustMaterial, target []byte, bundle string, profile profileSpec) importPackage {
	files := map[string][]byte{"metadata/timestamp.json": append([]byte(nil), m.timestamp...), fmt.Sprintf("metadata/%d.snapshot.json", m.state.Snapshot.Version): append([]byte(nil), m.snapshot...), fmt.Sprintf("metadata/%d.targets.json", m.state.Targets.Version): append([]byte(nil), m.targets...), "targets/knowledge/" + strings.TrimPrefix(bundle, "sha256:") + "." + path.Base(profile.targetPath): append([]byte(nil), target...)}
	return importPackage{files: files, targetPath: profile.targetPath}
}
