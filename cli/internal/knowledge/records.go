// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type clockFloor struct {
	APIVersion string `json:"apiVersion"`
	CheckedAt  string `json:"checkedAt"`
}
type importPending struct {
	APIVersion                           string `json:"apiVersion"`
	PriorTrustStateDigest                string `json:"priorTrustStateDigest,omitempty"`
	PriorSelectionDigest                 string `json:"priorSelectionDigest,omitempty"`
	InitialRootDigest                    string `json:"initialRootDigest,omitempty"`
	PackageDigest                        string `json:"packageDigest"`
	ExpectedRevision                     string `json:"expectedRevision,omitempty"`
	ExpectedBundleDigest                 string `json:"expectedBundleDigest,omitempty"`
	ExpectedVerificationAssertionsDigest string `json:"expectedVerificationAssertionsDigest,omitempty"`
	PublishedTrustStateDigest            string `json:"publishedTrustStateDigest,omitempty"`
	AcceptedTrustStateDigest             string `json:"acceptedTrustStateDigest,omitempty"`
	StartedAt                            string `json:"startedAt"`
}

func loadImportPending(store *storeFS) (*importPending, error) {
	raw, e := store.read("import-pending.json", 4096)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, ErrIntegrity
	}
	var p importPending
	if decodeCanonicalStrict(raw, &p) != nil || !pendingAssertionVersion(p) {
		return nil, ErrIntegrity
	}
	if p.PackageDigest == "" || p.InitialRootDigest == "" {
		return nil, ErrIntegrity
	}
	for _, d := range []string{p.PriorTrustStateDigest, p.PriorSelectionDigest, p.InitialRootDigest, p.PackageDigest, p.ExpectedBundleDigest, p.ExpectedVerificationAssertionsDigest, p.PublishedTrustStateDigest, p.AcceptedTrustStateDigest} {
		if d != "" {
			if n, x := normalizeDigest(d); x != nil || n != d {
				return nil, ErrIntegrity
			}
		}
	}
	if p.ExpectedRevision != "" {
		if _, e := parseRevision(p.ExpectedRevision); e != nil {
			return nil, ErrIntegrity
		}
	}
	if _, e := parseTime(p.StartedAt); e != nil {
		return nil, ErrIntegrity
	}
	return &p, nil
}
func beginImportTransaction(store *storeFS, p importPending) (*importPending, error) {
	if p.ExpectedVerificationAssertionsDigest == "" {
		p.APIVersion = pendingV1
	} else {
		p.APIVersion = pendingV2
	}
	old, e := loadImportPending(store)
	if e != nil {
		return nil, e
	}
	if old != nil {
		currentMatches := old.PriorTrustStateDigest == p.PriorTrustStateDigest || old.PublishedTrustStateDigest == p.PriorTrustStateDigest || old.AcceptedTrustStateDigest == p.PriorTrustStateDigest
		same := old.PackageDigest == p.PackageDigest && old.InitialRootDigest == p.InitialRootDigest && old.ExpectedRevision == p.ExpectedRevision && old.ExpectedBundleDigest == p.ExpectedBundleDigest && old.ExpectedVerificationAssertionsDigest == p.ExpectedVerificationAssertionsDigest && old.PriorSelectionDigest == p.PriorSelectionDigest && currentMatches
		if !same {
			return nil, fmt.Errorf("a different interrupted import must be resumed: %w", ErrRecoveryRequired)
		}
		return old, nil
	}
	raw, e := marshalCanonical(p)
	if e != nil {
		return nil, e
	}
	if e = store.write("import-pending.json", raw, true); e != nil {
		return nil, e
	}
	return &p, nil
}

func pendingAssertionVersion(p importPending) bool {
	switch p.APIVersion {
	case pendingV1:
		return p.ExpectedVerificationAssertionsDigest == ""
	case pendingV2:
		return p.ExpectedVerificationAssertionsDigest != ""
	default:
		return false
	}
}
func updatePendingAccepted(store *storeFS, digest string) error {
	p, e := loadImportPending(store)
	if e != nil || p == nil {
		return ErrIntegrity
	}
	p.AcceptedTrustStateDigest = digest
	raw, e := marshalCanonical(*p)
	if e != nil {
		return e
	}
	return store.write("import-pending.json", raw, false)
}
func updatePendingPublished(store *storeFS, digest string) error {
	p, e := loadImportPending(store)
	if e != nil || p == nil || p.AcceptedTrustStateDigest != digest {
		return ErrIntegrity
	}
	p.PublishedTrustStateDigest = digest
	raw, e := marshalCanonical(*p)
	if e != nil {
		return e
	}
	return store.write("import-pending.json", raw, false)
}
func selectionDigest(store *storeFS, admit AdmitFunc) (string, error) {
	return selectionDigestForProfile(store, certManagerProfile(), admit)
}

func selectionDigestForProfile(store *storeFS, profile profileSpec, admit AdmitFunc) (string, error) {
	raw, e := store.read("selection.json", 4096)
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil {
		return "", ErrIntegrity
	}
	selected, e := loadSelection(store)
	if e != nil || validateStoredSelection(store, selected, profile, admit) != nil {
		return "", ErrIntegrity
	}
	return digestBytes(raw), nil
}

func persistAdmission(store *storeFS, relative string, target, receipt []byte, stateDigest string) error {
	if err := store.write(relative+"/target.json", target, true); err != nil {
		return err
	}
	if err := store.write(relative+"/trust-receipt.json", receipt, true); err != nil {
		return err
	}
	binding, err := marshalCanonical(digestPointer{APIVersion: trustStateAPIVersion, Digest: stateDigest})
	if err != nil {
		return err
	}
	return store.write(relative+"/trust-state.json", binding, true)
}

func persistTrustMaterial(store *storeFS, material trustMaterial, now time.Time, hook func(string) error) (bool, error) {
	if validateTrustState(material.state) != nil {
		return false, ErrIntegrity
	}
	stateRaw, err := marshalCanonical(material.state)
	if err != nil {
		return false, err
	}
	stateDir := "trust/states/" + strings.TrimPrefix(material.stateDigest, "sha256:")
	if digestBytes(stateRaw) != material.stateDigest {
		return false, ErrIntegrity
	}
	if err = store.write(stateDir+"/state.json", stateRaw, true); err != nil {
		return false, err
	}
	if now.IsZero() || now.Location() != time.UTC {
		return false, ErrInvalid
	}
	if err = persistClockFloor(store, now); err != nil {
		return false, err
	}
	versions := make([]int64, 0, len(material.rootHistory))
	for v := range material.rootHistory {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, v := range versions {
		if err = store.write(fmt.Sprintf("%s/roots/%d.root.json", stateDir, v), material.rootHistory[v], true); err != nil {
			return false, err
		}
	}
	for name, raw := range map[string][]byte{"root.json": material.root, "timestamp.json": material.timestamp, "snapshot.json": material.snapshot, "targets.json": material.targets} {
		if len(raw) > 0 {
			if err = store.write(stateDir+"/"+name, raw, true); err != nil {
				return false, err
			}
		}
	}
	if hook != nil {
		if err = hook("state-published"); err != nil {
			return false, err
		}
	}
	if err = updatePendingAccepted(store, material.stateDigest); err != nil {
		return false, err
	}
	if hook != nil {
		if err = hook("pending-accepted"); err != nil {
			return false, err
		}
	}
	old, _ := loadDigestPointer(store, "trust/current.json")
	pointer, err := marshalCanonical(digestPointer{APIVersion: trustStateAPIVersion, Digest: material.stateDigest})
	if err != nil {
		return false, err
	}
	if err = store.write("trust/current.json", pointer, false); err != nil {
		return false, err
	}
	if hook != nil {
		if err = hook("current-published"); err != nil {
			return false, err
		}
	}
	if err = updatePendingPublished(store, material.stateDigest); err != nil {
		return false, err
	}
	return old != material.stateDigest, nil
}

func loadCurrentTrust(store *storeFS) (*trustMaterial, error) {
	return loadCurrentTrustForProfile(store, certManagerProfile())
}

func loadCurrentTrustForProfile(store *storeFS, profile profileSpec) (*trustMaterial, error) {
	digest, err := loadDigestPointer(store, "trust/current.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSelection
		}
		return nil, err
	}
	return loadTrustByDigestForProfile(store, digest, profile)
}
func loadTrustByDigest(store *storeFS, digest string) (*trustMaterial, error) {
	return loadTrustByDigestForProfile(store, digest, certManagerProfile())
}

func loadTrustByDigestForProfile(store *storeFS, digest string, profile profileSpec) (*trustMaterial, error) {
	if !profile.valid() {
		return nil, ErrIntegrity
	}
	normalized, err := normalizeDigest(digest)
	if err != nil {
		return nil, ErrIntegrity
	}
	dir := "trust/states/" + strings.TrimPrefix(normalized, "sha256:")
	raw, err := store.read(dir+"/state.json", maxStateFile)
	if err != nil || digestBytes(raw) != normalized {
		return nil, ErrIntegrity
	}
	var state trustState
	if err = decodeCanonicalStrict(raw, &state); err != nil || validateTrustState(state) != nil {
		return nil, ErrIntegrity
	}
	material := &trustMaterial{state: state, stateDigest: normalized, rootHistory: map[int64][]byte{}}
	for _, entry := range state.RootHistory {
		rr, e := store.read(fmt.Sprintf("%s/roots/%d.root.json", dir, entry.Version), maxStateFile)
		if e != nil || digestBytes(rr) != entry.Digest {
			return nil, ErrIntegrity
		}
		material.rootHistory[entry.Version] = rr
	}
	if err := verifyStoredRootChain(state, material.rootHistory); err != nil {
		return nil, fmt.Errorf("stored root chain: %w", err)
	}
	for name, receipt := range map[string]RoleReceipt{"root": state.Root, "timestamp": state.Timestamp, "snapshot": state.Snapshot, "targets": state.Targets} {
		if receipt.Version == 0 {
			continue
		}
		rr, e := store.read(dir+"/"+name+".json", maxStateFile)
		if e != nil || digestBytes(rr) != receipt.Digest || validateTUFJSONForTarget(rr, profile.targetPath) != nil || roleReceiptFromRaw(name, rr) != receipt {
			return nil, fmt.Errorf("stored %s role: %w", name, ErrIntegrity)
		}
		switch name {
		case "root":
			material.root = rr
		case "timestamp":
			material.timestamp = rr
		case "snapshot":
			material.snapshot = rr
		case "targets":
			material.targets = rr
		}
	}
	return material, nil
}
func loadDigestPointer(store *storeFS, rel string) (string, error) {
	raw, err := store.read(rel, 4096)
	if err != nil {
		return "", err
	}
	var p digestPointer
	if decodeCanonicalStrict(raw, &p) != nil || p.APIVersion != trustStateAPIVersion {
		return "", ErrIntegrity
	}
	return normalizeDigest(p.Digest)
}
func loadSelection(store *storeFS) (selectionPointer, error) {
	raw, err := store.read("selection.json", 4096)
	if err != nil {
		if os.IsNotExist(err) {
			return selectionPointer{}, ErrNoSelection
		}
		return selectionPointer{}, ErrIntegrity
	}
	var s selectionPointer
	if decodeCanonicalStrict(raw, &s) != nil || s.APIVersion != selectionAPIVersion {
		return selectionPointer{}, ErrIntegrity
	}
	if _, err = parseRevision(s.Revision); err != nil {
		return selectionPointer{}, ErrIntegrity
	}
	for _, v := range []string{s.BundleDigest, s.TrustReceiptDigest, s.TrustStateDigest} {
		if n, e := normalizeDigest(v); e != nil || n != v {
			return selectionPointer{}, ErrIntegrity
		}
	}
	return s, nil
}
func decodeStrict(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > maxStateFile || !json.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func decodeCanonicalStrict(raw []byte, out any) error {
	if err := decodeStrict(raw, out); err != nil {
		return err
	}
	canonical, err := marshalCanonical(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrIntegrity
	}
	return nil
}

func loadClockFloor(store *storeFS) (time.Time, error) {
	var floor time.Time
	raw, e := store.read("clock-floor.json", 4096)
	if os.IsNotExist(e) {
		return time.Time{}, ErrIntegrity
	}
	if e != nil {
		return time.Time{}, ErrIntegrity
	}
	var c clockFloor
	if decodeCanonicalStrict(raw, &c) != nil || c.APIVersion != "prufyx.io/knowledge-clock-floor/v1" {
		return time.Time{}, ErrIntegrity
	}
	t, e := parseTime(c.CheckedAt)
	if e != nil {
		return time.Time{}, ErrIntegrity
	}
	if t.After(floor) {
		floor = t
	}
	return floor, nil
}
func persistClockFloor(store *storeFS, now time.Time) error {
	raw, e := marshalCanonical(clockFloor{APIVersion: "prufyx.io/knowledge-clock-floor/v1", CheckedAt: now.UTC().Format(time.RFC3339)})
	if e != nil {
		return e
	}
	return store.write("clock-floor.json", raw, false)
}

func validateTrustState(s trustState) error {
	if s.APIVersion != trustStateAPIVersion || len(s.RootHistory) == 0 {
		return ErrIntegrity
	}
	if d, e := normalizeDigest(s.InitialRootDigest); e != nil || d != s.InitialRootDigest {
		return ErrIntegrity
	}
	previous := int64(0)
	for i, e := range s.RootHistory {
		if e.Version < 1 || (i > 0 && e.Version != previous+1) {
			return ErrIntegrity
		}
		if d, x := normalizeDigest(e.Digest); x != nil || d != e.Digest {
			return ErrIntegrity
		}
		previous = e.Version
	}
	if s.RootHistory[0].Digest != s.InitialRootDigest {
		return ErrIntegrity
	}
	if s.Root.Version != previous || s.Root.Digest != s.RootHistory[len(s.RootHistory)-1].Digest {
		return ErrIntegrity
	}
	roles := []RoleReceipt{s.Root, s.Timestamp, s.Snapshot, s.Targets}
	seenMissing := false
	for _, r := range roles {
		if r.Version == 0 {
			seenMissing = true
			if r.Digest != "" || r.Expires != "" {
				return ErrIntegrity
			}
			continue
		}
		if seenMissing || r.Version < 1 || r.Version > maxRevision {
			return ErrIntegrity
		}
		if d, e := normalizeDigest(r.Digest); e != nil || d != r.Digest {
			return ErrIntegrity
		}
		if _, e := parseTime(r.Expires); e != nil {
			return ErrIntegrity
		}
	}
	if (s.RevisionFloor == "") != (s.RevisionFloorBundleDigest == "") {
		return ErrIntegrity
	}
	if s.RevisionFloor != "" {
		if _, e := parseRevision(s.RevisionFloor); e != nil {
			return ErrIntegrity
		}
		if d, e := normalizeDigest(s.RevisionFloorBundleDigest); e != nil || d != s.RevisionFloorBundleDigest {
			return ErrIntegrity
		}
	}
	return nil
}
