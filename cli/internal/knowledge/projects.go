// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// ConstraintsProjectsIndexTargetPath is the index target of the per-project
// CNCF layout. Every project has its own target under
// knowledge/cncf/projects/<project>.v1.json, and every community project (a
// project outside the CNCF landscape catalog) under
// knowledge/community/projects/<project>.v1.json; the one index lists both.
const ConstraintsProjectsIndexTargetPath = cncfcheck.ExternalIndexTargetPath

// ErrLayout marks a package or store that uses the other CNCF target layout.
// It is always joined with ErrInvalid or ErrIntegrity and never relaxes a
// check; it only lets callers explain the mismatch.
var ErrLayout = errors.New("knowledge target layout mismatch")

const (
	// A per-project package holds the index, up to 256 project targets of at
	// most 1 MiB each, and TUF metadata. The complete package is bounded by
	// the local bounded-file reader (8 MiB); member bytes by 7 MiB.
	SplitMaxPackageBytes = 8 << 20
	// SplitMaxPackageMemberBytes is the bound on the summed size of all
	// members of a per-project package.
	SplitMaxPackageMemberBytes = 7 << 20
	splitMaxPackageBytes       = SplitMaxPackageBytes
	splitMaxPackageTotal       = SplitMaxPackageMemberBytes
	splitMaxPackageFiles       = cncfcheck.MaxExternalIndexProjects + 32
	splitMaxJSONMembers        = 8 * (cncfcheck.MaxExternalIndexProjects + 1) * 4
)

var (
	splitIndexMemberRE   = regexp.MustCompile(`^targets/knowledge/cncf/[0-9a-f]{64}\.index\.v1\.json$`)
	splitProjectMemberRE = regexp.MustCompile(`^targets/knowledge/(?:cncf|community)/projects/[0-9a-f]{64}\.([a-z0-9]+(?:-[a-z0-9]+)*)\.v1\.json$`)
	singleCNCFMemberRE   = regexp.MustCompile(`^targets/knowledge/[0-9a-f]{64}\.constraints\.v1\.json$`)
)

// ProjectTargetReceipt reports one verified project target.
type ProjectTargetReceipt struct {
	Project    string `json:"project"`
	TargetPath string `json:"targetPath"`
	Revision   string `json:"revision"`
	Length     int64  `json:"length"`
	Digest     string `json:"digest"`
}

// ProjectTarget is one verified project target carried by a VerifiedRevision
// opened from a per-project store.
type ProjectTarget struct {
	Project  string
	Path     string
	Revision string
	Digest   string
	bytes    []byte
}

func (p ProjectTarget) Bytes() []byte { return append([]byte(nil), p.bytes...) }

// projectFloor is the per-project rollback floor kept in the trust state.
type projectFloor struct {
	Project  string `json:"project"`
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}

type splitTargetError struct{ reason string }

func (e *splitTargetError) Error() string { return e.reason + ": " + ErrIntegrity.Error() }
func (e *splitTargetError) Unwrap() error { return ErrIntegrity }

func splitFailure(format string, args ...any) error {
	return &splitTargetError{reason: fmt.Sprintf(format, args...)}
}

func isSplitTarget(targetPath string) bool { return targetPath == ConstraintsProjectsIndexTargetPath }

func splitTargetKey(key string) bool {
	_, ok := cncfcheck.ProjectFromTargetPath(key)
	return ok
}

func jsonMemberLimit(targetPath string) int {
	if isSplitTarget(targetPath) {
		return splitMaxJSONMembers
	}
	return maxJSONMembers
}

func (p profileSpec) packageLimits() (maxBytes int, maxFiles int, maxTotal int64) {
	if p.split {
		return splitMaxPackageBytes, splitMaxPackageFiles, splitMaxPackageTotal
	}
	return maxPackageBytes, maxPackageFiles, maxPackageTotal
}

func splitMemberName(name string) bool {
	return splitIndexMemberRE.MatchString(name) || splitProjectMemberRE.MatchString(name)
}

// hashedTargetMember is the package member that go-tuf requests for one
// target under consistent snapshots: <dir>/<sha256>.<base>.
func hashedTargetMember(targetPath, digest string) string {
	return "targets/" + path.Dir(targetPath) + "/" + digest + "." + path.Base(targetPath)
}

// packageLayoutMismatch detects a package built for the other CNCF layout
// from member names alone, before any metadata is parsed, so the caller can
// explain the rejection. Packages that are not tar archives fall through.
func packageLayoutMismatch(raw []byte, profile profileSpec) error {
	if profile.id != profileConstraints && !profile.split {
		return nil
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	for count := 0; count <= splitMaxPackageFiles; count++ {
		header, err := reader.Next()
		if err != nil {
			return nil
		}
		if profile.id == profileConstraints && splitMemberName(header.Name) {
			return fmt.Errorf("package uses the per-project CNCF layout; use the cncf-projects profile with a new store directory: %w", errors.Join(ErrLayout, ErrInvalid))
		}
		if profile.split && singleCNCFMemberRE.MatchString(header.Name) {
			return fmt.Errorf("package uses the single-target CNCF layout; use the cncf profile: %w", errors.Join(ErrLayout, ErrInvalid))
		}
	}
	return nil
}

func admitConstraintsIndex(target []byte) (Admission, error) {
	index, err := cncfcheck.ParseExternalIndex(target)
	if err != nil {
		return Admission{}, fmt.Errorf("index target parse: %w", ErrIntegrity)
	}
	admission, err := index.Admission()
	if err != nil {
		return Admission{}, fmt.Errorf("index target admission: %w", ErrIntegrity)
	}
	return Admission{Revision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}, nil
}

// validateSplitTargetsRole checks the shape of a per-project targets role:
// the index plus one or more project targets, each within the per-target cap.
func validateSplitTargetsRole(targets *metadata.Metadata[metadata.TargetsType], profile profileSpec) error {
	all := targets.Signed.Targets
	if len(all) < 2 || len(all) > cncfcheck.MaxExternalIndexProjects+1 || all[profile.targetPath] == nil {
		return ErrIntegrity
	}
	for name, target := range all {
		if name != profile.targetPath && !splitTargetKey(name) {
			return ErrIntegrity
		}
		if target == nil || target.Length < 1 || target.Length > profile.maxTarget || len(target.Hashes) != 1 || len(target.Hashes["sha256"]) != sha256Size || target.Custom != nil || len(target.UnrecognizedFields) != 0 {
			return splitFailure("target %s exceeds the per-target cap or hash policy", name)
		}
	}
	return nil
}

// verifySplitTargets binds the verified index to the signed targets role and
// downloads the selected project targets through the TUF updater. The set of
// project targets in the index must equal the set in the targets role, with
// identical lengths and digests. A nil selection downloads every project.
func verifySplitTargets(u *updater.Updater, targets *metadata.Metadata[metadata.TargetsType], indexRaw []byte, targetDir string, only map[string]bool) (map[string][]byte, error) {
	index, err := cncfcheck.ParseExternalIndex(indexRaw)
	if err != nil {
		return nil, splitFailure("index target admission")
	}
	entries := index.Entries()
	listed := map[string]cncfcheck.ExternalIndexEntry{}
	for _, entry := range entries {
		listed[entry.TargetPath] = entry
	}
	for name := range targets.Signed.Targets {
		if name == ConstraintsProjectsIndexTargetPath {
			continue
		}
		if _, ok := listed[name]; !ok {
			return nil, splitFailure("target %s is signed but not listed in the index", name)
		}
	}
	for _, entry := range entries {
		info := targets.Signed.Targets[entry.TargetPath]
		if info == nil {
			return nil, splitFailure("target %s is listed in the index but not signed", entry.TargetPath)
		}
		if info.Length != entry.Length || "sha256:"+hex.EncodeToString(info.Hashes["sha256"]) != entry.Digest {
			return nil, splitFailure("target %s length or digest differs between index and targets metadata", entry.TargetPath)
		}
	}
	projects := map[string][]byte{}
	for _, entry := range entries {
		if only != nil && !only[entry.Project] {
			continue
		}
		info, err := u.GetTargetInfo(entry.TargetPath)
		if err != nil {
			return nil, err
		}
		if len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256Size || info.Length > maxPackageEntry {
			return nil, splitFailure("target %s hash or size policy", entry.TargetPath)
		}
		_, raw, err := u.DownloadTarget(info, filepath.Join(targetDir, "project-"+entry.Project+".json"), "https://offline.invalid/targets")
		if err != nil {
			return nil, splitFailure("target %s is missing or does not match its signed length and hash", entry.TargetPath)
		}
		if _, err := cncfcheck.AdmitExternalProjectTarget(index, entry.Project, raw); err != nil {
			return nil, splitFailure("target %s semantic admission", entry.TargetPath)
		}
		projects[entry.Project] = append([]byte(nil), raw...)
	}
	return projects, nil
}

// advanceProjectFloors enforces one rollback floor per project. A project's
// revision may not decrease, and an equal revision must keep the exact
// target digest. Floors of projects absent from the new index are retained so
// a later index cannot reintroduce an older target.
func advanceProjectFloors(floors []projectFloor, indexRaw []byte) ([]projectFloor, error) {
	index, err := cncfcheck.ParseExternalIndex(indexRaw)
	if err != nil {
		return nil, ErrIntegrity
	}
	next := map[string]projectFloor{}
	for _, floor := range floors {
		next[floor.Project] = floor
	}
	for _, entry := range index.Entries() {
		if floor, ok := next[entry.Project]; ok {
			if err := enforceRevisionFloor(floor.Revision, floor.Digest, entry.Revision, entry.Digest); err != nil {
				return nil, fmt.Errorf("project %s target %s revision %s is below floor %s: %w", entry.Project, entry.TargetPath, entry.Revision, floor.Revision, err)
			}
		}
		next[entry.Project] = projectFloor{Project: entry.Project, Revision: entry.Revision, Digest: entry.Digest}
	}
	result := make([]projectFloor, 0, len(next))
	for _, floor := range next {
		result = append(result, floor)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Project < result[j].Project })
	return result, nil
}

func validateProjectFloors(floors []projectFloor) error {
	for i, floor := range floors {
		if i > 0 && floors[i-1].Project >= floor.Project {
			return ErrIntegrity
		}
		if _, ok := cncfcheck.ProjectFromTargetPath(cncfcheck.ProjectTargetPath(floor.Project)); !ok {
			return ErrIntegrity
		}
		if _, err := parseRevision(floor.Revision); err != nil {
			return ErrIntegrity
		}
		if d, err := normalizeDigest(floor.Digest); err != nil || d != floor.Digest {
			return ErrIntegrity
		}
	}
	return nil
}

// readStoredProjects reads the admitted project targets named by the stored
// index. The caller re-verifies every byte against stored TUF metadata.
func readStoredProjects(store *storeFS, rel string, indexRaw []byte, only map[string]bool) (map[string][]byte, error) {
	index, err := cncfcheck.ParseExternalIndex(indexRaw)
	if err != nil {
		return nil, ErrIntegrity
	}
	projects := map[string][]byte{}
	for _, entry := range index.Entries() {
		if only != nil && !only[entry.Project] {
			continue
		}
		raw, err := store.read(rel+"/projects/"+entry.Project+".json", maxPackageEntry)
		if err != nil || digestBytes(raw) != entry.Digest {
			return nil, ErrIntegrity
		}
		projects[entry.Project] = raw
	}
	return projects, nil
}

func persistProjects(store *storeFS, rel string, projects map[string][]byte) error {
	names := make([]string, 0, len(projects))
	for name := range projects {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := store.write(rel+"/projects/"+name+".json", projects[name], true); err != nil {
			return err
		}
	}
	return nil
}

// projectReceipts lists the project targets of an index in project order.
func projectReceipts(indexRaw []byte) ([]ProjectTargetReceipt, error) {
	index, err := cncfcheck.ParseExternalIndex(indexRaw)
	if err != nil {
		return nil, ErrIntegrity
	}
	result := []ProjectTargetReceipt{}
	for _, entry := range index.Entries() {
		result = append(result, ProjectTargetReceipt{Project: entry.Project, TargetPath: entry.TargetPath, Revision: entry.Revision, Length: entry.Length, Digest: entry.Digest})
	}
	return result, nil
}

// verifiedProjectTargets builds the sealed project view for one open.
func verifiedProjectTargets(indexRaw []byte, projects map[string][]byte) (map[string]ProjectTarget, error) {
	index, err := cncfcheck.ParseExternalIndex(indexRaw)
	if err != nil {
		return nil, ErrIntegrity
	}
	result := map[string]ProjectTarget{}
	for project, raw := range projects {
		entry, ok := index.Entry(project)
		if !ok || digestBytes(raw) != entry.Digest {
			return nil, ErrIntegrity
		}
		result[project] = ProjectTarget{Project: project, Path: entry.TargetPath, Revision: entry.Revision, Digest: entry.Digest, bytes: append([]byte(nil), raw...)}
	}
	return result, nil
}

func projectSelection(projects []string) (map[string]bool, error) {
	if len(projects) > cncfcheck.MaxExternalIndexProjects {
		return nil, ErrInvalid
	}
	only := map[string]bool{}
	for _, project := range projects {
		if _, ok := cncfcheck.ProjectFromTargetPath(cncfcheck.ProjectTargetPath(project)); !ok {
			return nil, ErrInvalid
		}
		only[project] = true
	}
	return only, nil
}

func sameProjects(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for project, raw := range a {
		if !bytes.Equal(raw, b[project]) {
			return false
		}
	}
	return true
}

// withProjectReceipts attaches the verified project list of a per-project
// import to its receipt. Other profiles are returned unchanged.
func withProjectReceipts(receipt ImportReceipt, profile profileSpec, indexRaw []byte) ImportReceipt {
	if !profile.split {
		return receipt
	}
	if projects, err := projectReceipts(indexRaw); err == nil {
		receipt.ProjectTargets = projects
	}
	return receipt
}

// ImportConstraintsProjects imports a per-project CNCF package: the index
// and every project target are verified against the signed targets role, and
// the index and each project keep their own rollback floor.
func ImportConstraintsProjects(req ImportRequest) (ImportReceipt, error) {
	p := constraintsProjectsProfile()
	return importWithProfile(req, p, p.admit, time.Time{}, nil, nil)
}

// VerifyConstraintsProjects verifies a per-project CNCF package without a store.
func VerifyConstraintsProjects(req VerifyRequest) (PackageVerificationReceipt, error) {
	p := constraintsProjectsProfile()
	return verifyForProfile(req, p, p.admit)
}

// InspectConstraintsProjects reports a per-project CNCF store, re-verifying
// the index and every project target.
func InspectConstraintsProjects(storeRoot string) (Status, error) {
	return inspectProfile(storeRoot, constraintsProjectsProfile())
}

// OpenSelectedCNCF opens the selected CNCF revision in either layout. For a
// per-project store only the named projects are read and verified, together
// with the complete index; a single-target store ignores projects.
func OpenSelectedCNCF(req SelectionRequest, projects []string) (VerifiedRevision, error) {
	profile, err := cncfStoreProfile(req.StoreRoot)
	if err != nil {
		return VerifiedRevision{}, err
	}
	if !profile.split {
		return openRevision(req, profile, time.Time{}, SelectionCurrent, profile.admit, nil)
	}
	only, err := projectSelection(projects)
	if err != nil {
		return VerifiedRevision{}, err
	}
	return openRevision(req, profile, time.Time{}, SelectionCurrent, profile.admit, only)
}

// OpenHistoricalCNCF revalidates an exact historical CNCF revision in either
// layout, reading only the named projects from a per-project store.
func OpenHistoricalCNCF(req SelectionRequest, evaluatedAt time.Time, projects []string) (VerifiedRevision, error) {
	if req.ExpectedRevision == "" || req.ExpectedBundleDigest == "" || req.ExpectedTrustReceiptDigest == "" || evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC {
		return VerifiedRevision{}, fmt.Errorf("historical selection requires exact identities and UTC time: %w", ErrInvalid)
	}
	profile, err := cncfStoreProfile(req.StoreRoot)
	if err != nil {
		return VerifiedRevision{}, err
	}
	if !profile.split {
		return openRevision(req, profile, evaluatedAt, SelectionHistorical, profile.admit, nil)
	}
	only, err := projectSelection(projects)
	if err != nil {
		return VerifiedRevision{}, err
	}
	return openRevision(req, profile, evaluatedAt, SelectionHistorical, profile.admit, only)
}

// cncfStoreProfile reads the immutable profile marker under the store lock.
// A per-project marker selects the per-project profile; anything else selects
// the single-target profile, whose own marker check then applies unchanged.
func cncfStoreProfile(storeRoot string) (profileSpec, error) {
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		return profileSpec{}, err
	}
	defer store.Close()
	lock, err := store.lock(5 * time.Second)
	if err != nil {
		return profileSpec{}, err
	}
	defer unlockStore(lock)
	raw, err := store.read("profile.json", 4096)
	if err == nil {
		var marker profileMarker
		if decodeCanonicalStrict(raw, &marker) == nil && marker.APIVersion == profileMarkerAPIVersion && marker.Profile == profileProjectsMarkerName && marker.TargetPath == ConstraintsProjectsIndexTargetPath {
			return constraintsProjectsProfile(), nil
		}
	}
	return constraintsProfile(), nil
}
