// SPDX-License-Identifier: AGPL-3.0-only

package validation

// This file contains the explicit multi-artifact publication API.  OutputRoot
// predates the run contract and its Write method intentionally remains a
// one-file (or internally assembled legacy report) convenience.  RunStore is
// an alias for OutputRoot so callers cannot accidentally create a second path
// authority: all staging and publication stays anchored by OutputRoot's
// retained directory descriptors.
//
// The store provides tamper detection and replayable exact bytes against
// ordinary path replacement, symlink, hard-link, and accidental same-process
// failures. Publication reserves the final directory with a descriptor-
// relative no-replace mkdir and copies from the retained stage descriptor.
// Consequently a swapped stage pathname cannot change the bytes copied, and
// cleanup never needs to rename or unlink a source pathname.
// Production authority still requires OS isolation/separate UID and an
// external signature/origin binding; this local store is not an attestation.
// A committed decision-shaped batch is therefore storage only: callers must
// independently run decision.VerifyReportBytes and the exact replay checks
// with the exact roots, digests, policy, trust, evaluator, and UTC time before
// treating its files as an authority record.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

var errSecureAtomicPublicationUnsupported = errors.New("atomic no-replace directory publication unsupported")

// errStageBindingLost is returned when a retained staging directory's name no
// longer names that directory. It is an integrity failure, not a recoverable
// I/O condition: the namespace entry is left untouched by cleanup.
var errStageBindingLost = fmt.Errorf("staged output name binding lost: %w", ErrIntegrity)

const (
	// A run is useful only when it contains the complete bounded artifact set;
	// the upper bound prevents an untrusted caller from turning this API into a
	// general archive writer.
	MinRunArtifacts = 6
	MaxRunArtifacts = 16
	MaxRunBytes     = 8 << 20
	// Descriptive aliases retained for callers that name the limits by their
	// validation role.
	MinBatchFiles    = MinRunArtifacts
	MaxBatchFiles    = MaxRunArtifacts
	MaxBatchBytes    = MaxRunBytes
	MaxRunTotalBytes = MaxRunBytes
)

// RunArtifactNames is the fixed public filename allow-list.  Names are plain
// leaves and are deliberately not accepted by extension or prefix.  The list
// includes the v0.1 names as well as the provenance-bound artifact names used
// by the next workflow revision.
var runArtifactNames = map[string]struct{}{
	"current-bundle.json": {}, "current-bundle.sha256": {},
	"current.json": {}, "current.sha256": {},
	"adapter-artifact.json": {}, "adapter-artifact.sha256": {},
	"binding.json": {}, "binding.sha256": {},
	"plan.json": {}, "plan.sha256": {},
	"proposed-bundle.json": {}, "proposed-bundle.sha256": {},
	"proposed.json": {}, "proposed.sha256": {},
	"report.json": {}, "report.sha256": {},
	"decision-report.json": {}, "decision-replay.json": {},
	"demo-boundary.json":    {},
	"candidate-report.json": {}, "candidate-report.sha256": {},
	"replay.json": {}, "replay.sha256": {},
	"replay-record.json": {}, "replay-record.sha256": {},
	"run-manifest.json": {}, "run-manifest.sha256": {},
	"manifest.json": {}, "manifest.sha256": {},
}

var workflowRunArtifactNames = map[string]struct{}{
	"current-bundle.json": {}, "adapter-artifact.json": {}, "plan.json": {},
	"proposed-bundle.json": {}, "binding.json": {}, "report.json": {},
	"replay.json": {}, "run-manifest.json": {},
}

var authoritativeDecisionRunArtifactNames = map[string]struct{}{
	"current-bundle.json": {}, "adapter-artifact.json": {}, "plan.json": {},
	"proposed-bundle.json": {}, "binding.json": {}, "report.json": {},
	"replay.json": {}, "run-manifest.json": {}, "decision-report.json": {}, "decision-replay.json": {},
}

// RunArtifact is the canonical manifest projection for one staged file.
// Digest is over the exact bytes passed to Stage.
type RunArtifact struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

// RunManifest is deterministic: Files are always encoded in lexical name
// order, regardless of the order in which Stage was called.
type RunManifest struct {
	APIVersion    string        `json:"apiVersion"`
	Kind          string        `json:"kind"`
	SchemaVersion string        `json:"schemaVersion"`
	Files         []RunArtifact `json:"files"`
}

// RunStore and OutputBatch are descriptive aliases.  Keeping aliases avoids
// duplicate lifecycle state and makes both names usable by integrations.
type RunStore = OutputRoot
type OutputBatch = OutputRoot
type Batch = OutputRoot

// RunArtifactAllowlist returns a sorted copy of the fixed public filename
// contract. Callers cannot mutate the validator's allow-list.
func RunArtifactAllowlist() []string {
	names := make([]string, 0, len(runArtifactNames))
	for name := range runArtifactNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewRunStore creates a descriptor-anchored store whose public root does not
// exist until Commit succeeds.
func NewRunStore(path string) (*RunStore, error) {
	root, err := PrepareOutputRoot(path)
	if err != nil {
		return nil, err
	}
	return &root, nil
}

// NewOutputBatch is the constructor spelling used by callers that do not
// need the RunStore name.
func NewOutputBatch(path string) (*OutputBatch, error) { return NewRunStore(path) }

// BeginBatch starts the explicit six-to-sixteen artifact lifecycle on root.
// Staging is still private and descriptor-relative.  A second batch cannot be
// started on the same root.
func (root *OutputRoot) BeginBatch() (*OutputBatch, error) {
	if root == nil || root.parent == nil || root.directory == nil || root.committed || root.batchStarted {
		return nil, fmt.Errorf("output batch is unavailable: %w", ErrIO)
	}
	root.batchStarted = true
	root.batchFiles = make(map[string]RunArtifact)
	return root, nil
}

func (root *OutputRoot) NewBatch() (*OutputBatch, error) { return root.BeginBatch() }
func (root *OutputRoot) BeginRun() (*RunStore, error)    { return root.BeginBatch() }
func (root *OutputRoot) RunStore() (*RunStore, error)    { return root.BeginBatch() }
func (root *OutputRoot) Batch() (*OutputBatch, error)    { return root.BeginBatch() }

// NewBatch is a convenience constructor for callers that do not retain an
// OutputRoot value separately.
func NewBatch(path string) (*OutputBatch, error) { return NewRunStore(path) }

// Stage writes one allow-listed artifact to the private staging directory.
// It writes synchronously and fsyncs the file before returning, so no caller
// buffer remains part of the publication state.
func (root *OutputRoot) Stage(name string, data []byte) (err error) {
	if root == nil || root.parent == nil || root.directory == nil || root.committed {
		return fmt.Errorf("output batch is unavailable: %w", ErrIO)
	}
	// Stage on OutputRoot is itself an explicit batch start. BeginBatch is
	// provided for callers that want a typed lifecycle handle first.
	if !root.batchStarted {
		root.batchStarted = true
		root.batchFiles = make(map[string]RunArtifact)
	}
	if !validRunArtifactName(name) {
		return root.abortWithError(fmt.Errorf("output artifact name is not allow-listed: %w", ErrInvalid))
	}
	if _, exists := root.batchFiles[name]; exists {
		return root.abortWithError(fmt.Errorf("duplicate output artifact: %w", ErrInvalid))
	}
	if len(root.batchFiles) >= MaxRunArtifacts {
		return root.abortWithError(fmt.Errorf("output batch file count exceeds bound: %w", ErrInvalid))
	}
	if len(data) > MaxOutputReportBytes || int64(len(data)) > int64(MaxRunBytes)-root.batchBytes {
		return root.abortWithError(fmt.Errorf("output artifact exceeds bound: %w", ErrInvalid))
	}

	file, err := openRelativeExclusive(root.directory, name, 0o600)
	if err != nil {
		return root.abortWithError(fmt.Errorf("create staged output: %w: %v", ErrIO, err))
	}
	// Pin the cleanup ownership before any operation that can fail.  This is
	// important for a short/partial write: the failed file must be removed
	// before the stage directory itself is removed.
	root.stageFiles = append(root.stageFiles, name)
	failed := true
	defer func() {
		if failed {
			closeErr := file.Close()
			abortErr := root.abortBatch()
			if err == nil {
				switch {
				case closeErr != nil:
					err = fmt.Errorf("close staged output: %w: %v", ErrIO, closeErr)
				case abortErr != nil:
					err = fmt.Errorf("abort staged output: %w: %v", ErrIO, abortErr)
				}
			} else if closeErr != nil || abortErr != nil {
				err = fmt.Errorf("%w; cleanup failed: close=%v abort=%v", err, closeErr, abortErr)
			}
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("staged output is not a private regular file: %w", ErrIO)
	}
	if err := writeAll(file, data); err != nil {
		return fmt.Errorf("write staged output: %w: %v", ErrIO, err)
	}
	if outputWriteFaultHook != nil {
		if err := outputWriteFaultHook(name); err != nil {
			return fmt.Errorf("staged output fault: %w: %v", ErrIO, err)
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged output: %w: %v", ErrIO, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged output: %w: %v", ErrIO, err)
	}
	root.batchFiles[name] = RunArtifact{Name: name, Bytes: int64(len(data)), Digest: DigestBytes(data)}
	root.batchBytes += int64(len(data))
	failed = false
	return nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) != 0 {
		n, err := file.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validRunArtifactName(name string) bool {
	if name == "" || name[0] == '.' || name == "." || name == ".." || name != filepathBase(name) {
		return false
	}
	_, ok := runArtifactNames[name]
	return ok
}

// filepathBase is kept deliberately narrower than filepath.Base: artifact
// names are portable simple ASCII leaves, not host-specific path syntax.
func filepathBase(name string) string {
	for _, c := range name {
		if c == '/' || c == '\\' {
			return ""
		}
	}
	return name
}

// Manifest returns canonical manifest bytes for the currently staged files.
// The manifest itself is not implicitly added to the batch; callers choose
// whether to Stage it, avoiding hidden file-count changes and circular
// manifest digests.
func (root *OutputRoot) Manifest() ([]byte, error) {
	if root == nil || !root.batchStarted || root.parent == nil || root.directory == nil || root.committed {
		return nil, fmt.Errorf("output batch is unavailable: %w", ErrIO)
	}
	entries := make([]RunArtifact, 0, len(root.batchFiles))
	for _, entry := range root.batchFiles {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	manifest := RunManifest{APIVersion: APIVersion, Kind: "RunManifest", SchemaVersion: SchemaVersion, Files: entries}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode run manifest: %w: %v", ErrIO, err)
	}
	return append(encoded, '\n'), nil
}

// CanonicalRunManifest builds the same deterministic manifest projection for
// an in-memory artifact set.  It is useful when a caller wants to Stage the
// manifest as one of the bounded files.
func CanonicalRunManifest(files map[string][]byte) ([]byte, error) {
	if len(files) < MinRunArtifacts || len(files) > MaxRunArtifacts {
		return nil, fmt.Errorf("run artifact count is outside bound: %w", ErrInvalid)
	}
	entries := make([]RunArtifact, 0, len(files))
	var total int64
	for name, data := range files {
		if !validRunArtifactName(name) || len(data) > MaxOutputReportBytes || int64(len(data)) > int64(MaxRunBytes)-total {
			return nil, fmt.Errorf("run artifact is invalid or oversized: %w", ErrInvalid)
		}
		total += int64(len(data))
		entries = append(entries, RunArtifact{Name: name, Bytes: int64(len(data)), Digest: DigestBytes(data)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	encoded, err := json.Marshal(RunManifest{APIVersion: APIVersion, Kind: "RunManifest", SchemaVersion: SchemaVersion, Files: entries})
	if err != nil {
		return nil, fmt.Errorf("encode run manifest: %w: %v", ErrIO, err)
	}
	return append(encoded, '\n'), nil
}

// Commit publishes the complete explicit batch exactly once. Pre-reservation
// errors abort private staging and leave the destination absent (unless a
// competing creator already owns that name). Once the final directory has
// been fully copied and closed, a parent-fsync error returns ErrIO while
// leaving the complete run visible; callers must inspect/verify it and must
// not retry the same destination blindly.
func (root *OutputRoot) Commit() error {
	if root == nil || root.parent == nil || root.directory == nil || root.committed || !root.batchStarted {
		return fmt.Errorf("output batch is unavailable: %w", ErrIO)
	}
	if len(root.batchFiles) < MinRunArtifacts || len(root.batchFiles) > MaxRunArtifacts {
		return root.abortWithError(fmt.Errorf("output batch file count is outside bound: %w", ErrInvalid))
	}
	if root.batchBytes > MaxRunBytes {
		return root.abortWithError(fmt.Errorf("output batch exceeds byte bound: %w", ErrInvalid))
	}
	if err := validateRunProfile(root.batchFiles); err != nil {
		return root.abortWithError(err)
	}
	if !atomicBatchPublicationSupported() {
		return root.abortWithError(fmt.Errorf("atomic output publication unsupported: %w", errSecureAtomicPublicationUnsupported))
	}
	if outputCommitHook != nil {
		// Fault hooks model a creator/tamper immediately before publication. Run
		// them before the final descriptor and digest validation so tests cannot
		// introduce a post-validation gap.
		if err := outputCommitHook(root.stageName); err != nil {
			return root.abortWithError(fmt.Errorf("pre-commit output fault: %w: %v", ErrIO, err))
		}
	}
	if err := root.validateStagedBatch(); err != nil {
		return root.abortWithError(err)
	}
	if err := root.commit(); err != nil {
		return err
	}
	return nil
}

func (root *OutputRoot) abortWithError(primary error) error {
	// Before any pathname cleanup, re-establish that the stage name still
	// names our retained directory. A failure can race a stage-name swap even
	// when publication was never attempted; in that case preserve the
	// unowned namespace entry and clean only through our descriptor.
	if root != nil && root.directory != nil && root.stageName != "" && !stageBindingMatches(root) {
		root.stageBindingLost = true
	}
	cleanupErr := root.abortBatch()
	if cleanupErr != nil {
		return fmt.Errorf("%w: cleanup failed: %w", primary, cleanupErr)
	}
	return primary
}

// validateRunProfile keeps the generic store useful for bounded named
// artifacts while enforcing the integrated workflow's exact eight-file
// contract whenever either workflow-only artifact is present.
func validateRunProfile(files map[string]RunArtifact) error {
	if _, authority := files["decision-report.json"]; authority {
		expected := len(authoritativeDecisionRunArtifactNames)
		if _, demo := files["demo-boundary.json"]; demo {
			expected++
		}
		if len(files) != expected {
			return fmt.Errorf("authoritative decision run artifact set is incomplete: %w", ErrIntegrity)
		}
		for name := range authoritativeDecisionRunArtifactNames {
			if _, ok := files[name]; !ok {
				return fmt.Errorf("authoritative decision run artifact set is incomplete: %w", ErrIntegrity)
			}
		}
		if _, demo := files["demo-boundary.json"]; demo {
			if len(files) != expected {
				return fmt.Errorf("authority-demo run artifact set is incomplete: %w", ErrIntegrity)
			}
		}
		return nil
	}
	workflow := false
	for _, name := range []string{"adapter-artifact.json", "binding.json"} {
		if _, ok := files[name]; ok {
			workflow = true
		}
	}
	if !workflow {
		return nil
	}
	if len(files) != len(workflowRunArtifactNames) {
		return fmt.Errorf("workflow run artifact set is incomplete: %w", ErrIntegrity)
	}
	for name := range workflowRunArtifactNames {
		if _, ok := files[name]; !ok {
			return fmt.Errorf("workflow run artifact set is incomplete: %w", ErrIntegrity)
		}
	}
	return nil
}

// verifyStageBinding checks the stage name against the retained descriptor.
// The platform publication helper repeats this binding check against the
// final name after its atomic no-replace rename because renameat2/
// renameatx_np consume a source name rather than a directory descriptor.
func verifyStageBinding(root *OutputRoot) error {
	if root == nil || root.parent == nil || root.directory == nil || root.stageName == "" {
		return fmt.Errorf("staged output identity unavailable: %w", ErrIntegrity)
	}
	check, err := openRelativeDirectory(root.parent, root.stageName)
	if err != nil {
		root.stageBindingLost = true
		return fmt.Errorf("staged output identity changed: %w", ErrIntegrity)
	}
	defer check.Close()
	want, err := root.directory.Stat()
	if err != nil {
		root.stageBindingLost = true
		return fmt.Errorf("staged output identity unavailable: %w", ErrIntegrity)
	}
	got, err := check.Stat()
	if err != nil || !os.SameFile(want, got) {
		root.stageBindingLost = true
		return fmt.Errorf("staged output identity changed: %w", ErrIntegrity)
	}
	return nil
}

// stageBindingMatches is used only while deciding whether a failed publish
// may safely clean the stage pathname. Any inability to prove the same inode
// is treated as unowned and therefore not removed by name.
func stageBindingMatches(root *OutputRoot) bool {
	if root == nil || root.parent == nil || root.stageName == "" {
		return false
	}
	if root.directory == nil {
		return stageNameMatchesInfo(root.parent, root.stageName, root.stageInfo)
	}
	check, err := openRelativeDirectory(root.parent, root.stageName)
	if err != nil {
		return false
	}
	defer check.Close()
	want, err := root.directory.Stat()
	if err != nil {
		return false
	}
	got, err := check.Stat()
	return err == nil && os.SameFile(want, got)
}

func stageNameMatchesInfo(parent *os.File, stageName string, expected os.FileInfo) bool {
	if parent == nil || stageName == "" || expected == nil {
		return false
	}
	check, err := openRelativeDirectory(parent, stageName)
	if err != nil {
		return false
	}
	defer check.Close()
	got, err := check.Stat()
	return err == nil && os.SameFile(expected, got)
}

type publishedArtifact struct {
	name string
	info os.FileInfo
}

// finalDirectoryMatches proves that finalName still names the directory whose
// descriptor was reserved by this publisher. The descriptor remains the
// authority for all data operations; this witness is only for deciding
// whether the public namespace entry may be removed on failure.
func finalDirectoryMatches(parent, finalDirectory *os.File, finalName string) bool {
	if parent == nil || finalDirectory == nil || finalName == "" {
		return false
	}
	check, err := openRelativeDirectory(parent, finalName)
	if err != nil {
		return false
	}
	defer check.Close()
	want, err := finalDirectory.Stat()
	if err != nil {
		return false
	}
	got, err := check.Stat()
	return err == nil && os.SameFile(want, got)
}

func removeOwnedPublishedFile(directory *os.File, artifact publishedArtifact) error {
	check, err := openRelativeFile(directory, artifact.name, 0, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	got, statErr := check.Stat()
	closeErr := check.Close()
	if closeErr != nil {
		return closeErr
	}
	// Never unlink a replacement at the same leaf. A retained inode witness
	// makes cleanup fail closed when a creator wins the race.
	if statErr != nil || !os.SameFile(artifact.info, got) {
		return nil
	}
	return removeRelative(directory, artifact.name)
}

func cleanupPublishedDirectory(parent, finalDirectory *os.File, finalName string, created []publishedArtifact) error {
	if finalDirectory == nil {
		return nil
	}
	var firstErr error
	for _, artifact := range created {
		if err := removeOwnedPublishedFile(finalDirectory, artifact); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	if err := syncDirectory(finalDirectory); err != nil && firstErr == nil {
		firstErr = err
	}
	// Only remove the public name when the directory is empty and the name
	// still resolves to our reserved inode. A swapped name is left entirely
	// untouched, including attacker content.
	if firstErr == nil {
		entries, err := finalDirectory.Readdirnames(-1)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if err == nil && len(entries) == 0 && finalDirectoryMatches(parent, finalDirectory, finalName) {
			if err := removeDirectoryRelative(parent, finalName); err != nil && !errors.Is(err, os.ErrNotExist) {
				firstErr = err
			}
		}
	}
	if err := finalDirectory.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := syncDirectory(parent); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func copyPublishedArtifact(stageDirectory, finalDirectory *os.File, artifact RunArtifact) (publishedArtifact, error) {
	source, err := openRelativeFile(stageDirectory, artifact.Name, 0, 0)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf("open staged %s: %w", artifact.Name, err)
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || !singleLink(before) || before.Mode().Perm() != 0o600 || before.Size() != artifact.Bytes {
		return publishedArtifact{}, fmt.Errorf("staged %s identity or bounds changed", artifact.Name)
	}
	data, err := io.ReadAll(io.LimitReader(source, int64(MaxOutputReportBytes)+1))
	if err != nil || int64(len(data)) != artifact.Bytes || DigestBytes(data) != artifact.Digest {
		return publishedArtifact{}, fmt.Errorf("staged %s bytes changed", artifact.Name)
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != artifact.Bytes {
		return publishedArtifact{}, fmt.Errorf("staged %s identity changed during read", artifact.Name)
	}

	destination, err := openRelativeExclusive(finalDirectory, artifact.Name, 0o600)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf("create published %s: %w", artifact.Name, err)
	}
	closeDestination := true
	defer func() {
		if closeDestination {
			_ = destination.Close()
		}
	}()
	if err := writeAll(destination, data); err != nil {
		return publishedArtifact{}, fmt.Errorf("write published %s: %w", artifact.Name, err)
	}
	if err := destination.Sync(); err != nil {
		return publishedArtifact{}, fmt.Errorf("sync published %s: %w", artifact.Name, err)
	}
	info, err := destination.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Mode().Perm() != 0o600 || info.Size() != artifact.Bytes {
		return publishedArtifact{}, fmt.Errorf("published %s identity or bounds changed", artifact.Name)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		return publishedArtifact{}, fmt.Errorf("rewind published %s: %w", artifact.Name, err)
	}
	check, err := io.ReadAll(io.LimitReader(destination, int64(MaxOutputReportBytes)+1))
	if err != nil || int64(len(check)) != artifact.Bytes || DigestBytes(check) != artifact.Digest {
		return publishedArtifact{}, fmt.Errorf("published %s bytes changed", artifact.Name)
	}
	finalInfo, err := destination.Stat()
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != artifact.Bytes {
		return publishedArtifact{}, fmt.Errorf("published %s identity changed during verification", artifact.Name)
	}
	if err := destination.Close(); err != nil {
		return publishedArtifact{}, fmt.Errorf("close published %s: %w", artifact.Name, err)
	}
	closeDestination = false
	return publishedArtifact{name: artifact.Name, info: info}, nil
}

func validatePublishedArtifacts(directory *os.File, expected map[string]RunArtifact, identities []publishedArtifact) (returnErr error) {
	// The retained directory was opened before its files were created. Some
	// filesystems can keep a stale directory stream on that descriptor. Open a
	// fresh stream relative to the retained descriptor so validation observes
	// the completed set without resolving the mutable public pathname.
	scan, err := openRelativeDirectory(directory, ".")
	if err != nil {
		return err
	}
	defer func() {
		if err := scan.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()
	retainedInfo, retainedErr := directory.Stat()
	scanInfo, scanErr := scan.Stat()
	if retainedErr != nil || scanErr != nil || !os.SameFile(retainedInfo, scanInfo) {
		return fmt.Errorf("published output directory identity changed")
	}
	entries, err := scan.Readdirnames(-1)
	if err != nil {
		return err
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("published output set changed")
	}
	seen := make(map[string]struct{}, len(entries))
	for _, name := range entries {
		artifact, ok := expected[name]
		if !ok {
			return fmt.Errorf("published output name is invalid")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate published output")
		}
		seen[name] = struct{}{}
		file, err := openRelativeFile(scan, name, 0, 0)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, int64(MaxOutputReportBytes)+1))
		closeErr := file.Close()
		if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Mode().Perm() != 0o600 || info.Size() != artifact.Bytes || int64(len(data)) != artifact.Bytes || DigestBytes(data) != artifact.Digest {
			return fmt.Errorf("published output %s closure changed", name)
		}
		for _, identity := range identities {
			if identity.name == name && !os.SameFile(identity.info, info) {
				return fmt.Errorf("published output %s inode changed", name)
			}
		}
	}
	return nil
}

// publishDescriptorBoundDirectory reserves finalName without replacement and
// copies the fixed artifact set from the retained stage descriptor. The stage
// pathname is deliberately used only by the test seam; no source operation
// resolves it.
func publishDescriptorBoundDirectory(parent, stageDirectory *os.File, parentPath, stageName, finalName string, expected map[string]RunArtifact, files []string) error {
	if outputStageRenameHook != nil {
		if err := outputStageRenameHook(stageName); err != nil {
			return err
		}
	}
	if parentPath != "" {
		if err := verifyDirectoryIdentity(parentPath, parent); err != nil {
			return err
		}
	}
	if err := mkdirRelative(parent, finalName, 0o700); err != nil {
		return err
	}
	finalDirectory, err := openRelativeDirectory(parent, finalName)
	if err != nil {
		return err
	}
	created := make([]publishedArtifact, 0, len(files))
	cleanup := func(cause error) error {
		if cleanupErr := cleanupPublishedDirectory(parent, finalDirectory, finalName, created); cleanupErr != nil {
			return fmt.Errorf("%w; final cleanup failed: %v", cause, cleanupErr)
		}
		return cause
	}
	ordered := append([]string(nil), files...)
	sort.Strings(ordered)
	for _, name := range ordered {
		if outputFileCommitHook != nil {
			if err := outputFileCommitHook(finalDirectory, name); err != nil {
				return cleanup(err)
			}
		}
		artifact, ok := expected[name]
		if !ok {
			return cleanup(fmt.Errorf("missing publication descriptor for %s", name))
		}
		published, err := copyPublishedArtifact(stageDirectory, finalDirectory, artifact)
		if err != nil {
			return cleanup(err)
		}
		created = append(created, published)
		if outputFilePostCopyHook != nil {
			if err := outputFilePostCopyHook(finalDirectory, name); err != nil {
				return cleanup(err)
			}
		}
	}
	if outputFinalDirectoryHook != nil {
		if err := outputFinalDirectoryHook(finalDirectory); err != nil {
			return cleanup(err)
		}
	}
	if err := validatePublishedArtifacts(finalDirectory, expected, created); err != nil {
		return cleanup(err)
	}
	if parentPath != "" {
		if err := verifyDirectoryIdentity(parentPath, parent); err != nil {
			return cleanup(err)
		}
	}
	if !finalDirectoryMatches(parent, finalDirectory, finalName) {
		return cleanup(errStageBindingLost)
	}
	if err := syncDirectory(finalDirectory); err != nil {
		return cleanup(err)
	}
	if err := finalDirectory.Close(); err != nil {
		return err
	}
	return nil
}

// validateStagedBatch re-checks the descriptors immediately before commit.
// This catches a symlink, hard-link, unexpected extra entry, or mode/type
// change introduced after Stage returned.  The directory is private, but the
// check is still required because same-UID writers can otherwise alter a
// staged tree before it becomes public.
func (root *OutputRoot) validateStagedBatch() error {
	// Scan through a separately opened descriptor.  The retained staging FD's
	// directory offset is deliberately not consumed: cleanup must still be
	// able to enumerate and remove an untracked rogue entry on failure.
	scan, err := openRelativeDirectory(root.parent, root.stageName)
	if err != nil {
		return fmt.Errorf("inspect staged output: %w", ErrIntegrity)
	}
	entries, err := scan.Readdirnames(-1)
	closeScanErr := scan.Close()
	if err != nil {
		return fmt.Errorf("inspect staged output: %w", ErrIntegrity)
	}
	if closeScanErr != nil {
		return fmt.Errorf("close staged output inspection: %w", ErrIntegrity)
	}
	if len(entries) != len(root.batchFiles) {
		return fmt.Errorf("staged output set changed: %w", ErrIntegrity)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, name := range entries {
		if !validRunArtifactName(name) {
			return fmt.Errorf("staged output name is invalid: %w", ErrIntegrity)
		}
		if _, ok := root.batchFiles[name]; !ok {
			return fmt.Errorf("staged output set changed: %w", ErrIntegrity)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate staged output: %w", ErrIntegrity)
		}
		seen[name] = struct{}{}
		file, err := openRelativeFile(root.directory, name, 0, 0)
		if err != nil {
			return fmt.Errorf("staged output path changed: %w", ErrIntegrity)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Mode().Perm() != 0o600 {
			_ = file.Close()
			return fmt.Errorf("staged output is not a private regular file: %w", ErrIntegrity)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, int64(MaxOutputReportBytes)+1))
		closeErr := file.Close()
		entry := root.batchFiles[name]
		if readErr != nil || closeErr != nil || int64(len(data)) != entry.Bytes || DigestBytes(data) != entry.Digest {
			return fmt.Errorf("staged output bytes changed: %w", ErrIntegrity)
		}
	}
	return nil
}

func (root *OutputRoot) abortBatch() error {
	if root == nil || root.parent == nil {
		return nil
	}
	root.batchStarted = false
	root.batchFiles = nil
	root.batchBytes = 0
	return root.cleanupStage()
}

// Abort is idempotent and closes the retained parent descriptor after
// cleaning the private stage.  Close has the same behavior for deferred use.
func (root *OutputRoot) Abort() error {
	if root == nil || root.parent == nil {
		return nil
	}
	if root.committed {
		return root.Close()
	}
	firstErr := root.abortBatch()
	if err := root.parent.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	root.parent = nil
	return firstErr
}
