// SPDX-License-Identifier: AGPL-3.0-only

package sourcecorpus

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// WriteFailure reports whether all locally created output was removed. It
// never includes a path or retained data in its message.
type WriteFailure struct{ Cleanup string }

func (failure *WriteFailure) Error() string { return "capture write rejected" }

// ReadPrivateFile safely admits a single-link, owner-only regular file.
func ReadPrivateFile(path string, maximum int64) ([]byte, error) {
	file, err := openPhysical(path, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer file.Close()
	return readOwnerOnlyRegular(file, maximum)
}

// ReadRegularFile safely admits a single-link regular file. Unlike
// ReadPrivateFile it does not require owner-only permissions, so it can read
// public review inputs such as exported targets and checked-in vectors.
func ReadRegularFile(path string, maximum int64) ([]byte, error) {
	return readPhysicalFile(path, maximum, false)
}

// ReadPrivateTreeFile reads one fixed relative regular file below a private
// directory using the same no-follow descriptor walk as corpus collections.
func ReadPrivateTreeFile(rootPath, relative string, maximum int64) ([]byte, error) {
	root, err := openPhysical(rootPath, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer root.Close()
	if validatePrivateDirectory(root) != nil {
		return nil, errRejected
	}
	return readRelativeFile(root, relative, maximum, true)
}

// WriteNewPrivateFile writes one no-follow, exclusive owner-only regular file
// and fsyncs its private parent. It is for small local request manifests.
func WriteNewPrivateFile(path string, data []byte) error {
	if len(data) < 1 || int64(len(data)) > maxManifestBytes {
		return errRejected
	}
	parentPath, name := filepath.Dir(path), filepath.Base(path)
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(name) {
		return errRejected
	}
	// filepath.Dir returns "." for a normal relative leaf. Resolve only that
	// process-owned directory handle; openPhysical still walks every physical
	// component with no-follow semantics and the leaf is created with O_EXCL.
	if parentPath == "." {
		var err error
		parentPath, err = os.Getwd()
		if err != nil {
			return errRejected
		}
	}
	parent, err := openPhysical(parentPath, os.O_RDONLY)
	if err != nil {
		return errRejected
	}
	defer parent.Close()
	if validateOwnerOnlyDirectory(parent) != nil {
		return errRejected
	}
	item, err := createBoundFile(parent, name, data)
	if item != nil {
		defer item.file.Close()
	}
	if err != nil {
		if item != nil {
			_ = removeRelative(parent, name)
		}
		return errRejected
	}
	if syncFile(parent) != nil || !createdFileMatches(item) {
		_ = removeRelative(parent, name)
		return errRejected
	}
	return nil
}

// ValidatePrivateDirectoryPath admits an owner-only directory through a
// no-follow descriptor walk. Callers use it before any network activity.
func ValidatePrivateDirectoryPath(path string) error {
	directory, err := openPhysical(path, os.O_RDONLY)
	if err != nil {
		return errRejected
	}
	defer directory.Close()
	return validateOwnerOnlyDirectory(directory)
}

// EnsurePrivateChildAbsent rejects an existing destination through the same
// descriptor-bound parent used by final output creation.
func EnsurePrivateChildAbsent(parentPath, name string) error {
	if !regexpCaptureName.MatchString(name) {
		return errRejected
	}
	parent, err := openPhysical(parentPath, os.O_RDONLY)
	if err != nil {
		return errRejected
	}
	defer parent.Close()
	if validateOwnerOnlyDirectory(parent) != nil {
		return errRejected
	}
	probe, probeErr := openRelative(parent, name, os.O_RDONLY)
	if probeErr == nil {
		_ = probe.Close()
		return errRejected
	}
	if !errors.Is(probeErr, syscall.ENOENT) {
		return errRejected
	}
	return nil
}

type createdFile struct {
	directory *os.File
	name      string
	file      *os.File
	state     fileState
	digest    string
}

type createdDirectory struct {
	parent *os.File
	name   string
	held   *os.File
	state  fileState
}

func directoryEntryMatches(parent *os.File, name string, held *os.File, expected fileState) bool {
	current, err := openRelativeDirectory(parent, name)
	if err != nil {
		return false
	}
	defer current.Close()
	currentState, currentErr := stateOf(current)
	heldState, heldErr := stateOf(held)
	return currentErr == nil && heldErr == nil && currentState.device == expected.device && currentState.inode == expected.inode && heldState.device == expected.device && heldState.inode == expected.inode && validatePrivateDirectory(current) == nil && validatePrivateDirectory(held) == nil
}

func createdFileMatches(item *createdFile) bool {
	current, err := openRelative(item.directory, item.name, os.O_RDONLY)
	if err != nil {
		return false
	}
	defer current.Close()
	currentState, currentErr := stateOf(current)
	heldState, heldErr := stateOf(item.file)
	if currentErr != nil || heldErr != nil || currentState != item.state || heldState != item.state || currentState.mode.Perm() != 0o600 || currentState.uid != uint64(os.Geteuid()) || currentState.links != 1 {
		return false
	}
	if _, err = item.file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(item.file, item.state.size+1))
	return err == nil && int64(len(data)) == item.state.size && SHA(data) == item.digest
}

func createBoundFile(directory *os.File, name string, data []byte) (*createdFile, error) {
	file, err := createRelativeExclusive(directory, name, 0o600)
	if err != nil {
		return nil, errRejected
	}
	item := &createdFile{directory: directory, name: name, file: file, digest: SHA(data)}
	state, stateErr := stateOf(file)
	if stateErr != nil {
		return item, errRejected
	}
	item.state = state
	if !state.mode.IsRegular() || state.mode.Perm() != 0o600 || state.uid != uint64(os.Geteuid()) || state.links != 1 {
		return item, errRejected
	}
	written := 0
	for written < len(data) {
		amount, writeErr := file.Write(data[written:])
		if writeErr != nil || amount <= 0 {
			return item, errRejected
		}
		written += amount
	}
	if err = syncFile(file); err != nil {
		return item, errRejected
	}
	item.state, err = stateOf(file)
	if err != nil || item.state.size != int64(len(data)) || !createdFileMatches(item) {
		return item, errRejected
	}
	return item, nil
}

// WriteCaptureTree creates the exclusive private capture layout and writes the
// receipt completion marker last. Object keys are sha256:<hex> digests.
func WriteCaptureTree(parentPath, destination string, objects map[string][]byte, manifest, receipt []byte) error {
	return writeTree(parentPath, destination, objects, []treeFile{
		{"CANDIDATE-CORPUS-MANIFEST.json", manifest},
		{"CAPTURE-RECEIPT.json", receipt},
	}, regexpCaptureName)
}

// WriteProjectSnapshotTree writes the fixed, private project-onboarding
// snapshot layout. The receipt is the completion marker and is written last.
// It deliberately accepts no caller-controlled paths or file names.
func WriteProjectSnapshotTree(parentPath, destination string, objects map[string][]byte, snapshot, manifest, receipt []byte) error {
	files := []treeFile{{"PROJECT-ONBOARDING-SNAPSHOT.json", snapshot}}
	if len(manifest) > 0 {
		files = append(files, treeFile{"SOURCE-CORPUS-MANIFEST.json", manifest})
	}
	files = append(files, treeFile{"SYNC-RECEIPT.json", receipt})
	return writeTree(parentPath, destination, objects, files, regexpSnapshotName)
}

type treeFile struct {
	name string
	data []byte
}

func writeTree(parentPath, destination string, objects map[string][]byte, files []treeFile, destinationPattern *regexp.Regexp) error {
	if !destinationPattern.MatchString(destination) {
		return errRejected
	}
	parent, err := openPhysical(parentPath, os.O_RDONLY)
	if err != nil {
		return errRejected
	}
	defer parent.Close()
	if validateOwnerOnlyDirectory(parent) != nil {
		return errRejected
	}
	parentState, _ := stateOf(parent)
	probe, probeErr := openRelative(parent, destination, os.O_RDONLY)
	if probeErr == nil {
		_ = probe.Close()
		return errRejected
	}
	if !errors.Is(probeErr, syscall.ENOENT) {
		return errRejected
	}
	createdFiles := []*createdFile{}
	directories := []*createdDirectory{}
	cleanup := func() string {
		complete := true
		for i := len(createdFiles) - 1; i >= 0; i-- {
			item := createdFiles[i]
			state, stateErr := stateOf(item.file)
			if stateErr != nil || state.device != item.state.device || state.inode != item.state.inode || state.links != 1 || state.uid != uint64(os.Geteuid()) || state.mode.Perm() != 0o600 || removeRelative(item.directory, item.name) != nil {
				complete = false
			}
			_ = item.file.Close()
		}
		for i := len(directories) - 1; i >= 0; i-- {
			item := directories[i]
			if !directoryEntryMatches(item.parent, item.name, item.held, item.state) || removeDirRelative(item.parent, item.name) != nil {
				complete = false
			}
			_ = item.held.Close()
		}
		if complete {
			return "COMPLETE"
		}
		return "INCOMPLETE"
	}
	fail := func() error { return &WriteFailure{Cleanup: cleanup()} }
	makeDirectory := func(parentDir *os.File, name string) (*createdDirectory, error) {
		if mkdirRelative(parentDir, name, 0o700) != nil {
			return nil, errRejected
		}
		held, openErr := openRelativeDirectory(parentDir, name)
		if openErr != nil {
			return nil, errRejected
		}
		state, stateErr := stateOf(held)
		item := &createdDirectory{parent: parentDir, name: name, held: held, state: state}
		directories = append(directories, item)
		if stateErr != nil || validatePrivateDirectory(held) != nil || !directoryEntryMatches(parentDir, name, held, state) {
			return nil, errRejected
		}
		return item, nil
	}
	destinationDir, err := makeDirectory(parent, destination)
	if err != nil {
		return fail()
	}
	objectsDir, err := makeDirectory(destinationDir.held, "objects")
	if err != nil {
		return fail()
	}
	shaDir, err := makeDirectory(objectsDir.held, "sha256")
	if err != nil {
		return fail()
	}
	intact := func() bool {
		currentParent, stateErr := stateOf(parent)
		if stateErr != nil || currentParent.device != parentState.device || currentParent.inode != parentState.inode || currentParent.mode.Perm()&0o077 != 0 || currentParent.uid != uint64(os.Geteuid()) {
			return false
		}
		for _, item := range directories {
			if !directoryEntryMatches(item.parent, item.name, item.held, item.state) {
				return false
			}
		}
		for _, item := range createdFiles {
			if !createdFileMatches(item) {
				return false
			}
		}
		return true
	}
	digests := make([]string, 0, len(objects))
	for digest := range objects {
		if !shaPattern.MatchString(digest) {
			return fail()
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		if !intact() {
			return fail()
		}
		item, createErr := createBoundFile(shaDir.held, strings.TrimPrefix(digest, "sha256:"), objects[digest])
		if item != nil {
			createdFiles = append(createdFiles, item)
		}
		if createErr != nil {
			return fail()
		}
	}
	for _, file := range files {
		file.data = append(append([]byte{}, file.data...), '\n')
		if !intact() {
			return fail()
		}
		item, createErr := createBoundFile(destinationDir.held, file.name, file.data)
		if item != nil {
			createdFiles = append(createdFiles, item)
		}
		if createErr != nil {
			return fail()
		}
	}
	if syncFile(shaDir.held) != nil || syncFile(objectsDir.held) != nil || syncFile(destinationDir.held) != nil || syncFile(parent) != nil || !intact() {
		return fail()
	}
	for _, item := range createdFiles {
		_ = item.file.Close()
	}
	for i := len(directories) - 1; i >= 0; i-- {
		_ = directories[i].held.Close()
	}
	return nil
}

var regexpCaptureName = regexp.MustCompile(`^capture-[0-9a-f]{64}$`)
var regexpSnapshotName = regexp.MustCompile(`^snapshot-[0-9a-f]{64}$`)
