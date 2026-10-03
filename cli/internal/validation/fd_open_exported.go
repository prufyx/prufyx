// SPDX-License-Identifier: AGPL-3.0-only

package validation

import "os"

// The functions below expose the descriptor-relative open helpers to packages
// that walk caller-supplied input trees. Every component is opened with
// no-follow semantics, so a symlink anywhere on the path, or a path swapped
// for a symlink after it was listed, is refused rather than followed.

// OpenInputDirectory opens an existing directory by walking every component of
// its absolute form through retained directory descriptors.
func OpenInputDirectory(path string) (*os.File, error) {
	return openDirectoryPath(path)
}

// OpenInputRegularFile opens a regular file the same way, without blocking on
// FIFOs or devices.
func OpenInputRegularFile(path string) (*os.File, error) {
	return openInputFile(path)
}

// OpenEntryDirectory opens the directory called name inside dir. name must be
// a single path element; a symlink is refused.
func OpenEntryDirectory(dir *os.File, name string) (*os.File, error) {
	return openRelativeDirectory(dir, name)
}

// OpenEntryFile opens the file called name inside dir for reading, without
// following a symlink and without blocking. The caller checks the file type
// on the returned descriptor.
func OpenEntryFile(dir *os.File, name string) (*os.File, error) {
	return openRelativeFile(dir, name, 0, 0)
}
