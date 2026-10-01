// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

import (
	"fmt"
	"os"
)

// OpenDirectoryNoFollow acquires an absolute or relative directory path by
// walking from the filesystem root. Every path component is opened relative
// to the preceding descriptor with O_DIRECTORY and O_NOFOLLOW. The returned
// descriptor, rather than a later pathname reopen, is the authority used by
// descriptor-relative readers.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid directory root: %w", ErrInvalid)
	}
	directory, err := openDirectoryNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open directory root: %w", ErrInvalid)
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_ = directory.Close()
		return nil, fmt.Errorf("validate directory root: %w", ErrInvalid)
	}
	return directory, nil
}

// ReadBoundedRelative reads a private batch input through an already held
// root directory descriptor. Every ancestor and the leaf use no-follow,
// nonblocking descriptor-relative opens; the returned bytes are checked
// against the same descriptor before it closes.
func ReadBoundedRelative(root *os.File, relative string, limit int) ([]byte, error) {
	if root == nil || limit <= 0 || limit > maxBundleBytes {
		return nil, fmt.Errorf("invalid relative input: %w", ErrInvalid)
	}
	return readBoundedRelative(root, relative, limit)
}
