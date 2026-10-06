// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package validation

import "os"

// EntryKind is the file type of a directory entry, read without following a
// symlink.
type EntryKind int

const (
	EntryOther EntryKind = iota
	EntryRegular
	EntryDirectory
	EntrySymlink
)

// StatEntry is unavailable on Windows: it refuses instead of guessing.
func StatEntry(*os.File, string) (EntryKind, error) { return EntryOther, ErrUnsupportedPlatform }

// FileIdentity is who a file is: the device and inode pair, the owner and the
// number of hard links.
type FileIdentity struct {
	Dev, Ino, Uid, Nlink uint64
}

// IdentityOf always reports false on Windows, so callers that require owner
// and link-count checks fail closed.
func IdentityOf(os.FileInfo) (FileIdentity, bool) { return FileIdentity{}, false }
