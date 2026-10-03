// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package validation

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// EntryKind is the file type of a directory entry, read without following a
// symlink.
type EntryKind int

const (
	EntryOther EntryKind = iota
	EntryRegular
	EntryDirectory
	EntrySymlink
)

// StatEntry classifies the entry called name inside dir with fstatat and
// AT_SYMLINK_NOFOLLOW, so a symlink is reported as a symlink and no entry is
// opened (which could have side effects for devices). name must be a single
// path element.
func StatEntry(dir *os.File, name string) (EntryKind, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return EntryOther, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return EntryRegular, nil
	case unix.S_IFDIR:
		return EntryDirectory, nil
	case unix.S_IFLNK:
		return EntrySymlink, nil
	}
	return EntryOther, nil
}

// FileIdentity is who a file is: the device and inode pair, the owner and the
// number of hard links.
type FileIdentity struct {
	Dev, Ino, Uid, Nlink uint64
}

// IdentityOf reads the identity from the result of Stat on an open file. It
// reports false when the platform does not provide it.
func IdentityOf(info os.FileInfo) (FileIdentity, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return FileIdentity{}, false
	}
	return FileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Uid: uint64(st.Uid), Nlink: uint64(st.Nlink)}, true
}
