// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux && (amd64 || arm64)

package noreplace

import (
	"os"
	"syscall"
	"unsafe"
)

// Rename moves oldName to newName inside directory. Unlike rename(2) it never
// replaces a concurrently created destination (EEXIST). Filesystems that do
// not implement the flag fail with EINVAL.
func Rename(directory *os.File, oldName, newName string) error {
	const renameNoReplace = 1
	oldPath, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(sysRenameat2, directory.Fd(), uintptr(unsafe.Pointer(oldPath)), directory.Fd(), uintptr(unsafe.Pointer(newPath)), renameNoReplace, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
