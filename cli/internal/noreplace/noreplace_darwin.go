// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package noreplace

import (
	"os"
	"syscall"
	"unsafe"
)

// SYS_renameatx_np (macOS 10.12+); the syscall package does not expose it.
const sysRenameatx = 488

// Rename moves oldName to newName inside directory using RENAME_EXCL, which is
// atomic with respect to a competing creator.
func Rename(directory *os.File, oldName, newName string) error {
	oldPath, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	const renameExcl = 0x00000004 // RENAME_EXCL from sys/stdio.h
	_, _, errno := syscall.Syscall6(sysRenameatx, directory.Fd(), uintptr(unsafe.Pointer(oldPath)), directory.Fd(), uintptr(unsafe.Pointer(newPath)), renameExcl, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
