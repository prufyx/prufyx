// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package validation

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/prufyx/prufyx/cli/internal/noreplace"
)

func atomicBatchPublicationSupported() bool { return true }

// Darwin's syscall package does not expose openat/mkdirat wrappers, although
// macOS has supported both libc calls since 10.10. Keep the syscall numbers
// local and isolated so CGO=0 builds remain possible on macOS and Linux.
const (
	darwinSYSOpenat   = 463
	darwinSYSMkdirat  = 475
	darwinSYSRenameat = 465
	darwinSYSUnlinkat = 472
)

func darwinPathCall(number uintptr, directory *os.File, name string, flags, mode uintptr) (int, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	raw, _, errno := syscall.Syscall6(number, directory.Fd(), uintptr(unsafe.Pointer(path)), flags, mode, 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(raw), nil
}

func openRootDirectory() (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/"), nil
}

func openRelativeFile(directory *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := darwinPathCall(darwinSYSOpenat, directory, name, uintptr(flags|syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), uintptr(mode))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openRelativeDirectory(directory *os.File, name string) (*os.File, error) {
	fd, err := darwinPathCall(darwinSYSOpenat, directory, name, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func mkdirRelative(directory *os.File, name string, mode uint32) error {
	_, err := darwinPathCall(darwinSYSMkdirat, directory, name, uintptr(mode), 0)
	return err
}

func openRelativeExclusive(directory *os.File, name string, mode uint32) (*os.File, error) {
	fd, err := darwinPathCall(darwinSYSOpenat, directory, name, uintptr(syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), uintptr(mode))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func syncDirectory(directory *os.File) error {
	return syscall.Fsync(int(directory.Fd()))
}

func renameRelative(directory *os.File, oldName, newName string) error {
	oldPath, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinSYSRenameat, directory.Fd(), uintptr(unsafe.Pointer(oldPath)), directory.Fd(), uintptr(unsafe.Pointer(newPath)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func renameRelativeBetween(oldDirectory *os.File, oldName string, newDirectory *os.File, newName string) error {
	oldPath, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinSYSRenameat, oldDirectory.Fd(), uintptr(unsafe.Pointer(oldPath)), newDirectory.Fd(), uintptr(unsafe.Pointer(newPath)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// renameNoReplaceRelative uses renameatx_np(RENAME_EXCL), whose operation is
// atomic with respect to a competing creator and moves the complete staged
// directory in one namespace operation.  The syscall is used directly so
// CGO_ENABLED=0 builds retain the descriptor-relative guarantee.
func renameNoReplaceRelative(directory *os.File, oldName, newName string) error {
	return noreplace.Rename(directory, oldName, newName)
}

func removeRelative(directory *os.File, name string) error {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinSYSUnlinkat, directory.Fd(), uintptr(unsafe.Pointer(path)), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func removeDirectoryRelative(directory *os.File, name string) error {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	const darwinATRemovedir = 0x0080
	_, _, errno := syscall.Syscall6(darwinSYSUnlinkat, directory.Fd(), uintptr(unsafe.Pointer(path)), darwinATRemovedir, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
