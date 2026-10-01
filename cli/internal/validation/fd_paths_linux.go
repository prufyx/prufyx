// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package validation

import (
	"os"
	"syscall"
	"unsafe"
)

func atomicBatchPublicationSupported() bool { return true }

func openRootDirectory() (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/"), nil
}

func openRelativeFile(directory *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, flags|syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openRelativeDirectory(directory *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func mkdirRelative(directory *os.File, name string, mode uint32) error {
	return syscall.Mkdirat(int(directory.Fd()), name, mode)
}

func openRelativeExclusive(directory *os.File, name string, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func syncDirectory(directory *os.File) error {
	return syscall.Fsync(int(directory.Fd()))
}

func renameRelative(directory *os.File, oldName, newName string) error {
	return syscall.Renameat(int(directory.Fd()), oldName, int(directory.Fd()), newName)
}

// renameNoReplaceRelative closes the check/rename race: unlike rename(2),
// renameat2 with RENAME_NOREPLACE never replaces a concurrently-created
// destination. Linux filesystems that do not implement the flag fail closed.
func renameNoReplaceRelative(directory *os.File, oldName, newName string) error {
	const renameNoReplace = 1
	oldPath, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(linuxSYSRenameat2, directory.Fd(), uintptr(unsafe.Pointer(oldPath)), directory.Fd(), uintptr(unsafe.Pointer(newPath)), renameNoReplace, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func removeRelative(directory *os.File, name string) error {
	return syscall.Unlinkat(int(directory.Fd()), name)
}

func removeDirectoryRelative(directory *os.File, name string) error {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	// syscall.Unlinkat does not expose flags on all supported Go versions.
	// AT_REMOVEDIR keeps cleanup descriptor-relative and prevents recursive
	// deletion of anything outside the owned staging directory.
	_, _, errno := syscall.Syscall6(syscall.SYS_UNLINKAT, directory.Fd(), uintptr(unsafe.Pointer(path)), uintptr(0x200), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
