// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledge

import (
	"os"
	"syscall"
	"unsafe"
)

func platformCanonicalPath(path string) string { return path }

func fdOpenRoot() (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/"), nil
}
func fdOpenDir(dir *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func fdMkdir(dir *os.File, name string, mode uint32) error {
	return syscall.Mkdirat(int(dir.Fd()), name, mode)
}
func fdOpenFile(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func fdRename(dir *os.File, oldName, newName string) error {
	return syscall.Renameat(int(dir.Fd()), oldName, int(dir.Fd()), newName)
}
func fdRenameNoReplace(dir *os.File, oldName, newName string) error {
	const renameNoReplace = 1
	op, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(knowledgeSYSRenameat2, dir.Fd(), uintptr(unsafe.Pointer(op)), dir.Fd(), uintptr(unsafe.Pointer(np)), renameNoReplace, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func fdUnlink(dir *os.File, name string) error { return syscall.Unlinkat(int(dir.Fd()), name) }
func fdSync(dir *os.File) error                { return syscall.Fsync(int(dir.Fd())) }
