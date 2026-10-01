// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package knowledge

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func platformCanonicalPath(path string) string {
	for _, p := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if path == p[0] {
			return p[1]
		}
		if strings.HasPrefix(path, p[0]+"/") {
			return p[1] + strings.TrimPrefix(path, p[0])
		}
	}
	return path
}

const (
	knowledgeSYSOpenat    = 463
	knowledgeSYSMkdirat   = 475
	knowledgeSYSRenameat  = 465
	knowledgeSYSRenameatx = 488
	knowledgeSYSUnlinkat  = 472
)

func fdPathCall(number uintptr, dir *os.File, name string, flags, mode uintptr) (int, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	raw, _, errno := syscall.Syscall6(number, dir.Fd(), uintptr(unsafe.Pointer(p)), flags, mode, 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(raw), nil
}
func fdOpenRoot() (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/"), nil
}
func fdOpenDir(dir *os.File, name string) (*os.File, error) {
	fd, err := fdPathCall(knowledgeSYSOpenat, dir, name, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func fdMkdir(dir *os.File, name string, mode uint32) error {
	_, err := fdPathCall(knowledgeSYSMkdirat, dir, name, uintptr(mode), 0)
	return err
}
func fdOpenFile(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := fdPathCall(knowledgeSYSOpenat, dir, name, uintptr(flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), uintptr(mode))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func fdRename(dir *os.File, oldName, newName string) error {
	op, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(knowledgeSYSRenameat, dir.Fd(), uintptr(unsafe.Pointer(op)), dir.Fd(), uintptr(unsafe.Pointer(np)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func fdRenameNoReplace(dir *os.File, oldName, newName string) error {
	op, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	const renameExcl = 4
	_, _, errno := syscall.Syscall6(knowledgeSYSRenameatx, dir.Fd(), uintptr(unsafe.Pointer(op)), dir.Fd(), uintptr(unsafe.Pointer(np)), renameExcl, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func fdUnlink(dir *os.File, name string) error {
	_, err := fdPathCall(knowledgeSYSUnlinkat, dir, name, 0, 0)
	return err
}
func fdSync(dir *os.File) error { return syscall.Fsync(int(dir.Fd())) }
