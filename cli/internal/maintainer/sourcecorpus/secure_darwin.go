// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package sourcecorpus

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	darwinOpenat   = 463
	darwinMkdirat  = 475
	darwinUnlinkat = 472
)

func pathCall(number uintptr, dir *os.File, name string, flags uintptr) (int, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	raw, _, errno := syscall.Syscall6(number, dir.Fd(), uintptr(unsafe.Pointer(p)), flags, 0, 0, 0)
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
func openRelative(dir *os.File, name string, flags int) (*os.File, error) {
	fd, err := pathCall(darwinOpenat, dir, name, uintptr(flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func openRelativeDirectory(dir *os.File, name string) (*os.File, error) {
	fd, err := pathCall(darwinOpenat, dir, name, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func duplicateFD(fd int) (int, error) { return syscall.Dup(fd) }
func mkdirRelative(dir *os.File, name string, mode uint32) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinMkdirat, dir.Fd(), uintptr(unsafe.Pointer(p)), uintptr(mode), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func createRelativeExclusive(dir *os.File, name string, mode uint32) (*os.File, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	raw, _, errno := syscall.Syscall6(darwinOpenat, dir.Fd(), uintptr(unsafe.Pointer(p)), uintptr(syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), uintptr(mode), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(raw, name), nil
}
func removeRelative(dir *os.File, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinUnlinkat, dir.Fd(), uintptr(unsafe.Pointer(p)), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func removeDirRelative(dir *os.File, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinUnlinkat, dir.Fd(), uintptr(unsafe.Pointer(p)), 0x0080, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func syncFile(file *os.File) error { return syscall.Fsync(int(file.Fd())) }
func platformFileState(info os.FileInfo) (fileState, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileState{}, errRejected
	}
	return fileState{uint64(st.Dev), st.Ino, uint64(st.Nlink), uint64(st.Uid), info.Mode(), info.Size(), st.Mtimespec.Sec*1e9 + st.Mtimespec.Nsec, st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec}, nil
}
