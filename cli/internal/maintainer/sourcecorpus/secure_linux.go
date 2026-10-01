// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sourcecorpus

import (
	"os"
	"syscall"
	"unsafe"
)

func openRootDirectory() (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/"), nil
}
func openRelative(dir *os.File, name string, flags int) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func openRelativeDirectory(dir *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func duplicateFD(fd int) (int, error) { return syscall.Dup(fd) }
func mkdirRelative(dir *os.File, name string, mode uint32) error {
	return syscall.Mkdirat(int(dir.Fd()), name, mode)
}
func createRelativeExclusive(dir *os.File, name string, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func removeRelative(dir *os.File, name string) error { return syscall.Unlinkat(int(dir.Fd()), name) }
func removeDirRelative(dir *os.File, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_UNLINKAT, dir.Fd(), uintptr(unsafe.Pointer(p)), uintptr(0x200), 0, 0, 0)
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
	return fileState{uint64(st.Dev), st.Ino, uint64(st.Nlink), uint64(st.Uid), info.Mode(), info.Size(), st.Mtim.Sec*1e9 + st.Mtim.Nsec, st.Ctim.Sec*1e9 + st.Ctim.Nsec}, nil
}
