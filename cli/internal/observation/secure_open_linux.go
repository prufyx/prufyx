// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package observation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func observationPlatformSupported() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

func observationDupFile(file *os.File) (*os.File, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(callerFD uintptr) {
		fd, dupErr = syscall.Dup(int(callerFD))
	}); err != nil {
		return nil, err
	}
	if dupErr != nil || fd < 0 {
		return nil, dupErr
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "observation-capability"), nil
}

func observationOpenRoot(path string) (*os.File, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	current, err := os.Open("/")
	if err != nil {
		return nil, "", err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		fd, syscallErr := syscall.Openat(int(current.Fd()), component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if syscallErr != nil {
			_ = current.Close()
			return nil, "", syscallErr
		}
		next := os.NewFile(uintptr(fd), component)
		_ = current.Close()
		current = next
	}
	return current, abs, nil
}

func observationOpenDirectory(directory *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func observationOpenFile(directory *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func observationStableIdentity(file *os.File) (stableIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return stableIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return stableIdentity{}, syscall.EINVAL
	}
	return observationIdentityFromStat(*stat), nil
}

func observationIdentityFromStat(stat syscall.Stat_t) stableIdentity {
	return stableIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink),
		uid: stat.Uid, gid: stat.Gid, rawMode: stat.Mode, size: stat.Size,
		mtimeSec: int64(stat.Mtim.Sec), mtimeNsec: int64(stat.Mtim.Nsec),
		ctimeSec: int64(stat.Ctim.Sec), ctimeNsec: int64(stat.Ctim.Nsec),
	}
}

func observationStatAt(directory *os.File, name string) (stableIdentity, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return stableIdentity{}, err
	}
	var stat syscall.Stat_t
	const observationATSymlinkNoFollow = 0x100
	_, _, errno := syscall.Syscall6(observationFstatatSyscall, directory.Fd(), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&stat)), observationATSymlinkNoFollow, 0, 0)
	if errno != 0 {
		return stableIdentity{}, errno
	}
	return observationIdentityFromStat(stat), nil
}
