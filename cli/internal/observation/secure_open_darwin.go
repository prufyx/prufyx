// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

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

const observationSYSOpenat = 463

func observationOpenAt(directory *os.File, name string, flags, mode uintptr) (*os.File, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	raw, _, errno := syscall.Syscall6(observationSYSOpenat, directory.Fd(), uintptr(unsafe.Pointer(path)), flags, mode, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(uintptr(raw), name), nil
}

func observationOpenRoot(path string) (*os.File, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	abs = observationNormalizeDarwinPath(abs)
	current, err := os.Open("/")
	if err != nil {
		return nil, "", err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := observationOpenAt(current, component, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
		_ = current.Close()
		if openErr != nil {
			return nil, "", openErr
		}
		current = next
	}
	return current, abs, nil
}

func observationNormalizeDarwinPath(path string) string {
	for _, pair := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if path == pair[0] {
			return pair[1]
		}
		if strings.HasPrefix(path, pair[0]+string(filepath.Separator)) {
			return pair[1] + strings.TrimPrefix(path, pair[0])
		}
	}
	return path
}

func observationOpenDirectory(directory *os.File, name string) (*os.File, error) {
	return observationOpenAt(directory, name, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
}

func observationOpenFile(directory *os.File, name string) (*os.File, error) {
	return observationOpenAt(directory, name, uintptr(syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
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
		uid: stat.Uid, gid: stat.Gid, rawMode: uint32(stat.Mode), size: stat.Size,
		mtimeSec: stat.Mtimespec.Sec, mtimeNsec: stat.Mtimespec.Nsec,
		ctimeSec: stat.Ctimespec.Sec, ctimeNsec: stat.Ctimespec.Nsec,
		generation: uint64(stat.Gen),
	}
}

func observationStatAt(directory *os.File, name string) (stableIdentity, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return stableIdentity{}, err
	}
	var stat syscall.Stat_t
	const observationSYSFstatat = 470
	const observationATSymlinkNoFollow = 0x20
	_, _, errno := syscall.Syscall6(observationSYSFstatat, directory.Fd(), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&stat)), observationATSymlinkNoFollow, 0, 0)
	if errno != 0 {
		return stableIdentity{}, errno
	}
	return observationIdentityFromStat(stat), nil
}
