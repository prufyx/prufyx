// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package currentbundle

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const currentbundleSYSOpenat = 463

func currentbundleOpenat(directory *os.File, name string, flags, mode uintptr) (*os.File, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	raw, _, errno := syscall.Syscall6(currentbundleSYSOpenat, directory.Fd(), uintptr(unsafe.Pointer(path)), flags, mode, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(uintptr(raw), name), nil
}

func openArtifactFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	for _, pair := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if abs == pair[0] {
			abs = pair[1]
		} else if strings.HasPrefix(abs, pair[0]+string(filepath.Separator)) {
			abs = pair[1] + strings.TrimPrefix(abs, pair[0])
		}
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return nil, syscall.EINVAL
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	directory := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, syscall.EINVAL
		}
		next, err := currentbundleOpenat(directory, part, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
		if err != nil {
			return nil, err
		}
		if directory != root {
			_ = directory.Close()
		}
		directory = next
	}
	file, err := currentbundleOpenat(directory, parts[len(parts)-1], uintptr(flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), uintptr(mode.Perm()))
	if directory != root {
		_ = directory.Close()
	}
	return file, err
}

func artifactLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}
