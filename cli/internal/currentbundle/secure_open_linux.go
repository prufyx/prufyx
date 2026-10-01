// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package currentbundle

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openArtifactFile resolves every parent component from a directory
// descriptor. No path component, including the parent, may be a symlink.
func openArtifactFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
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
		fd, err := syscall.Openat(int(directory.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		next := os.NewFile(uintptr(fd), part)
		if directory != root {
			_ = directory.Close()
		}
		directory = next
	}
	fd, err := syscall.Openat(int(directory.Fd()), parts[len(parts)-1], flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if directory != root {
		_ = directory.Close()
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), parts[len(parts)-1]), nil
}

func artifactLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}
