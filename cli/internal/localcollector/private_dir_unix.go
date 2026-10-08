// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package localcollector

import (
	"errors"
	"os"
	"syscall"
)

// beforeOpenPrivateDir is a test seam that runs just before the directory is
// opened, where a path swap would matter.
var beforeOpenPrivateDir = func(string) {}

// makeDirPrivate makes path a private (0700) directory owned by the current
// user and returns its identity. The directory is opened with O_NOFOLLOW and
// O_DIRECTORY and every check and the chmod act on that one descriptor, so a
// symlink swapped in at path cannot redirect them (chmod(2) by path would
// follow it).
func makeDirPrivate(path string) (os.FileInfo, error) {
	beforeOpenPrivateDir(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("not owned by the current user")
	}
	if err := f.Chmod(0o700); err != nil {
		return nil, err
	}
	return info, nil
}
