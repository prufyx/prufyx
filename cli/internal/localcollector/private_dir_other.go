// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package localcollector

import (
	"errors"
	"os"
)

var beforeOpenPrivateDir = func(string) {}

// makeDirPrivate on platforms without O_NOFOLLOW and POSIX owners: a
// best-effort Lstat check, then chmod.
func makeDirPrivate(path string) (os.FileInfo, error) {
	beforeOpenPrivateDir(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("not a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return nil, err
	}
	return info, nil
}
