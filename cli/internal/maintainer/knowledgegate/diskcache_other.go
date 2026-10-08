// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package knowledgegate

import "os"

// openNoFollow refuses a symlink by checking the path first (this platform
// has no O_NOFOLLOW); the caller still checks the open file.
func openNoFollow(p string) (*os.File, error) {
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	return os.Open(p)
}
