// SPDX-License-Identifier: AGPL-3.0-only

package safefs

import (
	"errors"
	"os"
)

// OpenRegular opens p for reading without following a final symlink and
// without blocking on a FIFO, then checks on the descriptor itself that it is
// a regular file; anything else is refused and closed. Where the platform has
// no no-follow flag a symlink is refused by Lstat first.
func OpenRegular(p string) (*os.File, error) {
	if noFollow == 0 {
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("not a plain file")
		}
	}
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}
