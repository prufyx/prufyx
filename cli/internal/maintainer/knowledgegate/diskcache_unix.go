// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package knowledgegate

import (
	"os"
	"syscall"
)

// openNoFollow opens a cache file for reading without following a symlink
// and without blocking on a FIFO.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
