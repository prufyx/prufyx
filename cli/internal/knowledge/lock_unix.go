// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux || darwin

package knowledge

import (
	"errors"
	"os"
	"syscall"
)

func fileNlink(i os.FileInfo) uint64 {
	if st, ok := i.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

func lockFileExclusiveNonBlocking(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func lockWouldBlock(err error) bool { return errors.Is(err, syscall.EWOULDBLOCK) }

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
