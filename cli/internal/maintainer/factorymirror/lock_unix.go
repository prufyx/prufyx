// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package factorymirror

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// lockOpenedHook, when set (tests only), runs between opening the lock file
// and locking it.
var lockOpenedHook func()

// platformAcquire holds an exclusive flock on the lock file. The file is
// removed by the holder before unlocking; a contender that opened the
// file just before that notices, because its descriptor no longer refers to
// the file at the path, and starts over.
func platformAcquire(path string, body []byte, _ lockRecord, _ time.Duration) (func(), error) {
	for attempt := 0; attempt < 100; attempt++ {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}
		if lockOpenedHook != nil {
			lockOpenedHook()
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				return nil, ErrLocked
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, err
		}
		fi, ferr := f.Stat()
		pi, perr := os.Stat(path)
		if ferr != nil || perr != nil || !os.SameFile(fi, pi) {
			f.Close() // the holder before us removed the file; retry on the new one
			continue
		}
		// The record is informational (who holds the lock).
		if err := f.Truncate(0); err == nil {
			_, _ = f.WriteAt(body, 0)
		}
		return func() {
			_ = os.Remove(path)
			_ = f.Close() // closing drops the flock
		}, nil
	}
	return nil, ErrLocked
}
