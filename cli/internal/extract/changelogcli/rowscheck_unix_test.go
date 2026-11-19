// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package changelogcli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// specialTargets returns non-regular --targets paths: a symlink to a dir, a
// FIFO and a symlink to a FIFO. None may block or be read.
func specialTargets(t *testing.T, dir, dirLink string) map[string]string {
	t.Helper()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	fl := filepath.Join(dir, "fifolink")
	if err := os.Symlink(fifo, fl); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"symlink to dir": dirLink, "symlink to fifo": fl, "fifo": fifo}
}
