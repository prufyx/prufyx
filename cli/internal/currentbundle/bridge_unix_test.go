// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package currentbundle

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadBoundedFile_FIFOIsRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadBoundedFile(path, maxBundleBytes); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO read blocked")
	}
}
