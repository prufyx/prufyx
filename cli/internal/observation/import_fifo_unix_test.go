// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package observation

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestImportRejectsFIFOWithoutBlocking(t *testing.T) {
	root := syntheticRoot(t)
	fifo := filepath.Join(root, "demo", "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	started := time.Now()
	if _, err := importTestPath(t, root); err == nil {
		t.Fatal("Import accepted FIFO")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO import blocked for %s", elapsed)
	}
}
