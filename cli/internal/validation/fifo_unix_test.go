// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package validation

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadContracts_RejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "input.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProposedBundle(fifoPath); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("FIFO error = %v, want fail-closed path error", err)
	}
	_ = os.Remove(fifoPath)
}
