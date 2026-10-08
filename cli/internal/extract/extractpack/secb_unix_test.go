// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package extractpack

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// SEC-B F6a/F7a: new file gets 0644 regardless of umask, an existing mode is kept.
func TestWriteAtomicModes(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	p := filepath.Join(dir, "pack.json")
	if err := writeAtomic(p, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("new mode %v", fi.Mode().Perm())
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("kept mode %v", fi.Mode().Perm())
	}
	assertNoTemps(t, dir, 1)
}
