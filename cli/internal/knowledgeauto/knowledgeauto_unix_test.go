// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package knowledgeauto

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsureRootPrivateUnderAnyUmask(t *testing.T) {
	for _, mask := range []int{0o022, 0o002} {
		old := syscall.Umask(mask)
		base := t.TempDir()
		t.Setenv("XDG_DATA_HOME", base)
		root, err := EnsureRoot()
		syscall.Umask(old)
		if err != nil {
			t.Fatal(err)
		}
		for dir := root; dir != base; dir = filepath.Dir(dir) {
			info, err := os.Stat(dir)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("umask %o: %s mode %v err %v", mask, dir, info.Mode().Perm(), err)
			}
		}
	}
}

func TestEnsureRootEmptyHomeAnyUmask(t *testing.T) {
	for _, mask := range []int{0o022, 0o002} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_DATA_HOME", "")
		old := syscall.Umask(mask)
		root, err := EnsureRoot()
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %o: %v", mask, err)
		}
		// .local, share, prufyx, knowledge and cncf-projects were all missing.
		for dir := root; dir != home; dir = filepath.Dir(dir) {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
				t.Fatalf("umask %o: %s: %v %v", mask, dir, info, err)
			}
		}
		// Idempotent.
		if again, err := EnsureRoot(); err != nil || again != root {
			t.Fatalf("again: %q %v", again, err)
		}
	}
}
