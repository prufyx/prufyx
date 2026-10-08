// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || (linux && (amd64 || arm64))

package noreplace

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRenameNeverReplaces(t *testing.T) {
	root := t.TempDir()
	d, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	os.Mkdir(filepath.Join(root, "a"), 0o755)
	os.Mkdir(filepath.Join(root, "b"), 0o755)
	if err := Rename(d, "a", "b"); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("rename onto an existing empty directory: %v, want EEXIST", err)
	}
	if err := Rename(d, "a", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "c")); err != nil {
		t.Fatal(err)
	}
}
