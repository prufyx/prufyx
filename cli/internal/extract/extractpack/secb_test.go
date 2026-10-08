// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"os"
	"path/filepath"
	"testing"
)

// SEC-B F1: the pack path must not be a symlink that is replaced or followed.
func TestWriteAtomicRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "pack.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(link, []byte("new")); err == nil {
		t.Fatal("write through a symlink was accepted")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced")
	}
	assertNoTemps(t, root, 2)
}

// SEC-B: a directory at the pack path is not replaced.
func TestWriteAtomicRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pack.json")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("x")); err == nil {
		t.Fatal("directory target accepted")
	}
}

func assertNoTemps(t *testing.T, dir string, want int) {
	t.Helper()
	items, _ := os.ReadDir(dir)
	if len(items) != want {
		t.Fatalf("%s has %d entries, want %d", dir, len(items), want)
	}
}
