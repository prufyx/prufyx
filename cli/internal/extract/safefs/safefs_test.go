// SPDX-License-Identifier: AGPL-3.0-only

package safefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTreeRefusals(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"../x", "/abs", "a/../../x", "a//b", "", "a\\b", "./a"} {
		if err := WriteTree(filepath.Join(root, "o"), map[string][]byte{name: []byte("x")}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "o")); err == nil {
		t.Error("output created for refused names")
	}
	if items, _ := os.ReadDir(root); len(items) != 0 {
		t.Errorf("leftovers: %d", len(items))
	}
	if err := os.Mkdir(filepath.Join(root, "full"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "full", "f"), nil, 0o644)
	if err := WriteTree(filepath.Join(root, "full"), map[string][]byte{"a": nil}); err == nil {
		t.Error("non-empty dir accepted")
	}
}

func TestWriteTreeNestedAndEmptyExisting(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "o")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteTree(dir, map[string][]byte{"a/b/c.tsv": []byte("1"), "m.json": []byte("2")}); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]os.FileMode{"": 0o755, "a": 0o755, "a/b": 0o755, "a/b/c.tsv": 0o644, "m.json": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, p))
		if err != nil || fi.Mode().Perm() != m {
			t.Errorf("%q: %v %v want %v", p, fi, err, m)
		}
	}
	if items, _ := os.ReadDir(root); len(items) != 1 {
		t.Errorf("staging leftover: %d entries", len(items))
	}
}

func TestWriteFileRefusesNonRegular(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(root, "dangling"), []byte("x"), 0o644); err == nil {
		t.Error("dangling symlink accepted")
	}
	if _, err := os.Lstat(filepath.Join(root, "nowhere")); err == nil {
		t.Error("link target created")
	}
	if err := WriteFile(filepath.Join(root, "missingdir", "f"), nil, 0o644); err == nil {
		t.Error("missing parent accepted")
	}
}

func TestWriteFileSymlinkedParentDir(t *testing.T) {
	// A symlinked parent is the caller's own path (e.g. /tmp on macOS); only
	// the final component is policed. The write lands in the real directory.
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o755)
	os.Symlink(real, filepath.Join(root, "ln"))
	if err := WriteFile(filepath.Join(root, "ln", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(real, "f")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(fi, err)
	}
}
