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

// An existing empty output directory keeps its (stricter) mode.
func TestWriteTreeNestedAndEmptyExisting(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "o")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteTree(dir, map[string][]byte{"a/b/c.tsv": []byte("1"), "m.json": []byte("2")}); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]os.FileMode{"": 0o700, "a": 0o755, "a/b": 0o755, "a/b/c.tsv": 0o644, "m.json": 0o644} {
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

// SEC-B F7a: a failure in the middle of the tree leaves no partial output and
// no staging directory. Without staging, "a" would already be in place.
func TestWriteTreeFailureLeavesNothing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "o")
	files := map[string][]byte{"a": []byte("file"), "a/b": []byte("conflict")}
	if err := WriteTree(dir, files); err == nil {
		t.Fatal("conflicting names accepted")
	}
	if items, _ := os.ReadDir(root); len(items) != 0 {
		t.Fatalf("leftovers after a failed write: %v", items)
	}
	// An existing empty output stays as it was: same mode, still empty.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteTree(dir, files); err == nil {
		t.Fatal("conflicting names accepted")
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("existing output changed: %v %v", fi, err)
	}
	if items, _ := os.ReadDir(dir); len(items) != 0 {
		t.Fatalf("partial output in the existing directory: %v", items)
	}
	if items, _ := os.ReadDir(root); len(items) != 1 {
		t.Fatalf("staging leftovers: %v", items)
	}
}

// A mode looser than DirMode is not kept.
func TestWriteTreeExistingModeNeverLoosened(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "o")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o777)
	if err := WriteTree(dir, map[string][]byte{"f": nil}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, want 0755", fi.Mode().Perm())
	}
}

// --out . works: the current directory cannot be replaced, so it is filled.
func TestWriteTreeCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	files := map[string][]byte{"manifest.json": []byte("m"), "reads/x.tsv": []byte("r")}
	if err := WriteTree(".", files); err != nil {
		t.Fatal(err)
	}
	for n, want := range files {
		got, err := os.ReadFile(filepath.FromSlash(n))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
	if fi, _ := os.Stat("."); fi.Mode().Perm() != 0o700 {
		t.Errorf("cwd mode changed to %v", fi.Mode().Perm())
	}
	if items, _ := os.ReadDir("."); len(items) != 2 {
		t.Errorf("entries: %v", items)
	}
}

// A failure while filling the current directory leaves it empty again.
func TestWriteTreeCurrentDirectoryFailure(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := WriteTree(".", map[string][]byte{"a": nil, "a/b": nil}); err == nil {
		t.Fatal("conflicting names accepted")
	}
	if items, _ := os.ReadDir("."); len(items) != 0 {
		t.Fatalf("cwd not empty: %v", items)
	}
}

// A directory that appears at the destination is never replaced.
func TestRenameNoReplaceKeepsDestination(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "from"), 0o755)
	os.Mkdir(filepath.Join(root, "to"), 0o755)
	if err := renameNoReplace(root, "from", "to"); err == nil {
		t.Fatal("existing empty destination was replaced")
	}
	if _, err := os.Stat(filepath.Join(root, "from")); err != nil {
		t.Fatal("source vanished")
	}
}

// syncDir reports a directory that cannot be opened instead of succeeding.
func TestSyncDirReturnsErrors(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("missing directory: err %v", err)
	}
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("real directory: %v", err)
	}
}
