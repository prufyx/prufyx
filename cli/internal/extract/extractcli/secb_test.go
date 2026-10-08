// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"os"
	"path/filepath"
	"testing"
)

const secbDay = "2026-10-02T00:00:00Z"

func secbArgs(out string) []string {
	return []string{"run", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", out, "--derived-at", secbDay}
}

// SEC-B F1: an output directory that is a symlink must be refused, not followed.
func TestRunRefusesSymlinkedOutDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "out")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(secbArgs(link)...); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if items, _ := os.ReadDir(target); len(items) != 0 {
		t.Fatalf("symlink target was written: %d entries", len(items))
	}
}

// SEC-B F7a: no temp or staging leftovers beside a finished output.
func TestRunLeavesNoStagingDirs(t *testing.T) {
	parent := t.TempDir()
	if code, _, errs := run(secbArgs(filepath.Join(parent, "out"))...); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	items, _ := os.ReadDir(parent)
	if len(items) != 1 {
		t.Fatalf("parent has %d entries, want only out", len(items))
	}
}

// SEC-B F1: the wants file path must not be a followed symlink.
func TestWantsWriteRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "wants.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	w := &wantsReader{missing: map[wantKey]bool{{repo: "r", commit: "c", path: "p"}: true}, absent: map[string]bool{}, listed: map[string][]string{}}
	if _, err := w.write(link); err == nil {
		t.Fatal("write through a symlink was accepted")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("victim changed: %q", b)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced")
	}
}

// SEC-B B-m3: an existing empty --out keeps its stricter mode, and --out .
// fills the current directory.
func TestRunEmptyOutKeepsModeAndCurrentDirWorks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(secbArgs(dir)...); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("existing --out mode %v err %v, want 0700", st.Mode().Perm(), err)
	}
	abs, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	args := secbArgs(".")
	for i, a := range args {
		if a == fixture {
			args[i] = abs
		}
	}
	if code, _, errs := run(args...); code != 0 {
		t.Fatalf("--out . exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(cwd, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}
