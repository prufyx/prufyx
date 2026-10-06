// SPDX-License-Identifier: AGPL-3.0-only

package knowledgeauto

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func TestDefaultRoot(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/data")
	if root, ok := DefaultRoot(); !ok || root != "/data/prufyx/knowledge/cncf-projects" {
		t.Fatalf("xdg: %q %v", root, ok)
	}
	t.Setenv("XDG_DATA_HOME", "relative")
	t.Setenv("HOME", "/home/u")
	if root, ok := DefaultRoot(); !ok || root != "/home/u/.local/share/prufyx/knowledge/cncf-projects" {
		t.Fatalf("home: %q %v", root, ok)
	}
}

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

func TestLocate(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	if _, present, err := Locate(); present || err != nil {
		t.Fatalf("absent: %v %v", present, err)
	}
	root, err := EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); present || err != nil {
		t.Fatalf("empty dir is no store: %v %v", present, err)
	}
	if err := os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("not a store: %v %v", present, err)
	}
	if err := os.WriteFile(filepath.Join(root, "profile.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || err != nil {
		t.Fatalf("store: %v %v", present, err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("mode: %v %v", present, err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, root); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("symlink: %v %v", present, err)
	}
}

func TestCheckPinAndReason(t *testing.T) {
	good := "sha256:" + "ab01234567890123456789012345678901234567890123456789012345678901"
	if CheckPin("", "anything") != nil || CheckPin(good, good) != nil || CheckPin(good, good[7:]) != nil {
		t.Fatal("accepted cases refused")
	}
	if !errors.Is(CheckPin(good, "sha256:"+"cd01234567890123456789012345678901234567890123456789012345678901"), ErrRefused) || !errors.Is(CheckPin(good, ""), ErrRefused) {
		t.Fatal("wrong root accepted")
	}
	if Reason(knowledge.ErrExpired) == Reason(knowledge.ErrRollback) || Reason(errors.New("x")) == "" {
		t.Fatal("reason classes")
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

func TestEnsureRootRefusesSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureRoot(); err == nil {
		t.Fatal("a symbolic link parent was followed")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("created through a link: %v", entries)
	}
}

func TestLocateNeverCommittedStoreIsAbsent(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	root, err := EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What a failed first import leaves.
	write(".lock")
	write("profile.json")
	write("clock-floor.json")
	if err := os.Mkdir(filepath.Join(root, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); err != nil || present {
		t.Fatalf("bootstrap leftovers: present=%v err=%v", present, err)
	}
	// A committed selection, a pending import, or anything else is refused or present.
	for _, name := range []string{"selection.json", "import-pending.json"} {
		write(name)
		if _, present, err := Locate(); err != nil || !present {
			t.Fatalf("%s: present=%v err=%v", name, present, err)
		}
		os.Remove(filepath.Join(root, name))
	}
	if err := os.Mkdir(filepath.Join(root, "admissions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, present, _ := Locate(); !present {
		t.Fatal("a store with admissions counted as absent")
	}
	os.Remove(filepath.Join(root, "admissions"))
	// A symbolic link in place of an artefact is not a leftover.
	os.Remove(filepath.Join(root, "clock-floor.json"))
	if err := os.Symlink("/etc/hosts", filepath.Join(root, "clock-floor.json")); err != nil {
		t.Fatal(err)
	}
	if _, present, _ := Locate(); !present {
		t.Fatal("a symbolic link counted as absent")
	}
}

func TestStalenessNote(t *testing.T) {
	note := StalenessNote("2026-01-02T03:04:05Z", "2026-04-02T00:00:00Z")
	for _, want := range []string{"2026-01-02T03:04:05Z", "expires 2026-04-02T00:00:00Z", "older than the embedded"} {
		if !strings.Contains(note, want) {
			t.Fatalf("%q lacks %q", note, want)
		}
	}
}
