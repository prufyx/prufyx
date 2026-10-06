// SPDX-License-Identifier: AGPL-3.0-only

package knowledgeauto

import (
	"errors"
	"os"
	"path/filepath"
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
