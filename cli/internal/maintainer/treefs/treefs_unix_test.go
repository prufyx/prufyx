// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package treefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"syscall"
)

func within(t *testing.T, name string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s blocked", name)
	}
}

func TestReadAndWriteRefuseLinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	must(os.WriteFile(filepath.Join(root, "a", "b", "plain.txt"), []byte("plain"), 0o644))
	must(os.Symlink(secret, filepath.Join(root, "a", "b", "leaf.txt")))
	must(os.Symlink(outside, filepath.Join(root, "a", "linkdir")))
	must(syscall.Mkfifo(filepath.Join(root, "a", "b", "pipe"), 0o600))
	must(os.WriteFile(filepath.Join(root, "a", "big.txt"), []byte("0123456789"), 0o644))

	if raw, err := Read(root, "a/b/plain.txt", 100); err != nil || string(raw) != "plain" {
		t.Fatalf("plain read: %q %v", raw, err)
	}
	for _, rel := range []string{"a/b/leaf.txt", "a/linkdir/secret.txt", "a/b/pipe", "a/b", "a/missing.txt", "../x", "/abs", "a//b/plain.txt"} {
		within(t, "read "+rel, func() {
			if raw, err := Read(root, rel, 100); err == nil {
				t.Errorf("read %s accepted: %q", rel, raw)
			}
		})
	}
	if _, err := Read(root, "a/big.txt", 9); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("size cap: %v", err)
	}
	if _, err := Read(root, "a/big.txt", 10); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"a/b/leaf.txt", "a/linkdir/secret.txt", "a/b/pipe", "a/b", "a/nodir/x.txt"} {
		within(t, "write "+rel, func() {
			if err := Write(root, rel, []byte("clobbered"), 0o644); err == nil {
				t.Errorf("write %s accepted", rel)
			}
		})
	}
	if raw, _ := os.ReadFile(secret); string(raw) != "outside" {
		t.Fatalf("a file outside the root was written through a link: %q", raw)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("something was created outside the root: %v", ents)
	}

	// A regular file is replaced atomically with the requested mode, a new
	// file is created, and no staging file is left behind.
	must(Write(root, "a/b/plain.txt", []byte("new"), 0o640))
	must(Write(root, "a/b/created.txt", []byte("made"), 0o644))
	if raw, _ := os.ReadFile(filepath.Join(root, "a", "b", "plain.txt")); string(raw) != "new" {
		t.Fatalf("replace: %q", raw)
	}
	if info, _ := os.Stat(filepath.Join(root, "a", "b", "plain.txt")); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode())
	}
	ents, _ := os.ReadDir(filepath.Join(root, "a", "b"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".treefs-") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}
}

// A FIFO given as the root fails at once with "not a directory"; opening it
// for reading would block forever.
func TestOpenDirRefusesAFIFORootWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("fifo unavailable")
	}
	within(t, "OpenDir fifo", func() {
		d, err := OpenDir(fifo, "")
		if err == nil {
			d.Close()
			t.Error("FIFO root accepted")
		} else if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
