// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package knowledge

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDescriptorStoreRejectsNonRegularLinksAndFIFOWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := ensureStoreRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			target := filepath.Join(root, "target")
			if err = os.WriteFile(target, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(root, "selection.json")
			switch kind {
			case "symlink":
				err = os.Symlink(target, name)
			case "hardlink":
				err = os.Link(target, name)
			case "fifo":
				err = syscall.Mkfifo(name, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, e := store.read("selection.json", 64); done <- e }()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("unsafe file accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("read blocked")
			}
		})
	}
}
