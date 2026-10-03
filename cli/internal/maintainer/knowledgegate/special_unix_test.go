// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Head files are read only through the no-follow, non-blocking, bounded
// reader: a link to a file outside the tree is never read (its content
// cannot leak into the report), a FIFO never blocks the gate, and the tree
// check names them.
func TestHeadSpecialFilesAreNeverRead(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "runner-secret")
	writeFile(t, secret, []byte(`{"token":"do-not-print-0f1e2d"}`))
	for name, tc := range map[string]struct {
		rel  string
		make func(t *testing.T, full string)
	}{
		"inventory input links outside": {"cli/internal/spiffex509svid/data/profile.json", func(t *testing.T, full string) {
			if err := os.Symlink(secret, full); err != nil {
				t.Fatal(err)
			}
		}},
		"attestation input links outside": {"cli/internal/cncfcheck/data/priority-portfolio.json", func(t *testing.T, full string) {
			if err := os.Symlink(secret, full); err != nil {
				t.Fatal(err)
			}
		}},
		"attestation input is a FIFO": {"cli/internal/projectcheck/data/projects.json", func(t *testing.T, full string) {
			if err := syscall.Mkfifo(full, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"inventory input is a FIFO": {"cli/internal/tikvgcpv2/data/profile.json", func(t *testing.T, full string) {
			if err := syscall.Mkfifo(full, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"parent directory links outside": {"cli/internal/cloudeventsstructuredjson/data", func(t *testing.T, full string) {
			writeFile(t, filepath.Join(filepath.Dir(secret), "profile.json"), []byte(`{"token":"do-not-print-0f1e2d"}`))
			if err := os.Symlink(filepath.Dir(secret), full); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			full := filepath.Join(head.Root, filepath.FromSlash(tc.rel))
			if err := os.RemoveAll(full); err != nil {
				t.Fatal(err)
			}
			tc.make(t, full)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			done := make(chan struct{})
			var r *Report
			var err error
			go func() {
				defer close(done)
				r, err = Verify(ctx, Options{Layout: DefaultLayout(), Base: base, Head: head, Now: gateNow})
			}()
			select {
			case <-done:
			case <-time.After(time.Minute):
				t.Fatal("the gate blocked on a head file")
			}
			if err != nil {
				if strings.Contains(err.Error(), "do-not-print") {
					t.Fatal("the error leaks a file outside the tree")
				}
				return
			}
			requireFail(t, r, "tree")
			for _, f := range failedChecks(r) {
				if strings.Contains(f, "do-not-print") {
					t.Fatalf("the report leaks a file outside the tree: %s", f)
				}
			}
		})
	}
}

func TestTreeReadRefusesSpecialFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "d", "big.json"), make([]byte, 2048))
	writeFile(t, filepath.Join(root, "d", "ok.json"), []byte("{}"))
	if err := syscall.Mkfifo(filepath.Join(root, "d", "fifo.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := Tree{Root: root}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := tr.Read("d/fifo.json", 1<<10); err == nil {
			t.Error("a FIFO was read")
		}
		if _, err := tr.Dir("d", 1<<20, 10); err == nil {
			t.Error("a directory holding a FIFO was read")
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	if _, err := tr.Read("d/big.json", 1<<10); err == nil {
		t.Fatal("an oversize file was read")
	}
	if _, err := tr.Read("d/missing.json", 1<<10); !errors.Is(err, ErrMissing) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := tr.Read("nodir/missing.json", 1<<10); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing parent: %v", err)
	}
	if raw, err := tr.Read("d/ok.json", 1<<10); err != nil || string(raw) != "{}" {
		t.Fatalf("plain file: %v", err)
	}
}
