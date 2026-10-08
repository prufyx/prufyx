// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package localcollector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SEC-G G-m1: the output root is opened with O_NOFOLLOW and chmodded through
// that descriptor, so a symlink swapped in after the earlier checks is
// refused and its target is not chmodded. The hook swaps at the moment that
// matters; a path-based Lstat-then-Chmod chmods the victim and fails this.
func TestOutputRootSwappedForSymlinkIsNotFollowed(t *testing.T) {
	tmp := t.TempDir()
	victim := filepath.Join(tmp, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "root")
	swapped := false
	beforeOpenPrivateDir = func(p string) {
		if p != root {
			return
		}
		swapped = true
		if err := os.Remove(root); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(victim, root); err != nil {
			t.Error(err)
		}
	}
	defer func() { beforeOpenPrivateDir = func(string) {} }()
	o := outputRootOptions(t, root)
	o.Kubectl = os.Args[0]
	if err := validateOptions(&o); err == nil {
		t.Fatal("output root swapped for a symlink was accepted")
	}
	if !swapped {
		t.Fatal("the swap hook never ran; the check is not on the guarded path")
	}
	if info, _ := os.Stat(victim); info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target was chmodded to %v", info.Mode().Perm())
	}
}

// SEC-G G-m1: MkdirTemp resolves the output root by path again, so the run
// directory could land in a directory that was swapped in meanwhile. The
// collector must notice and fail, leaving nothing behind in the new directory.
func TestRunDirectoryRefusedWhenOutputRootChanged(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	o := outputRootOptions(t, root)
	o.Kubectl = os.Args[0]
	o.Now = func() time.Time { return time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC) }
	o.Random = strings.NewReader(strings.Repeat("r", 32))
	swapped := false
	beforeOpenPrivateDir = func(p string) {
		if p == root || swapped {
			return
		}
		// p is the freshly created run directory inside root.
		swapped = true
		if err := os.Rename(root, root+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Error(err)
		}
		if err := os.Rename(filepath.Join(root+".old", filepath.Base(p)), p); err != nil {
			t.Error(err)
		}
	}
	defer func() { beforeOpenPrivateDir = func(string) {} }()
	var stdout, stderr bytes.Buffer
	_, code := (Collector{Runner: &fakeRunner{t: t, private: "private"}}).Collect(context.Background(), o, &stdout, &stderr)
	if !swapped {
		t.Fatal("the swap hook never ran")
	}
	if code == 0 {
		t.Fatal("collection succeeded although the output root was replaced")
	}
}

// SEC-G G-m2: a directory owned by another user is refused even at 0700.
func TestOutputRootOwnedByAnotherUserRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand a directory to another user")
	}
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 4242, 4242); err != nil {
		t.Skip(err)
	}
	o := outputRootOptions(t, root)
	if err := validateOptions(&o); err == nil {
		t.Fatal("output root owned by another user accepted")
	}
}
