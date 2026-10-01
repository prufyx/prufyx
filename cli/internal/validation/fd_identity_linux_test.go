// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package validation

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// identity reports the (device, inode) pair that uniquely names an object
// within a filesystem. Two stats of the same underlying object -- whether
// reached by path or by directory-descriptor -- must report the same pair.
func identity(t *testing.T, info os.FileInfo) (dev, ino uint64) {
	t.Helper()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("FileInfo.Sys() = %T, want *syscall.Stat_t", info.Sys())
	}
	return uint64(st.Dev), st.Ino
}

// TestDescriptorRelativeOperationsAgreeWithPathBasedStat documents and
// verifies the filesystem invariant that fd_paths_linux.go relies on for its
// descriptor-relative (Mkdirat/Openat/Unlinkat) publication path: a directory
// or file reached through a retained directory descriptor names the exact
// same inode (dev, ino) as the same path reached by an independent,
// path-based lookup, both before and after descriptor-relative mutations.
//
// This recovers exploratory research (a standalone fstat/fstatat probe
// comparing os.Open+Fstat against raw fstatat(AT_SYMLINK_NOFOLLOW) around
// Mkdirat/Unlinkat on a scratch directory) as a permanent regression test
// exercised through the package's own descriptor-relative helpers rather
// than through hand-rolled raw syscalls.
func TestDescriptorRelativeOperationsAgreeWithPathBasedStat(t *testing.T) {
	root := t.TempDir()

	directory, err := os.Open(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer directory.Close()

	// Baseline: fstat via the retained directory descriptor must agree with
	// an independent path-based stat of the same directory.
	fdInfo, err := directory.Stat()
	if err != nil {
		t.Fatalf("fstat(directory fd): %v", err)
	}
	pathInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat(root path): %v", err)
	}
	fdDev, fdIno := identity(t, fdInfo)
	pathDev, pathIno := identity(t, pathInfo)
	if fdDev != pathDev || fdIno != pathIno {
		t.Fatalf("baseline identity mismatch: fd=(%d,%d) path=(%d,%d)", fdDev, fdIno, pathDev, pathIno)
	}

	// Create "probe" through the descriptor-relative helper (Mkdirat under
	// the hood) exactly as production publication code does.
	if err := mkdirRelative(directory, "probe", 0o700); err != nil {
		t.Fatalf("mkdirRelative: %v", err)
	}

	probePath := filepath.Join(root, "probe")

	// The new directory must be visible, and identical, whether opened via
	// the directory descriptor (Openat) or via an independent path lookup.
	child, err := openRelativeDirectory(directory, "probe")
	if err != nil {
		t.Fatalf("openRelativeDirectory(probe): %v", err)
	}
	defer child.Close()
	childInfo, err := child.Stat()
	if err != nil {
		t.Fatalf("fstat(child fd): %v", err)
	}
	probePathInfo, err := os.Stat(probePath)
	if err != nil {
		t.Fatalf("stat(probe path): %v", err)
	}
	childDev, childIno := identity(t, childInfo)
	probeDev, probeIno := identity(t, probePathInfo)
	if childDev != probeDev || childIno != probeIno {
		t.Fatalf("post-mkdir identity mismatch: fd=(%d,%d) path=(%d,%d)", childDev, childIno, probeDev, probeIno)
	}

	// The containing directory's own identity must be unaffected by the
	// child creation -- Mkdirat must not have reopened or replaced it.
	fdInfoAfter, err := directory.Stat()
	if err != nil {
		t.Fatalf("fstat(directory fd) after mkdir: %v", err)
	}
	fdDevAfter, fdInoAfter := identity(t, fdInfoAfter)
	if fdDevAfter != fdDev || fdInoAfter != fdIno {
		t.Fatalf("parent identity changed after mkdirRelative: before=(%d,%d) after=(%d,%d)", fdDev, fdIno, fdDevAfter, fdInoAfter)
	}

	// removeDirectoryRelative (Unlinkat+AT_REMOVEDIR) must be immediately
	// visible to an independent path-based lookup: no caching divergence
	// between the descriptor-relative and path-based views.
	if err := removeDirectoryRelative(directory, "probe"); err != nil {
		t.Fatalf("removeDirectoryRelative: %v", err)
	}
	if _, err := os.Stat(probePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat(probe path) after removeDirectoryRelative = %v, want ErrNotExist", err)
	}
}
