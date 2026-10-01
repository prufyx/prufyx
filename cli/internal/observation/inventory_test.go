// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func inventoryFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	leaf := filepath.Join(root, "observations", "ctx", "000000")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func inventoryOpen(t *testing.T, path string) *Root {
	t.Helper()
	root, err := OpenPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestInventoryBoundsAtLimitAndPlusOne(t *testing.T) {
	rootPath := inventoryFixture(t)
	root := inventoryOpen(t, rootPath)
	base := InventoryLimits{MaxTotalBytes: 2, MaxFiles: 1, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 31}
	leaves, err := root.InventoryObservation(context.Background(), base)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("at-limit inventory: leaves=%d err=%v", len(leaves), err)
	}
	for _, leaf := range leaves {
		_ = leaf.Close()
	}

	if err := os.WriteFile(filepath.Join(rootPath, "observations", "ctx", "000000", "x"), []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, limits := range map[string]InventoryLimits{
		"file-plus-one":    base,
		"name-plus-one":    func() InventoryLimits { v := base; v.MaxFiles = 2; return v }(),
		"content-plus-one": func() InventoryLimits { v := base; v.MaxFiles = 2; v.MaxNameBytes = 32; v.MaxTotalBytes = 2; return v }(),
	} {
		if name == "name-plus-one" {
			limits.MaxNameBytes = 31
		}
		if _, err := root.InventoryObservation(context.Background(), limits); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func TestInventoryProductionFileAndNameBoundaries(t *testing.T) {
	rootPath := inventoryFixture(t)
	leafPath := filepath.Join(rootPath, "observations", "ctx", "000000")
	// index.json consumes one admission; the remaining entries reach the
	// production 16,384-file ceiling exactly.
	for i := 0; i < 16383; i++ {
		if err := os.WriteFile(filepath.Join(leafPath, fmt.Sprintf("f-%05d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := inventoryOpen(t, rootPath)
	limits := InventoryLimits{MaxTotalBytes: 64 << 20, MaxFiles: 16384, MaxDirectories: 4096, MaxDepth: 32, MaxNameBytes: 4 << 20}
	leaves, err := root.InventoryObservation(context.Background(), limits)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("production file at-limit: leaves=%d err=%v", len(leaves), err)
	}
	for _, leaf := range leaves {
		_ = leaf.Close()
	}
	if err := os.WriteFile(filepath.Join(leafPath, "overflow"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.InventoryObservation(context.Background(), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("production file plus-one accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(leafPath, "overflow")); err != nil {
		t.Fatal(err)
	}
	nameLimits := limits
	nameLimits.MaxNameBytes = 4 << 20
	if _, err := root.InventoryObservation(context.Background(), nameLimits); err != nil {
		t.Fatalf("production name budget unexpectedly rejected: %v", err)
	}
}

func TestInventoryProductionNameBoundaryAtFourMiB(t *testing.T) {
	rootPath := inventoryFixture(t)
	observations := filepath.Join(rootPath, "observations")
	leafPath := filepath.Join(observations, "ctx", "000000")
	// 15,999 names of 255 bytes, one 34-byte name, 449 directory names of
	// 255 bytes, and the four fixed names total exactly 4 MiB. This exercises
	// the declared aggregate production name ceiling, independently of the
	// 16,384-file ceiling.
	for i := 0; i < 449; i++ {
		name := fmt.Sprintf("d-%03d-%s", i, strings.Repeat("d", 249))
		if len(name) != 255 {
			t.Fatalf("directory name length=%d", len(name))
		}
		if err := os.Mkdir(filepath.Join(observations, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 15999; i++ {
		name := fmt.Sprintf("f-%05d-%s", i, strings.Repeat("f", 247))
		if len(name) != 255 {
			t.Fatalf("file name length=%d", len(name))
		}
		if err := os.WriteFile(filepath.Join(leafPath, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(leafPath, "short-"+strings.Repeat("s", 27)), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	root := inventoryOpen(t, rootPath)
	limits := InventoryLimits{MaxTotalBytes: 64 << 20, MaxFileBytes: 8 << 20, MaxFiles: 16384, MaxDirectories: 4096, MaxDepth: 32, MaxNameBytes: 4 << 20}
	leaves, err := root.InventoryObservation(context.Background(), limits)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("exact 4MiB name budget rejected: leaves=%d err=%v", len(leaves), err)
	}
	for _, leaf := range leaves {
		_ = leaf.Close()
	}
	limits.MaxNameBytes--
	if _, err := root.InventoryObservation(context.Background(), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("4MiB-minus-one name budget accepted: %v", err)
	}
}

func TestInventoryRejectsStatToOpenReplacementBeforeHash(t *testing.T) {
	rootPath := inventoryFixture(t)
	replacement := filepath.Join(rootPath, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement-is-larger"), 0600); err != nil {
		t.Fatal(err)
	}
	root := inventoryOpen(t, rootPath)
	previous := inventoryAdmissionTransitionHook
	defer func() { inventoryAdmissionTransitionHook = previous }()
	inventoryAdmissionTransitionHook = func(_ *os.File, name string) {
		if name == "index.json" {
			if err := os.Rename(replacement, filepath.Join(rootPath, "observations", "ctx", "000000", name)); err != nil {
				t.Fatalf("replace admitted file: %v", err)
			}
		}
	}
	if _, err := root.InventoryObservation(context.Background(), InventoryLimits{}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("stat-to-open replacement accepted: %v", err)
	}
}

func TestInventoryDescriptorCleanupFailureMatrix(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, rootPath string)
		run   func(t *testing.T, root *Root, rootPath string)
	}{
		{name: "cancelled", run: func(t *testing.T, root *Root, _ string) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = root.InventoryObservation(ctx, InventoryLimits{})
		}},
		{name: "hardlink", setup: func(t *testing.T, rootPath string) {
			if err := os.Link(filepath.Join(rootPath, "observations", "ctx", "000000", "index.json"), filepath.Join(rootPath, "observations", "ctx", "000000", "linked")); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{})
		}},
		{name: "symlink", setup: func(t *testing.T, rootPath string) {
			if err := os.Symlink("index.json", filepath.Join(rootPath, "observations", "ctx", "000000", "link")); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{})
		}},
		{name: "non-regular", setup: func(t *testing.T, rootPath string) {
			if err := syscall.Mkfifo(filepath.Join(rootPath, "observations", "ctx", "000000", "fifo"), 0600); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{})
		}},
		{name: "oversize-admission", setup: func(t *testing.T, rootPath string) {
			if err := os.WriteFile(filepath.Join(rootPath, "observations", "ctx", "000000", "large"), []byte("123"), 0600); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 2, MaxFileBytes: 2, MaxFiles: 2, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 128})
		}},
		{name: "total-budget", setup: func(t *testing.T, rootPath string) {
			if err := os.WriteFile(filepath.Join(rootPath, "observations", "ctx", "000000", "extra"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 2, MaxFileBytes: 8, MaxFiles: 2, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 128})
		}},
		{name: "name-budget", run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 8, MaxFileBytes: 8, MaxFiles: 2, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 1})
		}},
		{name: "directory-budget", run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 8, MaxFileBytes: 8, MaxFiles: 2, MaxDirectories: 2, MaxDepth: 3, MaxNameBytes: 128})
		}},
		{name: "depth-budget", run: func(t *testing.T, root *Root, _ string) {
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 8, MaxFileBytes: 8, MaxFiles: 2, MaxDirectories: 4, MaxDepth: 1, MaxNameBytes: 128})
		}},
		{name: "stat-open-replacement", setup: func(t *testing.T, rootPath string) {
			if err := os.WriteFile(filepath.Join(rootPath, "replacement"), []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
		}, run: func(t *testing.T, root *Root, rootPath string) {
			previous := inventoryAdmissionTransitionHook
			defer func() { inventoryAdmissionTransitionHook = previous }()
			inventoryAdmissionTransitionHook = func(_ *os.File, name string) {
				if name == "index.json" {
					if err := os.Rename(filepath.Join(rootPath, "replacement"), filepath.Join(rootPath, "observations", "ctx", "000000", name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, _ = root.InventoryObservation(context.Background(), InventoryLimits{})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rootPath := inventoryFixture(t)
			if tc.setup != nil {
				tc.setup(t, rootPath)
			}
			root := inventoryOpen(t, rootPath)
			before := descriptorCount(t)
			tc.run(t, root, rootPath)
			if after := descriptorCount(t); after != before {
				t.Fatalf("descriptor leak on %s failure: before=%d after=%d", tc.name, before, after)
			}
		})
	}
}

func descriptorCount(t *testing.T) int {
	t.Helper()
	count, err := countOpenDescriptors()
	if err != nil {
		t.Fatalf("descriptor count unavailable on supported host: %v", err)
	}
	return count
}

func TestInventoryDescriptorCleanupOnSuccessAndFailure(t *testing.T) {
	rootPath := inventoryFixture(t)
	root := inventoryOpen(t, rootPath)
	before := descriptorCount(t)
	leaves, err := root.InventoryObservation(context.Background(), InventoryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	readBefore := descriptorCount(t)
	if len(leaves) != 1 {
		t.Fatalf("unexpected retained leaves: %d", len(leaves))
	}
	if _, err := leaves[0].ReadFile(context.Background(), "index.json", 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bounded read failure=%v", err)
	}
	if got := descriptorCount(t); got != readBefore {
		t.Fatalf("descriptor leak after ReadFile failure: before=%d after=%d", readBefore, got)
	}
	for _, leaf := range leaves {
		_ = leaf.Close()
	}
	if got := descriptorCount(t); got != before {
		t.Fatalf("descriptor leak after success: before=%d after=%d", before, got)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "observations", "ctx", "000000", "too-large"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.InventoryObservation(context.Background(), InventoryLimits{MaxTotalBytes: 2, MaxFiles: 2, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 128}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized failure=%v", err)
	}
	if got := descriptorCount(t); got != before {
		t.Fatalf("descriptor leak after failure: before=%d after=%d", before, got)
	}
}

func TestInventoryCancellationAndHardlinkFailClosed(t *testing.T) {
	rootPath := inventoryFixture(t)
	root := inventoryOpen(t, rootPath)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := root.InventoryObservation(canceled, InventoryLimits{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancellation: %v", err)
	}
	if err := os.Link(filepath.Join(rootPath, "observations", "ctx", "000000", "index.json"), filepath.Join(rootPath, "observations", "ctx", "000000", "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.InventoryObservation(context.Background(), InventoryLimits{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hardlink accepted: %v", err)
	}
}

func TestInventorySymlinkFailClosed(t *testing.T) {
	rootPath := inventoryFixture(t)
	if err := os.Symlink("index.json", filepath.Join(rootPath, "observations", "ctx", "000000", "link")); err != nil {
		t.Fatal(err)
	}
	root := inventoryOpen(t, rootPath)
	if _, err := root.InventoryObservation(context.Background(), InventoryLimits{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink accepted: %v", err)
	}
}

func TestRootReadFileIsLeafConfinedAndInventoryBound(t *testing.T) {
	rootPath := inventoryFixture(t)
	root := inventoryOpen(t, rootPath)
	leaves, err := root.InventoryObservation(context.Background(), InventoryLimits{})
	if err != nil || len(leaves) != 1 {
		t.Fatalf("inventory: leaves=%d err=%v", len(leaves), err)
	}
	leaf := leaves[0]
	t.Cleanup(func() { _ = leaf.Close() })
	for _, name := range []string{"", ".", "..", "../index.json", "/etc/passwd", `..\\index.json`, "index.json/child", "missing.json"} {
		if _, err := leaf.ReadFile(context.Background(), name, 1024); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q accepted: %v", name, err)
		}
	}
	if got, err := leaf.ReadFile(context.Background(), "index.json", 1024); err != nil || string(got) != "{}" {
		t.Fatalf("bound read: %q %v", got, err)
	}
	index := filepath.Join(rootPath, "observations", "ctx", "000000", "index.json")
	if err := os.Rename(index, index+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.ReadFile(context.Background(), "index.json", 1024); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replacement accepted: %v", err)
	}
}

func TestRootReadFileRejectsSameInodeContentChange(t *testing.T) {
	rootPath := inventoryFixture(t)
	root := inventoryOpen(t, rootPath)
	leaves, err := root.InventoryObservation(context.Background(), InventoryLimits{})
	if err != nil || len(leaves) != 1 {
		t.Fatalf("inventory: leaves=%d err=%v", len(leaves), err)
	}
	leaf := leaves[0]
	t.Cleanup(func() { _ = leaf.Close() })
	index := filepath.Join(rootPath, "observations", "ctx", "000000", "index.json")
	if err := os.WriteFile(index, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.ReadFile(context.Background(), "index.json", 1024); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("same-inode rewrite accepted: %v", err)
	}
}

func TestInventoryRejectsNonRegularEntries(t *testing.T) {
	tests := []struct {
		name string
		make func(string) (func(), error)
	}{
		{name: "fifo", make: func(path string) (func(), error) {
			return func() {}, syscall.Mkfifo(path, 0o600)
		}},
		{name: "socket", make: func(path string) (func(), error) {
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				return func() {}, err
			}
			return func() { _ = listener.Close() }, nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rootPath := inventoryFixture(t)
			cleanup, err := tc.make(filepath.Join(rootPath, "observations", "ctx", "000000", tc.name))
			if err != nil {
				t.Skipf("%s unavailable: %v", tc.name, err)
			}
			defer cleanup()
			root := inventoryOpen(t, rootPath)
			if _, err := root.InventoryObservation(context.Background(), InventoryLimits{}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s accepted: %v", tc.name, err)
			}
		})
	}
}

func TestInventoryCancellationAfterTraversalStarts(t *testing.T) {
	rootPath := inventoryFixture(t)
	for i := 0; i < 256; i++ {
		if err := os.WriteFile(filepath.Join(rootPath, "observations", "ctx", "000000", fmt.Sprintf("f-%03d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := inventoryOpen(t, rootPath)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { time.Sleep(time.Millisecond); cancel() }()
	if _, err := root.InventoryObservation(ctx, InventoryLimits{}); err != nil && !errors.Is(err, ErrCancelled) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("unexpected cancellation result: %v", err)
	}
}

type cancelAfterChecks struct {
	checks int32
	limit  int32
}

func (c *cancelAfterChecks) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterChecks) Done() <-chan struct{}       { return nil }
func (c *cancelAfterChecks) Value(any) any               { return nil }
func (c *cancelAfterChecks) Err() error {
	if atomic.AddInt32(&c.checks, 1) > c.limit {
		return context.Canceled
	}
	return nil
}

func TestInventoryCancellationMidStream(t *testing.T) {
	rootPath := inventoryFixture(t)
	index := filepath.Join(rootPath, "observations", "ctx", "000000", "index.json")
	f, err := os.OpenFile(index, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4 << 20); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	root := inventoryOpen(t, rootPath)
	ctx := &cancelAfterChecks{limit: 8}
	if _, err := root.InventoryObservation(ctx, InventoryLimits{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("mid-stream cancellation not enforced: %v", err)
	}
}

func BenchmarkInventoryWideDirectory(b *testing.B) {
	rootPath := b.TempDir()
	leafPath := filepath.Join(rootPath, "observations", "ctx", "000000")
	if err := os.MkdirAll(leafPath, 0o700); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 1024; i++ {
		if err := os.WriteFile(filepath.Join(leafPath, fmt.Sprintf("f-%04d", i)), []byte("x"), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(leafPath, "index.json"), []byte("{}"), 0o600); err != nil {
		b.Fatal(err)
	}
	root, err := OpenPath(rootPath)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		leaves, err := root.InventoryObservation(context.Background(), InventoryLimits{MaxFiles: 2048, MaxDirectories: 4, MaxDepth: 3, MaxTotalBytes: 2048, MaxNameBytes: 1 << 20})
		if err != nil {
			b.Fatal(err)
		}
		for _, leaf := range leaves {
			_ = leaf.Close()
		}
	}
}

func TestInventoryWideDirectoryHasBoundedWork(t *testing.T) {
	rootPath := t.TempDir()
	leafPath := filepath.Join(rootPath, "observations", "ctx", "000000")
	if err := os.MkdirAll(leafPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1024; i++ {
		if err := os.WriteFile(filepath.Join(leafPath, fmt.Sprintf("f-%04d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(leafPath, "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := inventoryOpen(t, rootPath)
	limits := InventoryLimits{MaxTotalBytes: 2048, MaxFiles: 2048, MaxDirectories: 4, MaxDepth: 3, MaxNameBytes: 1 << 20}
	start := time.Now()
	allocs := testing.AllocsPerRun(1, func() {
		leaves, err := root.InventoryObservation(context.Background(), limits)
		if err != nil {
			t.Fatalf("wide inventory: %v", err)
		}
		for _, leaf := range leaves {
			_ = leaf.Close()
		}
	})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("wide inventory exceeded duration ceiling: %s", elapsed)
	}
	// This is deliberately a generous regression ceiling above the current
	// Darwin measurement (~12.4k allocations) while still rejecting accidental
	// directory-wide materialization or per-byte growth.
	if allocs > 20000 {
		t.Fatalf("wide inventory allocations=%0.0f want <= 20000", allocs)
	}
}
