// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCapabilityOwnsOnlyDuplicatedDescriptor(t *testing.T) {
	fixture := syntheticRoot(t)
	parent, err := os.Open(filepath.Dir(fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	root, err := OpenAt(parent, filepath.Base(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), root, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Stat(); err != nil {
		t.Fatalf("caller descriptor was closed: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if _, err := Import(context.Background(), root, ImportOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("use after close = %v", err)
	}
}

func TestAdoptSurvivesCallerClose(t *testing.T) {
	caller, err := os.Open(syntheticRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	root, err := Adopt(caller)
	if err != nil {
		t.Fatal(err)
	}
	if err := caller.Close(); err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := Import(context.Background(), root, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestAdoptConcurrentCloseNeverDuplicatesReusedDescriptor(t *testing.T) {
	fixture := syntheticRoot(t)
	replacement := t.TempDir()
	for iteration := 0; iteration < 1000; iteration++ {
		caller, err := os.Open(fixture)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		var root *Root
		var adoptErr error
		go func() {
			defer wg.Done()
			<-start
			root, adoptErr = Adopt(caller)
		}()
		close(start)
		_ = caller.Close()
		reused, openErr := os.Open(replacement)
		if openErr != nil {
			t.Fatal(openErr)
		}
		wg.Wait()
		_ = reused.Close()
		if adoptErr != nil {
			if !errors.Is(adoptErr, ErrInvalid) {
				t.Fatalf("iteration %d: untyped close race: %v", iteration, adoptErr)
			}
			continue
		}
		if _, err := Import(context.Background(), root, ImportOptions{}); err != nil {
			_ = root.Close()
			t.Fatalf("iteration %d: adopted replacement descriptor: %v", iteration, err)
		}
		_ = root.Close()
	}
}

func TestCapabilityBindsOriginalDirectoryAcrossPathSwap(t *testing.T) {
	fixture := syntheticRoot(t)
	root, err := OpenPath(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	saved := fixture + "-saved"
	if err := os.Rename(fixture, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "attacker"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), root, ImportOptions{}); err != nil {
		t.Fatalf("capability followed swapped pathname: %v", err)
	}
}

func TestImportCancellationAndNarrowLimits(t *testing.T) {
	root, err := OpenPath(syntheticRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Import(cancelled, root, ImportOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel = %v", err)
	}
	if _, err := Import(context.Background(), root, ImportOptions{Limits: ImportLimits{MaxFileBytes: 1, MaxManifestBytes: 1}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("narrow limit = %v", err)
	}
	if _, err := Import(context.Background(), root, ImportOptions{Limits: ImportLimits{MaxFileBytes: maxFileBytes + 1}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raised limit = %v", err)
	}
}

func TestOpenAtRejectsNonLeafAndSymlink(t *testing.T) {
	parentPath := t.TempDir()
	target := filepath.Join(parentPath, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(parentPath, "link")); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, leaf := range []string{"../target", "link", ".", ""} {
		if root, err := OpenAt(parent, leaf); err == nil {
			root.Close()
			t.Fatalf("accepted %q", leaf)
		}
	}
}
