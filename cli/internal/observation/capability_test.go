// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func importTestPath(t testing.TB, path string) (CurrentBundle, error) {
	t.Helper()
	root, err := OpenPath(path)
	if err != nil {
		return CurrentBundle{}, err
	}
	defer root.Close()
	return Import(context.Background(), root, ImportOptions{})
}

func importPathWithReadHooks(t testing.TB, path string, hooks *importReadHooks) (CurrentBundle, error) {
	t.Helper()
	root, err := OpenPath(path)
	if err != nil {
		return CurrentBundle{}, err
	}
	defer root.Close()
	return importWithReadHooks(context.Background(), root, ImportOptions{}, hooks)
}

func TestStableReadRejectsSameSizeRewriteWithRestoredMtime(t *testing.T) {
	rootPath := syntheticRoot(t)
	target := filepath.Join(rootPath, "index.json")
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)/2] ^= 1
	triggered := false
	_, err = importPathWithReadHooks(t, rootPath, &importReadHooks{afterStableStat: func(rel string) error {
		if rel != "index.json" || triggered {
			return nil
		}
		triggered = true
		if err := os.WriteFile(target, mutated, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chtimes(target, time.Unix(1, 0), info.ModTime())
	}})
	if !triggered || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("same-size/restored-mtime mutation = %v triggered=%v", err, triggered)
	}
}

func TestInventoryRejectsDirectorySwapAndRestore(t *testing.T) {
	rootPath := syntheticRoot(t)
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	contextName := ""
	for _, entry := range entries {
		if entry.IsDir() {
			contextName = entry.Name()
			break
		}
	}
	if contextName == "" {
		t.Fatal("fixture has no context directory")
	}
	triggered := false
	_, err = importPathWithReadHooks(t, rootPath, &importReadHooks{afterInventoryDir: func(rel string) error {
		if rel != contextName || triggered {
			return nil
		}
		triggered = true
		// Swap detection compares the directory's ctime. Linux stamps ctime
		// from a coarse clock, so a rename in the same tick as the open can
		// keep the old value; wait past the tick so the swap is observable.
		time.Sleep(50 * time.Millisecond)
		original := filepath.Join(rootPath, contextName)
		saved := original + "-saved"
		if err := os.Rename(original, saved); err != nil {
			return err
		}
		if err := os.Mkdir(original, 0700); err != nil {
			return err
		}
		if err := os.Remove(original); err != nil {
			return err
		}
		return os.Rename(saved, original)
	}})
	if !triggered || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("directory swap/restore = %v triggered=%v", err, triggered)
	}
}

func TestFirstInventoryRejectsCompleteAlternateRootReplacement(t *testing.T) {
	original := syntheticRoot(t)
	alternate := syntheticRoot(t)
	writeJSON(t, filepath.Join(alternate, "demo", "server-version.json"), map[string]any{"gitVersion": "v1.34.0"})
	regenerateManifests(t, alternate)
	names := []string{"index.json", "MANIFEST.sha256", "demo"}
	swapped := false
	hooks := &importReadHooks{afterFirstInventory: func() error {
		for _, name := range names {
			if err := os.Rename(filepath.Join(original, name), filepath.Join(original, name+".saved")); err != nil {
				return err
			}
			if err := os.Rename(filepath.Join(alternate, name), filepath.Join(original, name)); err != nil {
				return err
			}
		}
		swapped = true
		return nil
	}}
	bundle, err := importPathWithReadHooks(t, original, hooks)
	if !swapped || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("alternate root replacement = %v swapped=%v", err, swapped)
	}
	if bundle.KubernetesVersion != "" || len(bundle.Components) != 0 || len(bundle.SourceDigests) != 0 {
		t.Fatalf("alternate projection escaped on failure: %#v", bundle)
	}
	for _, name := range names {
		if moveErr := os.Rename(filepath.Join(original, name), filepath.Join(alternate, name)); moveErr != nil {
			t.Fatal(moveErr)
		}
		if moveErr := os.Rename(filepath.Join(original, name+".saved"), filepath.Join(original, name)); moveErr != nil {
			t.Fatal(moveErr)
		}
	}
	if _, err := importTestPath(t, original); err != nil {
		t.Fatalf("restored original did not import: %v", err)
	}
}
