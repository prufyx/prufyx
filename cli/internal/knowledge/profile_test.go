// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConstraintsProfileMarkerIsClosedAndImmutable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lock, err := store.lock(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockStore(lock)

	p := constraintsProfile()
	if err := checkProfileMarker(store, p, true); err != nil {
		t.Fatal(err)
	}
	marker, err := store.read("profile.json", 4096)
	if err != nil {
		t.Fatal(err)
	}
	want, err := markerBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != string(want) {
		t.Fatalf("marker is not canonical fixed profile: %q", marker)
	}
	if err := checkProfileMarker(store, p, true); err != nil {
		t.Fatal(err)
	}
	if err := checkProfileMarker(store, certManagerProfile(), false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("legacy profile accepted generic marker: %v", err)
	}
}

func TestConstraintsProfileReadPathsDistinguishEmptyAndPopulatedUnmarkedRoots(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "populated"}[populated], func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := ensureStoreRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := store.lock(5 * time.Second)
			if err != nil {
				store.Close()
				t.Fatal(err)
			}
			if populated {
				if err := store.write("selection.json", []byte("x\n"), true); err != nil {
					unlockStore(lock)
					store.Close()
					t.Fatal(err)
				}
			}
			err = checkProfileMarker(store, constraintsProfile(), false)
			unlockStore(lock)
			store.Close()
			if populated {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("populated unmarked root result: %v", err)
				}
			} else if !errors.Is(err, ErrNoSelection) {
				t.Fatalf("empty unmarked root result: %v", err)
			}
		})
	}
}

func TestInspectConstraintsEmptyDoesNotInitializeMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	status, err := InspectConstraints(root)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "NO_SELECTION" || status.TrustSource != "none" || status.CurrentEligible {
		t.Fatalf("unexpected empty generic status: %+v", status)
	}
	if _, err := os.Stat(filepath.Join(root, "profile.json")); !os.IsNotExist(err) {
		t.Fatalf("read path initialized generic marker: %v", err)
	}
}

func TestConstraintsProfileTargetNamespaceIsSeparate(t *testing.T) {
	if !packageMemberName("targets/knowledge/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.constraints.v1.json", ConstraintsTargetPath) {
		t.Fatal("generic target member rejected")
	}
	if packageMemberName("targets/knowledge/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cert-manager.v1.json", ConstraintsTargetPath) {
		t.Fatal("legacy target member accepted by generic profile")
	}
	if !packageMemberName("targets/knowledge/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cert-manager.v1.json", TargetPath) {
		t.Fatal("legacy target member rejected by legacy profile")
	}
}
