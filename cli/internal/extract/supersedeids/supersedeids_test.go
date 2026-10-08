// SPDX-License-Identifier: AGPL-3.0-only

package supersedeids

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped pack is wholly one generation.
func TestShippedPackIsOneGeneration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := Generation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if superseded != Superseded() {
		t.Fatalf("Superseded() = %v, Generation = %v", Superseded(), superseded)
	}
	if len(ReviewedIDs()) != 25 || len(AddedIDs()) != 4 || len(ReplacementIDs()) != 25 {
		t.Fatalf("id sets %d/%d/%d", len(ReviewedIDs()), len(AddedIDs()), len(ReplacementIDs()))
	}
	for _, id := range ReviewedIDs() {
		if want := ReplacementIDs()[id]; superseded && ID(id) != want || !superseded && ID(id) != id {
			t.Fatalf("ID(%s) = %s", id, ID(id))
		}
	}
}

// A pack holding only part of a generation, or both, is refused.
func TestGenerationRefusesMixedPacks(t *testing.T) {
	for _, pack := range []string{
		`{"entries":[]}`,
		`{"entries":[{"rule":{"id":"kubernetes.served-api-removal.x"}}]}`,
		`{"entries":[{"rule":{"id":"kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0"}}]}`,
	} {
		if _, err := Generation([]byte(pack)); err == nil {
			t.Errorf("accepted %s", pack)
		}
	}
}
