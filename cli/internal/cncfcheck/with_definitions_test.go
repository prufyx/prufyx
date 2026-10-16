// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"errors"
	"testing"
)

// The WithDefinitions wrappers refuse an empty definition list the way the
// WithTable wrappers refuse a nil table: neither falls back to the compiled
// registry, which would admit a pack against a registry the caller never
// named.
func TestWithDefinitionsRefusesAnEmptyList(t *testing.T) {
	landscape, err := packagedFiles.ReadFile("data/landscape-projects.json")
	if err != nil {
		t.Fatal(err)
	}
	priority, err := packagedFiles.ReadFile("data/priority-portfolio.json")
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPackFilesWith(landscape, priority, packRaw, compiledDefinitions()); err != nil {
		t.Fatalf("the compiled registry is refused: %v", err)
	}
	if _, err := BuildAttestationFromFilesWith(landscape, priority, packRaw, compiledDefinitions()); err != nil {
		t.Fatalf("the compiled registry is refused: %v", err)
	}
	if _, err := CheckPackFilesWith(landscape, priority, packRaw, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("CheckPackFilesWith(nil): %v", err)
	}
	if _, err := BuildAttestationFromFilesWith(landscape, priority, packRaw, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("BuildAttestationFromFilesWith(nil): %v", err)
	}
	empty := compiledDefinitions()[:0]
	if _, err := CheckPackFilesWith(landscape, priority, packRaw, empty); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("CheckPackFilesWith(empty): %v", err)
	}
	if _, err := BuildAttestationFromFilesWith(landscape, priority, packRaw, empty); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("BuildAttestationFromFilesWith(empty): %v", err)
	}
}
