// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStaleFindIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\nvar x = 1\nvar y = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, find := range map[string]string{"absent": "var z", "twice": "= 1"} {
		got, _ := runOne(Mutant{ID: name, File: "a.go", Find: find, Replace: "x", Package: ".", Run: "."}, dir, t.TempDir(), time.Minute)
		if got != stale {
			t.Fatalf("%s: got %s, want %s", name, got, stale)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Mutant{ID: "a", File: "x.go", Find: "a", Replace: "b", Package: ".", Run: ".", Expect: "killed"}
	if err := validate([]Mutant{ok}); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Expect = "skipped"
	if validate([]Mutant{bad}) == nil || validate([]Mutant{ok, ok}) == nil {
		t.Fatal("invalid data accepted")
	}
}
