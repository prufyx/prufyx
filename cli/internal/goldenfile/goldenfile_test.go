// SPDX-License-Identifier: AGPL-3.0-only

package goldenfile

import (
	"os"
	"path/filepath"
	"testing"
)

// Update says what it did, which a rewrite that then compared the file with
// itself could not: the old bytes are read before they are replaced.
func TestUpdateReportsWhatItReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "golden.txt")
	steps := []struct {
		content string
		want    Outcome
	}{{"BLOCKED\n", Created}, {"BLOCKED\n", Unchanged}, {"PASS\n", Changed}, {"PASS\n", Unchanged}}
	for _, step := range steps {
		got, err := Update(path, []byte(step.content))
		if err != nil || got != step.want {
			t.Fatalf("Update(%q) = %v, %v; want %v", step.content, got, err, step.want)
		}
		if raw, _ := os.ReadFile(path); string(raw) != step.content {
			t.Fatalf("file holds %q, want %q", raw, step.content)
		}
	}
}

func TestCompareRefusesADifferentFileAndAMissingOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "golden.txt")
	if err := Compare(path, []byte("x")); err == nil {
		t.Fatal("a missing golden file matched")
	}
	if err := os.WriteFile(path, []byte("BLOCKED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Compare(path, []byte("PASS\n")); err == nil {
		t.Fatal("different bytes matched")
	}
	if err := Compare(path, []byte("BLOCKED\n")); err != nil {
		t.Fatal(err)
	}
}

// In update mode Check does not fail on output that differs from the file; it
// replaces the file. Outside update mode it does not touch the file.
func TestCheckUpdateModeRewritesAndCompareModeDoesNot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "golden.txt")
	if err := os.WriteFile(path, []byte("BLOCKED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	Check(t, path, []byte("PASS\n"), true, "")
	if raw, _ := os.ReadFile(path); string(raw) != "PASS\n" {
		t.Fatalf("update mode left %q", raw)
	}
	Check(t, path, []byte("PASS\n"), false, "")
	if raw, _ := os.ReadFile(path); string(raw) != "PASS\n" {
		t.Fatalf("compare mode changed the file to %q", raw)
	}
}
