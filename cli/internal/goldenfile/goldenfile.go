// SPDX-License-Identifier: AGPL-3.0-only

// Package goldenfile is the golden-file check of the tests that follow the
// bytes of the shipped rule pack. In update mode it rewrites the file and says
// whether it changed anything; it does not then compare the file with what it
// has just written, which would make every golden assertion pass whatever the
// output is. Used by tests only: no production code imports it.
package goldenfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Outcome says what Update did to a golden file.
type Outcome int

const (
	// Unchanged: the file already held the output.
	Unchanged Outcome = iota
	// Changed: the file held different bytes and now holds the output.
	Changed
	// Created: the file did not exist.
	Created
)

func (o Outcome) String() string {
	switch o {
	case Changed:
		return "changed"
	case Created:
		return "created"
	}
	return "unchanged"
}

// Update writes got to path (creating its directory) and reports what it
// replaced. It reads the old bytes first.
func Update(path string, got []byte) (Outcome, error) {
	old, err := os.ReadFile(path)
	outcome := Changed
	switch {
	case os.IsNotExist(err):
		outcome = Created
	case err != nil:
		return 0, err
	case bytes.Equal(old, got):
		return Unchanged, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, got, 0o644); err != nil {
		return 0, err
	}
	return outcome, nil
}

// Compare returns an error unless path holds exactly got.
func Compare(path string, got []byte) error {
	want, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s differs from the golden file", filepath.Base(path))
	}
	return nil
}

// Check compares got with the golden file at path, or, when update is set,
// rewrites it and logs what changed (and does not compare). A failed rewrite
// or comparison fails the test; hint is added to a comparison failure.
func Check(t testing.TB, path string, got []byte, update bool, hint string) {
	t.Helper()
	if update {
		outcome, err := Update(path, got)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("golden %s: %s", path, outcome)
		return
	}
	if err := Compare(path, got); err != nil {
		t.Fatalf("%v%s:\n%s", err, hint, got)
	}
}
