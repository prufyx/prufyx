// SPDX-License-Identifier: AGPL-3.0-only

package offlineboundary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRejectsSymlinkedWorkDir(t *testing.T) {
	real := t.TempDir()
	if err := os.Chmod(real, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(real, "prufyx")
	if err := os.WriteFile(binary, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "work")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Binary: binary, WorkDir: link, PositiveControl: []string{"/bin/true"}, Scenarios: []Scenario{{Name: "help", Argv: []string{"--help"}}}, UID: 1000, GID: 1000}
	if err := validate(cfg); err == nil {
		t.Fatal("symlinked work directory accepted")
	}
}

// Stale or planted files in WorkDir (including those of a scenario whose name
// extends another's) must never be read as evidence for the current trace.
func TestNewTraceDirIsolatesStaleAndPrefixCollidingFiles(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"strace-help", "strace-help.123", "strace-help-more.9"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("socket(AF_INET)"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := newTraceDir(work, "help")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("trace dir mode: %v %v", info, err)
	}
	files, err := traceFiles(dir)
	if err == nil && len(files) != 0 {
		t.Fatalf("stale files visible: %v", files)
	}
}

func TestTraceFilesRejectsSymlinkEntries(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(secret, []byte("socket("), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "trace.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := traceFiles(dir); err == nil {
		t.Fatal("symlink trace entry accepted")
	}
}
