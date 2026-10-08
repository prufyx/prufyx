// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The reattestation outputs (prepare's statement.json, rules.next.json and
// summary.txt; sign's statement.sig.json) are what a maintainer signs and
// what the knowledge gate verifies. They are written only as new files in a
// new directory, never through a symbolic link, never over an existing file,
// and never half: a failed prepare leaves no output directory.

func (f automatedFixture) prepareInto(out string) []string {
	args := f.prepareArgs()
	for i := range args {
		if args[i] == "--output-dir" {
			args[i+1] = out
		}
	}
	return args
}

func (f automatedFixture) automationSign(output string) []string {
	return f.signArgs(filepath.Join(f.autoOut, "statement.json"), output, "--role", "automation", "--key", f.automation.path, "--passphrase-file", f.passphraseFile)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEvidenceReattestPrepareRefusesSymlinkedOutputFile(t *testing.T) {
	f := newAutomatedFixture(t)
	out := filepath.Join(f.dir, "planted")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(f.dir, "victim.txt")
	writeFile(t, victim, []byte("victim"))
	if err := os.Symlink(victim, filepath.Join(out, "statement.json")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(f.prepareInto(out), &stdout, &stderr); err == nil {
		t.Fatal("prepare wrote into a directory holding a planted symlink")
	}
	if got := mustRead(t, victim); string(got) != "victim" {
		t.Fatalf("prepare wrote through the symlink: victim is now %q", got)
	}
}

func TestEvidenceReattestPrepareRefusesSymlinkedOutputDir(t *testing.T) {
	f := newAutomatedFixture(t)
	elsewhere := filepath.Join(f.dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "link-out")
	if err := os.Symlink(elsewhere, out); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(f.prepareInto(out), &stdout, &stderr); err == nil {
		t.Fatal("prepare wrote through a symlinked output directory")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("prepare wrote %d files through the symlinked output directory", len(entries))
	}
}

func TestEvidenceReattestPrepareRefusesExistingOutputDir(t *testing.T) {
	f := newAutomatedFixture(t)
	// The fixture's own output directory holds the statement it prepared;
	// a second prepare must not replace it.
	before := mustRead(t, filepath.Join(f.autoOut, "statement.json"))
	writeFile(t, filepath.Join(f.autoOut, "summary.txt"), []byte("kept"))
	var stdout, stderr bytes.Buffer
	if err := run(f.prepareInto(f.autoOut), &stdout, &stderr); err == nil {
		t.Fatal("prepare replaced the outputs in an existing directory")
	}
	if got := mustRead(t, filepath.Join(f.autoOut, "statement.json")); !bytes.Equal(got, before) {
		t.Fatal("prepare changed an existing statement.json")
	}
	if got := mustRead(t, filepath.Join(f.autoOut, "summary.txt")); string(got) != "kept" {
		t.Fatal("prepare changed an existing summary.txt")
	}
}

// On the old code an existing output directory was filled file by file, so
// a write that failed after statement.json left a statement without its
// rules.next.json.
func TestEvidenceReattestPrepareLeavesNoPartialOutput(t *testing.T) {
	f := newAutomatedFixture(t)
	out := filepath.Join(f.dir, "partial")
	if err := os.MkdirAll(filepath.Join(out, "rules.next.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(f.prepareInto(out), &stdout, &stderr); err == nil {
		t.Fatal("prepare succeeded although rules.next.json could not be written")
	}
	if _, err := os.Lstat(filepath.Join(out, "statement.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed prepare left statement.json behind: %v", err)
	}

	// A failure while the new directory is being filled removes it.
	fresh := filepath.Join(f.dir, "fresh")
	reattestOutputFault = func(name string) error {
		if name == "summary.txt" {
			return errors.New("injected")
		}
		return nil
	}
	defer func() { reattestOutputFault = nil }()
	if err := run(f.prepareInto(fresh), &stdout, &stderr); err == nil {
		t.Fatal("prepare succeeded although summary.txt could not be written")
	}
	if _, err := os.Lstat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed prepare left its output directory behind: %v", err)
	}
	if entries, _ := os.ReadDir(f.dir); hasPrefixEntry(entries, ".prufyx-reattest-") {
		t.Fatal("a failed prepare left a staging directory behind")
	}
}

func hasPrefixEntry(entries []os.DirEntry, prefix string) bool {
	for _, e := range entries {
		if len(e.Name()) >= len(prefix) && e.Name()[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func TestEvidenceReattestSignRefusesExistingOutput(t *testing.T) {
	f := newAutomatedFixture(t)
	output := filepath.Join(f.dir, "existing.sig.json")
	writeFile(t, output, []byte("an earlier signature"))
	var stdout, stderr bytes.Buffer
	if err := run(f.automationSign(output), &stdout, &stderr); err == nil {
		t.Fatal("sign replaced an existing output file")
	}
	if got := mustRead(t, output); string(got) != "an earlier signature" {
		t.Fatalf("sign overwrote an existing file: %q", got)
	}
}

func TestEvidenceReattestSignRefusesSymlinkedOutput(t *testing.T) {
	f := newAutomatedFixture(t)
	victim := filepath.Join(f.dir, "victim.txt")
	writeFile(t, victim, []byte("victim"))
	output := filepath.Join(f.dir, "link.sig.json")
	if err := os.Symlink(victim, output); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(f.automationSign(output), &stdout, &stderr); err == nil {
		t.Fatal("sign wrote through a symlinked output")
	}
	if got := mustRead(t, victim); string(got) != "victim" {
		t.Fatalf("sign wrote through the symlink: victim is now %q", got)
	}
	// A dangling link is refused as well, and is not followed to create
	// its target.
	dangling := filepath.Join(f.dir, "dangling.sig.json")
	target := filepath.Join(f.dir, "created-through-link")
	if err := os.Symlink(target, dangling); err != nil {
		t.Fatal(err)
	}
	if err := run(f.automationSign(dangling), &stdout, &stderr); err == nil {
		t.Fatal("sign wrote through a dangling symlink")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sign created the dangling link's target: %v", err)
	}
}
