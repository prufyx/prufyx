// SPDX-License-Identifier: AGPL-3.0-only

package knowledgeexport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func TestWriteExportsNewCompleteCNCFTarget(t *testing.T) {
	output := filepath.Join(t.TempDir(), "constraints.v1.json")
	if err := Write(Options{Profile: "cncf", Revision: "73", Output: output}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Revision != "73" || admission.Purpose != "operator_provided" || !admission.HasRule {
		t.Fatalf("admission=%+v", admission)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
}

func TestWriteRejectsExistingOrInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(Options{Profile: "cncf", Revision: "1", Output: existing}); !errors.Is(err, ErrRejected) {
		t.Fatalf("existing error=%v", err)
	}
	if raw, err := os.ReadFile(existing); err != nil || string(raw) != "sentinel" {
		t.Fatalf("existing changed raw=%q err=%v", raw, err)
	}
	for _, options := range []Options{
		{Profile: "other", Revision: "1", Output: filepath.Join(dir, "other.json")},
		{Profile: "cncf", Revision: "0", Output: filepath.Join(dir, "zero.json")},
		{Profile: "cncf", Revision: "1", Output: ""},
	} {
		if err := Write(options); !errors.Is(err, ErrRejected) {
			t.Fatalf("options=%+v err=%v", options, err)
		}
	}
}

func TestWriteProjectsExportsIndexAndProjectTargets(t *testing.T) {
	output := filepath.Join(t.TempDir(), "targets")
	if err := Write(Options{Profile: ProfileCNCFProjects, Revision: "73", Output: output}); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(output, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cncfcheck.ParseExternalIndex(index)
	if err != nil || len(parsed.Entries()) < 2 {
		t.Fatalf("index err=%v entries=%d", err, len(parsed.Entries()))
	}
	for _, entry := range parsed.Entries() {
		raw, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(entry.TargetPath)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cncfcheck.AdmitExternalProjectTarget(parsed, entry.Project, raw); err != nil {
			t.Fatalf("%s: %v", entry.TargetPath, err)
		}
	}
	// A second export onto the same directory is refused and changes nothing.
	if err := Write(Options{Profile: ProfileCNCFProjects, Revision: "73", Output: output}); !errors.Is(err, ErrRejected) {
		t.Fatalf("existing directory: %v", err)
	}
	// The next revision built from this index keeps unchanged projects at 73.
	previous := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(previous, index, 0o644); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(t.TempDir(), "next")
	if err := Write(Options{Profile: ProfileCNCFProjects, Revision: "74", Output: next, PreviousIndex: previous}); err != nil {
		t.Fatal(err)
	}
	nextIndex, err := os.ReadFile(filepath.Join(next, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	nextParsed, err := cncfcheck.ParseExternalIndex(nextIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range nextParsed.Entries() {
		if entry.Revision != "73" {
			t.Fatalf("unchanged project %s moved to revision %s", entry.Project, entry.Revision)
		}
	}
	// A revision that does not advance the previous index is refused.
	if err := Write(Options{Profile: ProfileCNCFProjects, Revision: "73", Output: filepath.Join(t.TempDir(), "same"), PreviousIndex: previous}); !errors.Is(err, ErrRejected) {
		t.Fatalf("non-advancing revision: %v", err)
	}
	// The single-target profile takes no previous index.
	if err := Write(Options{Profile: "cncf", Revision: "73", Output: filepath.Join(t.TempDir(), "c.json"), PreviousIndex: previous}); !errors.Is(err, ErrRejected) {
		t.Fatalf("cncf profile accepted --previous-index: %v", err)
	}
}
