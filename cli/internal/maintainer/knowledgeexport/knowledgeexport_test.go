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
