// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

func TestReadMovedBlobsIsAbsoluteContentAddressedAndOptional(t *testing.T) {
	if blobs, err := readMovedBlobs(""); err != nil || blobs != nil {
		t.Fatalf("no directory means no files: %v %v", blobs, err)
	}
	if _, err := readMovedBlobs("relative/dir"); err == nil {
		t.Fatal("a relative directory must be refused")
	}
	if _, err := readMovedBlobs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing directory must be refused, not read as empty")
	}
	dir := t.TempDir()
	data := []byte("a retained file")
	if err := os.WriteFile(filepath.Join(dir, "whatever"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	blobs, err := readMovedBlobs(dir)
	if err != nil || string(blobs[sourcecorpus.SHA(data)]) != string(data) {
		t.Fatalf("files are keyed by the digest of their bytes: %v %v", blobs, err)
	}
}
