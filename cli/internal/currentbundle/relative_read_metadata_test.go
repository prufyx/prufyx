// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package currentbundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArtifactChangeTimesMatchRejectsBenignMetadataMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"input":"same bytes"}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime().Add(2*time.Second), before.ModTime().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if artifactChangeTimesMatch(before, after) {
		t.Fatal("metadata-only mutation was accepted")
	}
}
