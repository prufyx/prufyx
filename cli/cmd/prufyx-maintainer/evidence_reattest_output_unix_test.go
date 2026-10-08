// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The output modes are explicit: a group-writable statement or signature
// could be replaced between prepare, sign and verify by anyone in the group.
func TestEvidenceReattestOutputModesIgnoreUmask(t *testing.T) {
	f := newAutomatedFixture(t)
	for i, mask := range []int{0o022, 0o002} {
		out := filepath.Join(f.dir, "modes", string(rune('a'+i)))
		sig := filepath.Join(f.dir, "modes-"+string(rune('a'+i))+".sig.json")
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		old := syscall.Umask(mask)
		var stdout, stderr bytes.Buffer
		prepareErr := run(f.prepareInto(out), &stdout, &stderr)
		signErr := run(f.automationSign(sig), &stdout, &stderr)
		syscall.Umask(old)
		if prepareErr != nil || signErr != nil {
			t.Fatalf("umask %o: prepare %v, sign %v: %s", mask, prepareErr, signErr, stderr.String())
		}
		want := map[string]os.FileMode{
			out: 0o755, filepath.Join(out, "statement.json"): 0o644, filepath.Join(out, "rules.next.json"): 0o644,
			filepath.Join(out, "summary.txt"): 0o644, sig: 0o644,
		}
		for path, mode := range want {
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				t.Errorf("umask %o: %s has mode %v, want %v", mask, filepath.Base(path), info.Mode().Perm(), mode)
			}
		}
	}
}
