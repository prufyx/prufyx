// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseNotesDirectories(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	rules := filepath.Join("cli", "internal", "cncfcheck", "data", "rules.json")
	for dir, body := range map[string]string{
		from: `{"entries":[{"project":"a","rule":{"id":"a.1"}}]}`,
		to:   `{"entries":[{"project":"a","rule":{"id":"a.1"}},{"project":"a","rule":{"id":"a.2"}}],"lineAttestations":[{"component":"pkg:github/kubernetes/kubernetes","line":"1.37"}]}`,
	} {
		p := filepath.Join(dir, rules)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"### Rules by project (1 added, 0 removed)", "| CNCF | `a` | 1 | 0 | 2 |", "New since `" + from + "`: 1.37.", "listed only when the trees are git revisions"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q\n%s", want, out.String())
		}
	}
	cl := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(cl, []byte("## [Unreleased]\n\n<!-- release-notes:begin -->\nstale\n<!-- release-notes:end -->\n\n### Added\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to, "--into", cl, "--level", "4"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cl); !strings.Contains(string(b), "#### Summary") || strings.Contains(string(b), "stale") || !strings.HasSuffix(string(b), "### Added\n") {
		t.Errorf("changelog = %q", b)
	}
	outFile := filepath.Join(t.TempDir(), "notes.md")
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to, "--out", outFile}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(outFile); err != nil || !strings.Contains(string(b), "### Summary") {
		t.Errorf("--out file = %q, %v", b, err)
	}
}

func TestReleaseNotesUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"release-notes"},
		{"release-notes", "--to", "HEAD"},
		{"release-notes", "--from", "v1", "--from-dir", "x", "--to-dir", "y"},
		{"release-notes", "--from-dir", "x"},
		{"release-notes", "--from", "v1", "extra"},
		{"release-notes", "--from", "-x"},
		{"release-notes", "--from-dir", "x", "--to-dir", "y", "--level", "5"},
		{"release-notes", "--from-dir", "x", "--to-dir", "y", "--out", "a", "--into", "b"},
	} {
		var out, errOut bytes.Buffer
		if err := run(args, &out, &errOut); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
