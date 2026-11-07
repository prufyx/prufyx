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
	// The opt-in omits the PR section and --check uses the same rendering.
	omitArgs := []string{"release-notes", "--from-dir", from, "--to-dir", to, "--into", cl, "--omit-merged-prs"}
	if err := run(omitArgs, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cl); strings.Contains(string(b), "Merged pull requests") || !strings.Contains(string(b), "### Summary") {
		t.Fatalf("omitted output %q", b)
	}
	if err := run(append(omitArgs, "--check"), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to, "--into", cl, "--level", "4"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	// --check passes on the regenerated file, fails on a stale block and
	// never writes.
	args := []string{"release-notes", "--from-dir", from, "--to-dir", to, "--into", cl, "--level", "4", "--check"}
	if err := run(args, &out, &errOut); err != nil {
		t.Errorf("--check on a fresh block: %v", err)
	}
	b, _ := os.ReadFile(cl)
	stale := strings.Replace(string(b), "#### Summary", "#### Sumary", 1)
	if err := os.WriteFile(cl, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(args, &out, &errOut); err == nil {
		t.Error("--check accepted a stale block")
	}
	if b2, _ := os.ReadFile(cl); string(b2) != stale {
		t.Error("--check wrote the file")
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
		{"release-notes", "--from-dir", "x", "--to-dir", "y", "--check"},
	} {
		var out, errOut bytes.Buffer
		if err := run(args, &out, &errOut); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}

func TestReleaseNotesAttestationDetail(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	att := func(comp, line, extractor, derived string, versions ...string) string {
		vs := ""
		for i, v := range versions {
			if i > 0 {
				vs += ","
			}
			vs += `{"version":"` + v + `"}`
		}
		return `{"component":"` + comp + `","line":"` + line + `","releases":{"from":[],"to":[` + vs + `]},"evidence":{"extractor":{"version":"` + extractor + `","codeDigest":"sha256:x"},"derivedAt":"` + derived + `"}}`
	}
	rules := filepath.Join("cli", "internal", "cncfcheck", "data", "rules.json")
	for dir, body := range map[string]string{
		from: `{"entries":[],"lineAttestations":[` + att("pkg:github/istio/istio", "1.31", "1.0.0", "d1", "1.31.0", "1.31.3") + `,` +
			att("pkg:github/dapr/dapr", "1.18", "2.7.0", "d1", "1.18.0") + `,` + att("pkg:github/dapr/dapr", "1.19", "2.7.0", "d1", "1.19.0") + `]}`,
		to: `{"entries":[],"lineAttestations":[` + att("pkg:github/istio/istio", "1.31", "1.0.0", "d1", "1.31.0", "1.31.3", "1.31.4") + `,` + att("pkg:github/istio/istio", "1.32", "1.0.0", "d1", "1.32.0") + `,` +
			att("pkg:github/dapr/dapr", "1.18", "2.8.0", "d2", "1.18.0") + `,` + att("pkg:github/dapr/dapr", "1.19", "2.8.0", "d2", "1.19.0") + `]}`,
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
	for _, want := range []string{
		"### Versions newly covered by attestations (including new lines) (1)",
		"Versions listed in line attestations; not an upgrade verdict.",
		"- `istio/istio`: 2 newly covered versions: 1.31.4, 1.32.0",
		"### Re-derived line attestations (1)",
		"- `dapr/dapr`: lines 1.18, 1.19; extractor 2.7.0 -> 2.8.0",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "`istio/istio`: lines") {
		t.Error("an unchanged-extractor attestation was reported as re-derived")
	}
}
