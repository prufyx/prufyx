// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const countsFixtures = "../../internal/maintainer/releasenotes/testdata/"

// writeCounts commits the two fixture counts files into the trees.
func writeCounts(t *testing.T, from, to string) {
	t.Helper()
	for dir, name := range map[string]string{from: "counts-prev.json", to: "counts-cur.json"} {
		b, err := os.ReadFile(countsFixtures + name)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "cli", "docs", "generated", "coverage-counts.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReleaseNotesRefuseWithoutCounts(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	var out, errOut bytes.Buffer
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to}, &out, &errOut); err == nil {
		t.Fatal("rendered without counts files")
	}
	writeCounts(t, from, to)
	if err := os.Remove(filepath.Join(from, "cli", "docs", "generated", "coverage-counts.json")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release-notes", "--from-dir", from, "--to-dir", to}, &out, &errOut); err == nil {
		t.Fatal("rendered without the previous counts")
	}
	if strings.Contains(out.String(), "n/a") {
		t.Error("printed n/a")
	}
}

func TestReleaseNotesFromRevPin(t *testing.T) {
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, b)
		}
	}
	repo := t.TempDir()
	scratch := t.TempDir()
	writeCounts(t, repo, scratch)
	prev, err := os.ReadFile(countsFixtures + "counts-prev.json")
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(countsFixtures + "counts-cur.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, "cli", "docs", "generated", "coverage-counts.json")
	git(repo, "init", "-q")
	git(repo, "add", "-A")
	git(repo, "commit", "-q", "-m", "one")
	git(repo, "tag", "v1")
	if err := os.WriteFile(path, cur, 0o644); err != nil {
		t.Fatal(err)
	}
	git(repo, "commit", "-q", "-am", "two")
	git(repo, "checkout", "-q", "-b", "side", "v1")
	git(repo, "commit", "-q", "--allow-empty", "-m", "side")
	git(repo, "tag", "v1side")
	git(repo, "checkout", "-q", "-")
	sum := releasenotesSha(prev)
	run1 := func(args ...string) error {
		var out, errOut bytes.Buffer
		return run(append([]string{"release-notes", "--repo", repo, "--omit-merged-prs"}, args...), &out, &errOut)
	}
	for name, args := range map[string][]string{
		"no pin":          {"--from", "v1"},
		"wrong pin":       {"--from", "v1", "--previous-counts-sha256", strings.Repeat("0", 64)},
		"missing tag":     {"--from", "v9", "--previous-counts-sha256", sum},
		"not an ancestor": {"--from", "v1side", "--previous-counts-sha256", sum},
	} {
		if err := run1(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"release-notes", "--repo", repo, "--omit-merged-prs", "--from", "v1", "--previous-counts-sha256", sum}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"previous = tag `v1`, commit ", "counts sha256 `" + sum + "`", "### Coverage since the previous release"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q\n%s", want, out.String())
		}
	}
}

func releasenotesSha(b []byte) string { return releasenotes.Sum256Hex(b) }

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
	writeCounts(t, from, to)
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
	writeCounts(t, from, to)
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
