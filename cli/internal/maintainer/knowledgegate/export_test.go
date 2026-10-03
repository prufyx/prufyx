// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// A commit whose own .gitattributes rewrites files on checkout (ident
// expansion, line-ending conversion) is exported with the exact blob
// bytes, while a checkout of the same commit differs: the gate checks
// what merges, not what the change's attributes make of it.
func TestExportIgnoresTheCommitsAttributes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	files := map[string]string{
		".gitattributes":           "*.json ident\n*.md text eol=crlf\n*.txt filter=nosuch\n",
		"cli/knowledge/a.json":     "{\"id\": \"$Id$\"}\n",
		"cli/docs/b.md":            "line one\nline two\n",
		"cli/c.txt":                "plain\n",
		"cli/tool.sh":              "#!/bin/sh\n",
		"cli/internal/data/x.json": "{}\n",
	}
	for rel, content := range files {
		writeFile(t, filepath.Join(repo, filepath.FromSlash(rel)), []byte(content))
	}
	if err := os.Chmod(filepath.Join(repo, "cli", "tool.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../internal/data/x.json", filepath.Join(repo, "cli", "docs", "link.json")); err != nil {
		t.Fatal(err)
	}
	// Commit the bytes as they are (no conversion on the way in).
	gitIn(t, repo, "-c", "core.autocrlf=false", "add", "-A")
	gitIn(t, repo, "commit", "-q", "-m", "c")
	commit := gitIn(t, repo, "rev-parse", "HEAD")

	out := filepath.Join(t.TempDir(), "export")
	if err := Export(context.Background(), ExportOptions{GitDir: filepath.Join(repo, ".git"), Commit: commit, Out: out}); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		raw, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel)))
		if err != nil || string(raw) != content {
			t.Fatalf("%s: exported %q, want the blob %q (%v)", rel, raw, content, err)
		}
	}
	if target, err := os.Readlink(filepath.Join(out, "cli", "docs", "link.json")); err != nil || target != "../internal/data/x.json" {
		t.Fatalf("link exported as %q %v", target, err)
	}
	if info, err := os.Stat(filepath.Join(out, "cli", "tool.sh")); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("mode not kept: %v %v", info, err)
	}
	special, err := (Tree{Root: out}).SpecialFiles("cli")
	if err != nil || len(special) != 1 || special[0] != "cli/docs/link.json" {
		t.Fatalf("special files %v %v", special, err)
	}

	// A checkout honours the attributes, so its bytes differ.
	checkout := t.TempDir()
	gitIn(t, checkout, "init", "-q")
	gitIn(t, checkout, "fetch", "-q", repo, commit)
	cmd := exec.Command("git", "-C", checkout, "-c", "filter.nosuch.smudge=false", "checkout", "-q", commit)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	_ = cmd.Run()
	a, _ := os.ReadFile(filepath.Join(checkout, "cli", "knowledge", "a.json"))
	b, _ := os.ReadFile(filepath.Join(checkout, "cli", "docs", "b.md"))
	if string(a) == files["cli/knowledge/a.json"] && string(b) == files["cli/docs/b.md"] {
		t.Fatal("the checkout did not apply the attributes; the test proves nothing")
	}

	// The export refuses to reuse a directory and a short commit id.
	if err := Export(context.Background(), ExportOptions{GitDir: filepath.Join(repo, ".git"), Commit: commit, Out: out}); err == nil {
		t.Fatal("exported into an existing directory")
	}
	if err := Export(context.Background(), ExportOptions{GitDir: filepath.Join(repo, ".git"), Commit: commit[:12], Out: out + "2"}); err == nil {
		t.Fatal("exported a short commit id")
	}
}

func TestParseLsTreeRefuses(t *testing.T) {
	blob := "100644 blob " + strings.Repeat("a", 40) + "      3\t"
	for name, rec := range map[string]string{
		"dot dot":      blob + "cli/../x",
		"dot git":      blob + "cli/.git/config",
		"dot GIT":      blob + "cli/.GIT/config",
		"absolute":     blob + "/etc/x",
		"backslash":    blob + "cli\\x",
		"submodule":    "160000 commit " + strings.Repeat("b", 40) + "       -\tcli/sub",
		"odd mode":     "100600 blob " + strings.Repeat("a", 40) + "      3\tcli/x",
		"too large":    "100644 blob " + strings.Repeat("a", 40) + " 999999999999\tcli/x",
		"no tab":       "100644 blob " + strings.Repeat("a", 40) + " 3 cli/x",
		"short object": "100644 blob abc 3\tcli/x",
	} {
		if _, err := parseLsTree([]byte(rec + "\x00")); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	entries, err := parseLsTree([]byte(blob + "cli/ok.json\x00"))
	if err != nil || len(entries) != 1 || entries[0].path != "cli/ok.json" || entries[0].size != 3 {
		t.Fatalf("%v %+v", err, entries)
	}
	if !bytes.Equal([]byte(entries[0].object), []byte(strings.Repeat("a", 40))) {
		t.Fatal("object id")
	}
}
