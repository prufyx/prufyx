// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The diff-check script runs against a throwaway repository with a synthetic
// catalogue; nothing of the real catalogue is read.

func ckGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func ckWrite(t *testing.T, dir, p, c string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ckRepo(t *testing.T, catalogue bool) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	dir := t.TempDir()
	ckGit(t, dir, "init", "-q", "-b", "main")
	if catalogue {
		ckWrite(t, dir, "cli/internal/extract/crdversions/target-zorbulax.json", "{}\n")
		ckWrite(t, dir, "cli/internal/extract/crdversions/target-cluster.json", "{}\n")
		ckWrite(t, dir, "cli/internal/extract/crdversions/target-abc.json", "{}\n")
		ckWrite(t, dir, "cli/internal/customresources/table.json", `{"projects":[{"slug": "frobnitz-ops","component": "pkg:github/acme/quuxplorer"}]}`+"\n")
	}
	ckWrite(t, dir, "code/a.go", "package a\n")
	ckGit(t, dir, "add", "-A")
	ckGit(t, dir, "commit", "-q", "-m", "base")
	ckGit(t, dir, "checkout", "-q", "-b", "capability/x")
	return dir
}

func ckRun(t *testing.T, dir string) (int, string) {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/check-no-project-names")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "main", "HEAD")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func ckCommit(t *testing.T, dir string) {
	t.Helper()
	ckGit(t, dir, "add", "-A")
	ckGit(t, dir, "commit", "-q", "-m", "change")
}

func TestCheckNamesScript(t *testing.T) {
	type tc struct {
		name  string
		files map[string]string
		code  int
		want  string
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	cases := []tc{
		{"clean code change", map[string]string{"code/a.go": "package a\n\n// generic text only\n"}, 0, "ok"},
		{"slug in code", map[string]string{"code/a.go": "package a\n\n// handles Zorbulax specially\n"}, 1, "project name"},
		{"slug in a doc", map[string]string{"docs/x.md": "the zorbulax case\n"}, 1, "project name"},
		{"hyphenated slug", map[string]string{"code/a.go": "package a\n\nvar x = \"frobnitz-ops\"\n"}, 1, "project name"},
		{"repository name from the table component", map[string]string{"code/a.go": "package a\n\nvar x = \"QuuxPlorer\"\n"}, 1, "project name"},
		{"word boundary: part of another word", map[string]string{"code/a.go": "package a\n\n// zorbulaxation\n"}, 0, "ok"},
		{"test file is exempt from the name rule", map[string]string{"code/a_test.go": "package a\n\n// zorbulax\n"}, 0, "ok"},
		{"short name is not checked", map[string]string{"code/a.go": "package a\n\n// abc\n"}, 0, "ok"},
		{"stoplist name is not checked", map[string]string{"code/a.go": "package a\n\n// the cluster\n"}, 0, "ok"},
		{"target file", map[string]string{"cli/internal/extract/crdversions/target-newone.json": "{}\n"}, 1, "data path"},
		{"recipe directory", map[string]string{"cli/knowledge/target-recipes/newone/recipe.json": "{}\n"}, 1, "data path"},
		{"table", map[string]string{"cli/internal/customresources/table.json": "{}\n"}, 1, "data path"},
		{"guard", map[string]string{"cli/internal/customresources/guard.json": "{}\n"}, 1, "data path"},
		{"rules file", map[string]string{"code/testdata/x/rules-new.json": "{}\n"}, 1, "data path"},
		{"reserved record", map[string]string{"cli/knowledge/reserved-groups.json": "{}\n"}, 1, "data path"},
		{"fixture not pinned", map[string]string{"code/testdata/f.yaml": "a: 1\n"}, 1, "not pinned"},
		{"fixture pinned", map[string]string{"code/testdata/f.yaml": "a: 1\n", "cli/testdata-fixtures.sha256": sum("a: 1\n") + "  code/testdata/f.yaml\n"}, 0, "ok"},
		{"fixture pinned with another hash", map[string]string{"code/testdata/f.yaml": "a: 1\n", "cli/testdata-fixtures.sha256": sum("a: 2\n") + "  code/testdata/f.yaml\n"}, 1, "not pinned"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := ckRepo(t, true)
			for p, content := range c.files {
				ckWrite(t, dir, p, content)
			}
			ckCommit(t, dir)
			code, out := ckRun(t, dir)
			if code != c.code || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, want %d (%q): %s", code, c.code, c.want, out)
			}
		})
	}
	t.Run("no catalogue fails closed", func(t *testing.T) {
		dir := ckRepo(t, false)
		ckWrite(t, dir, "code/a.go", "package a\n\n// text\n")
		ckCommit(t, dir)
		if code, out := ckRun(t, dir); code != 2 {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
	t.Run("unknown base fails closed", func(t *testing.T) {
		dir := ckRepo(t, true)
		script, _ := filepath.Abs("../../../../scripts/check-no-project-names")
		cmd := exec.Command("bash", script, "no-such-ref", "HEAD")
		cmd.Dir = dir
		if err := cmd.Run(); err == nil {
			t.Fatal("an unknown base was accepted")
		}
	})
}
