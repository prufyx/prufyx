// SPDX-License-Identifier: AGPL-3.0-only

// Package gitreadtest builds a small local git repository to serve as the
// remote of gitread tests, so they run offline.
package gitreadtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Repo is a bare repository at <Root>/<Owner>/<Name>; Base is the file:// URL
// to use as gitread.Remote.Base.
type Repo struct {
	Root, Base, Owner, Name string
	// C1 is tagged v1 (annotated, TagObj); C2 is an untagged ancestor of C3,
	// the tip of main (HEAD); Side is on a branch that is not main and not tagged.
	C1, C2, C3, Side, TagObj string
}

// Git runs git in dir and returns its trimmed output; it fails the test on error.
func Git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "LC_ALL=C",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t testing.TB, dir, name, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// New builds the repository: regular files, an executable, a symlink and a
// submodule entry (gitlink) in C1, so tree listings show every entry kind.
func New(t testing.TB, owner, name string) *Repo {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	Git(t, work, "init", "--quiet", "-b", "main")
	write(t, work, "README.md", "one\n", 0o644)
	write(t, work, "docs/a.txt", "a\n", 0o644)
	write(t, work, "docs/sub/b.txt", "b\n", 0o644)
	write(t, work, "run.sh", "#!/bin/sh\n", 0o755)
	if err := os.Symlink("README.md", filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	Git(t, work, "add", "-A")
	Git(t, work, "update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,vendor/mod")
	Git(t, work, "commit", "--quiet", "-m", "c1")
	r := &Repo{Root: filepath.Join(root, "remote"), Owner: owner, Name: name}
	r.C1 = Git(t, work, "rev-parse", "HEAD")
	Git(t, work, "tag", "-a", "-m", "v1", "v1")
	r.TagObj = Git(t, work, "rev-parse", "v1")
	Git(t, work, "checkout", "--quiet", "-b", "side")
	write(t, work, "side.txt", "side\n", 0o644)
	Git(t, work, "add", "-A")
	Git(t, work, "commit", "--quiet", "-m", "side")
	r.Side = Git(t, work, "rev-parse", "HEAD")
	Git(t, work, "checkout", "--quiet", "main")
	write(t, work, "README.md", "two\n", 0o644)
	Git(t, work, "commit", "--quiet", "-am", "c2")
	r.C2 = Git(t, work, "rev-parse", "HEAD")
	write(t, work, "README.md", "three\n", 0o644)
	Git(t, work, "commit", "--quiet", "-am", "c3")
	r.C3 = Git(t, work, "rev-parse", "HEAD")
	bare := filepath.Join(r.Root, owner, name)
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatal(err)
	}
	Git(t, root, "clone", "--quiet", "--bare", work, bare)
	Git(t, bare, "config", "uploadpack.allowFilter", "true")
	Git(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	r.Base = "file://" + r.Root
	return r
}
