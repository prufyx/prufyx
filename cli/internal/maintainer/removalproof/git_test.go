// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "f.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "one")
	head := git("rev-parse", "HEAD")
	git("tag", "v1.0.0")
	git("tag", "-a", "-m", "x", "v1.0.1")
	git("tag", "blob", head+":a/f.go")

	ref := extract.RepoRef{Key: "github.com/example/tool"}
	src := &gitSource{ctx: context.Background(), dir: dir, repo: ref}
	defer src.Close()
	tags, err := src.Tags(ref)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range tags {
		got[x.Name] = x.Commit
	}
	if got["v1.0.0"] != head || got["v1.0.1"] != head || got["blob"] != "" {
		t.Fatalf("tags: %v", got)
	}
	root, err := src.List(ref, head, "")
	if err != nil || len(root) != 1 || root[0].Type != "tree" {
		t.Fatalf("root: %v %v", root, err)
	}
	data, err := src.Read(ref, head, "a/f.go")
	if err != nil || string(data) != "package a\n" {
		t.Fatalf("read: %q %v", data, err)
	}
	if _, err := src.Read(ref, head, "a/none.go"); !errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := src.Read(ref, strings.Repeat("0", 40), "a/f.go"); err == nil || errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("unknown commit: %v", err)
	}
	if _, err := src.Read(extract.RepoRef{Key: "github.com/example/else"}, head, "a/f.go"); err == nil {
		t.Fatal("another repository was read")
	}
}

func TestMainUsage(t *testing.T) {
	var out, errOut strings.Builder
	if code := Main(nil, &out, &errOut); code != 2 || out.Len() != 0 {
		t.Fatalf("code %d", code)
	}
	if code := Main([]string{"--request", "/nonexistent", "--repo", ".", "--pins", "x", "--lines", "x", "--modcache", "x"}, &out, &errOut); code != 2 {
		t.Fatalf("code %d", code)
	}
}
