// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasedocs"
)

func docsExit(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(append([]string{"release-docs"}, args...), &out, &errOut)
	if err == nil {
		return 0, out.String()
	}
	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("not a command error: %v", err)
	}
	return ce.code, ce.message
}

func TestReleaseDocsRefusesBadUsage(t *testing.T) {
	cases := [][]string{
		{},
		{"verify"},
		{"check"},
		{"check", "--root", ".", "--mode", "warn"},
		{"check", "--root", ".", "--mode", "release", "--tag", "v1.0.0", "--previous", "v0.9.0"},
		{"check", "--root", ".", "--mode", "cut", "--tag", "v1.0.0", "--previous", "v0.9.0", "--deny-file", "/nonexistent"},
		{"check", "--root", ".", "--mode", "unreleased", "--tag", "v1.0.0"},
		{"check", "--root", ".", "--mode", "unreleased", "--mode", "release"},
		{"check", "--root", ".", "--mode", "unreleased", "extra"},
		{"published"},
		{"published", "--root", "."},
		{"published", "--base", "main"},
		{"published", "--root", ".", "--base", ""},
		{"published", "--root", ".", "--base", "main", "extra"},
		{"published", "--root", ".", "--base", "main", "--mode", "unreleased"},
	}
	for _, args := range cases {
		code, msg := docsExit(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s), want 2", args, code, msg)
		}
	}
}

func TestReleaseDocsFailsClosedOnAnEmptyRoot(t *testing.T) {
	code, msg := docsExit(t, "check", "--root", t.TempDir(), "--mode", "unreleased")
	if code == 0 || !strings.Contains(msg, "release-docs:") {
		t.Fatalf("an empty root passed: %d %s", code, msg)
	}
}

func TestReleaseDocsPublishedFailsClosedOnAnEmptyRoot(t *testing.T) {
	code, msg := docsExit(t, "published", "--root", t.TempDir(), "--base", "main")
	if code != releasedocs.CodeTag || !strings.Contains(msg, "release-docs:") {
		t.Fatalf("an empty root: %d %s", code, msg)
	}
}

func TestReleaseDocsPublishedSucceedsOnAnUnchangedRelease(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, b)
		}
	}
	commit := func(entry string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte("## [1.0.0]\n\n"+entry+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "--allow-empty", "-m", "c")
	}
	git("init", "-q", "-b", "main")
	commit("- one")
	git("tag", "v1.0.0")
	git("branch", "base")
	commit("- one")
	args := []string{"published", "--root", root, "--base", "base"}
	if code, msg := docsExit(t, args...); code != 0 || !strings.Contains(msg, "ok (published)") {
		t.Fatalf("unchanged: %d %s", code, msg)
	}
	commit("- rewritten")
	if code, msg := docsExit(t, args...); code != releasedocs.CodeChangelog {
		t.Fatalf("rewritten: %d %s", code, msg)
	}
}
