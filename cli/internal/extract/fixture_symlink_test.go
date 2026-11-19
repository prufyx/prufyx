// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureCommitDir(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string]string{}, map[string]map[string]string{testCommit: {"a.txt": "alpha\n", "dir/b.go": "package b\n"}})
	return root, filepath.Join(root, filepath.FromSlash(testRepo), "commits", testCommit)
}

func TestFixtureReaderSymlinks(t *testing.T) {
	cases := []struct {
		name    string
		link    string // path of the link inside the commit dir
		target  string
		wantErr bool
	}{
		{"to file", "ln", "a.txt", false},
		{"to dir", "ln", "dir", false},
		{"dangling", "ln", "missing/nowhere", false},
		{"relative up inside root", "dir/ln", "../a.txt", false},
		{"absolute target", "ln", "/etc/passwd", true},
		{"escapes root", "ln", "../../outside", true},
		{"escapes via subdir", "dir/ln", "../../x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, commitDir := fixtureCommitDir(t)
			if err := os.Symlink(tc.target, filepath.Join(commitDir, filepath.FromSlash(tc.link))); err != nil {
				t.Fatal(err)
			}
			fr := FixtureReader{Root: root}
			repo := repoRef(t)
			entries, err := fr.List(repo, testCommit, "")
			if tc.link != "ln" {
				// the link sits in dir/; the root listing is unaffected
				// unless a subtree fails, which also fails the root.
				if tc.wantErr {
					if !errors.Is(err, ErrFixtureSymlink) {
						t.Fatalf("root list: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				sub, err := fr.List(repo, testCommit, "dir")
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, e := range sub {
					if e.Path == "dir/ln" && e.Mode == "120000" && e.Type == "blob" && e.SHA == gitObjectID("blob", []byte(tc.target)) {
						found = true
					}
				}
				if !found {
					t.Fatalf("link not listed as 120000 blob: %+v", sub)
				}
				return
			}
			if tc.wantErr {
				if !errors.Is(err, ErrFixtureSymlink) {
					t.Fatalf("want ErrFixtureSymlink, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range entries {
				if e.Path == "ln" {
					found = true
					if e.Mode != "120000" || e.Type != "blob" || e.SHA != gitObjectID("blob", []byte(tc.target)) {
						t.Fatalf("link entry %+v", e)
					}
				}
			}
			if !found {
				t.Fatalf("link missing from listing %+v", entries)
			}
			// Never followed: Read refuses the link itself, and nothing
			// beneath a link is reachable.
			if _, err := fr.Read(repo, testCommit, "ln"); err == nil {
				t.Fatal("Read followed or served a symlink")
			}
			if _, err := fr.Read(repo, testCommit, "ln/b.go"); err == nil {
				t.Fatal("Read went through a symlinked parent")
			}
			if _, err := fr.List(repo, testCommit, "ln"); err == nil {
				t.Fatal("List followed a symlink")
			}
		})
	}
}

// The fixture listing of a tree with symlinks equals what git computes for
// the same tree, which is what the mirror reader serves from ls-tree.
func TestFixtureReaderSymlinkParityWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root, commitDir := fixtureCommitDir(t)
	for name, target := range map[string]string{"l-file": "a.txt", "l-dir": "dir", "l-dangling": "gone", "dir/l-up": "../a.txt"} {
		if err := os.Symlink(target, filepath.Join(commitDir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	gitRun := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = commitDir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	gitRun("init", "-q")
	gitRun("config", "core.symlinks", "true")
	gitRun("add", "-A")
	tree := gitRun("write-tree")
	fr := FixtureReader{Root: root}
	repo := repoRef(t)
	check := func(dir, spec string) {
		want := gitRun("ls-tree", spec)
		entries, err := fr.List(repo, testCommit, dir)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Mode+" "+e.Type+" "+e.SHA+"\t"+strings.TrimPrefix(e.Path, dir+"/"))
		}
		// ls-tree on a tree id lists names relative to that tree.
		if strings.Join(got, "\n") != want {
			t.Fatalf("%q differs from git:\n%s\nwant\n%s", dir, strings.Join(got, "\n"), want)
		}
	}
	check("", tree)
	check("dir", gitRun("rev-parse", tree+":dir"))
}
