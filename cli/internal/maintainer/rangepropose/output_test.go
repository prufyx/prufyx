// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputDirectoryRules(t *testing.T) {
	root := t.TempDir()
	mkdir := func(parts ...string) string {
		dir := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	link := func(target, name string) string {
		path := filepath.Join(root, name)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tree := mkdir("tree", "sub")
	mkdir("tree", ".git")
	linked := mkdir("linked")
	write(t, filepath.Join(linked, ".git"), "gitdir: /elsewhere\n")
	bare := mkdir("bare.git")
	mkdir("bare.git", "objects")
	write(t, filepath.Join(bare, "HEAD"), "ref: refs/heads/main\n")
	full := mkdir("full")
	write(t, filepath.Join(full, "proposals.json"), "{}")
	data := mkdir("copy", "cli", "internal", "cncfcheck", "data")
	cased := mkdir("cased", "Internal", "CncfCheck", "Data")
	file := filepath.Join(root, "file")
	write(t, file, "x")
	const (
		notEmpty  = "the output directory is not empty"
		inTree    = "the output directory is inside a git work tree"
		inData    = "the output directory is inside the rule data directory"
		notNewDir = "the output path is not a new directory"
	)
	// An empty name must not mean the current directory, even an acceptable one.
	t.Chdir(mkdir("cwd"))
	for name, tc := range map[string]struct{ dir, want string }{
		"empty name":            {"", "no output directory"},
		"work tree root":        {filepath.Join(root, "tree"), notEmpty},
		"inside a work tree":    {filepath.Join(tree, "out"), inTree},
		"linked work tree":      {filepath.Join(linked, "out"), inTree},
		"symlink into a tree":   {link(tree, "to-tree"), inTree},
		"parent symlink":        {filepath.Join(link(tree, "to-tree-2"), "out"), inTree},
		"git directory":         {filepath.Join(bare, "out"), "the output directory is inside a git directory"},
		"not empty":             {full, notEmpty},
		"data directory":        {filepath.Join(data, "out"), inData},
		"data directory casing": {filepath.Join(cased, "out"), inData},
		"symlink to data":       {link(data, "to-data"), inData},
		"dangling symlink":      {link(filepath.Join(root, "nowhere"), "dangling"), notNewDir},
		"a file":                {file, "the output path is not a directory"},
		"missing parent":        {filepath.Join(root, "a", "b"), "the parent of the output directory does not exist"},
	} {
		if got, err := OutputDir(tc.dir); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %q %v", name, got, err)
		}
		if err := Write(tc.dir, Report{}); err == nil || err.Error() != tc.want {
			t.Errorf("%s write: %v", name, err)
		}
	}
	for _, dir := range []string{filepath.Join(root, "new"), mkdir("empty")} {
		if err := Write(dir, Report{}); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range []string{ProposalsFile, ReviewFile, SummaryFile} {
			if info, err := os.Lstat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if err := Write(dir, Report{}); err == nil {
			t.Fatal("a second write over the outputs was accepted")
		}
	}
}
