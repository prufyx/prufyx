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
	for name, dir := range map[string]string{
		"empty name":            "",
		"work tree root":        filepath.Join(root, "tree"),
		"inside a work tree":    filepath.Join(tree, "out"),
		"linked work tree":      filepath.Join(linked, "out"),
		"symlink into a tree":   link(tree, "to-tree"),
		"parent symlink":        filepath.Join(link(tree, "to-tree-2"), "out"),
		"git directory":         filepath.Join(bare, "out"),
		"not empty":             full,
		"data directory":        filepath.Join(data, "out"),
		"data directory casing": filepath.Join(cased, "out"),
		"symlink to data":       link(data, "to-data"),
		"dangling symlink":      link(filepath.Join(root, "nowhere"), "dangling"),
		"a file":                file,
		"missing parent":        filepath.Join(root, "a", "b"),
	} {
		if got, err := OutputDir(dir); err == nil {
			t.Errorf("%s accepted: %s", name, got)
		}
		if err := Write(dir, Report{}); err == nil {
			t.Errorf("%s written", name)
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
