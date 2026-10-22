// SPDX-License-Identifier: AGPL-3.0-only

// Package releasenotes writes the "what was added" part of a release's
// CHANGELOG entry and release notes. It compares the data files of two source
// trees (a directory or a git revision) and prints Markdown. Every number and
// list is computed from those files; nothing is typed by hand and no rule of
// either tree is evaluated.
package releasenotes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Tree reads files of one source tree. Paths are slash-separated and relative
// to the repository root.
type Tree interface {
	// Read returns the file, or an error satisfying errors.Is(err, fs.ErrNotExist)
	// when the tree has no such file.
	Read(name string) ([]byte, error)
	// List returns the files directly under dir, sorted; a missing dir is empty.
	List(dir string) ([]string, error)
}

// DirTree reads a checked-out directory.
type DirTree struct{ Root string }

func (t DirTree) Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(t.Root, filepath.FromSlash(name)))
}

func (t DirTree) List(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(t.Root, filepath.FromSlash(dir)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, path.Join(dir, e.Name()))
		}
	}
	sort.Strings(names)
	return names, nil
}

// GitTree reads a revision of a repository without checking it out.
type GitTree struct {
	Repo string
	Rev  string
}

func (t GitTree) run(args ...string) ([]byte, error) {
	if t.Rev == "" || strings.HasPrefix(t.Rev, "-") {
		return nil, fmt.Errorf("invalid revision %q", t.Rev)
	}
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", t.Repo}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (t GitTree) Read(name string) ([]byte, error) {
	// cat-file --batch-check would be cheaper; a missing path is rare enough.
	if _, err := t.run("cat-file", "-e", t.Rev+"^{commit}"); err != nil {
		return nil, err
	}
	if _, err := t.run("cat-file", "-e", t.Rev+":"+name); err != nil {
		return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
	}
	return t.run("show", t.Rev+":"+name)
}

func (t GitTree) List(dir string) ([]string, error) {
	if _, err := t.run("cat-file", "-e", t.Rev+"^{commit}"); err != nil {
		return nil, err
	}
	if _, err := t.run("cat-file", "-e", t.Rev+":"+dir); err != nil {
		return nil, nil
	}
	out, err := t.run("ls-tree", "--name-only", t.Rev, strings.TrimSuffix(dir, "/")+"/")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	return names, nil
}
