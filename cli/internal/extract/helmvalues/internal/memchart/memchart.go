// SPDX-License-Identifier: AGPL-3.0-only

// Package memchart is an in-memory extract.PinnedReader for tests: a set of
// files per commit, listed as a Git tree would list them.
package memchart

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

type file struct {
	content string
	mode    string
}

// Repo holds the files of each commit it was given.
type Repo struct {
	commits map[string]map[string]file
}

// New returns an empty repository.
func New() *Repo { return &Repo{commits: map[string]map[string]file{}} }

// Put adds a regular file at path under commit.
func (r *Repo) Put(commit, path, content string) *Repo {
	return r.PutMode(commit, path, content, "100644")
}

// PutMode adds an entry with the given Git mode (120000 is a symbolic link).
func (r *Repo) PutMode(commit, path, content, mode string) *Repo {
	if r.commits[commit] == nil {
		r.commits[commit] = map[string]file{}
	}
	r.commits[commit][path] = file{content: content, mode: mode}
	return r
}

// Read implements extract.PinnedReader.
func (r *Repo) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	f, ok := r.commits[commit][path]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, path)
	}
	return []byte(f.content), nil
}

// List implements extract.PinnedReader: the entries directly inside dir.
func (r *Repo) List(_ extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	seen := map[string]extract.TreeEntry{}
	for p, f := range r.commits[commit] {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok {
			continue
		}
		name, _, nested := strings.Cut(rest, "/")
		if nested {
			seen[name] = extract.TreeEntry{Mode: "040000", Type: "tree", Path: prefix + name}
			continue
		}
		seen[name] = extract.TreeEntry{Mode: f.mode, Type: "blob", Path: prefix + name}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	out := make([]extract.TreeEntry, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
