// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 by definition
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// FixtureReader serves pinned bytes from a directory, for tests and for
// offline fixture runs. Layout, per repository key:
//
//	<root>/<host>/<owner>/<name>/tags.json            {"v1.2.0": "<40-hex commit>", ...}
//	<root>/<host>/<owner>/<name>/commits/<commit>/... the tree at that commit
//
// Listings carry the git object ids git itself would compute for the same
// tree (regular files as mode 100644 blobs, directories as trees, symlinks
// as mode 120000 blobs whose content is the link target), so
// content-addressed reuse behaves exactly as on a real mirror. A symlink is
// never followed: it is listed with its target text, and Read refuses it as
// the mirror reader does. A link whose target is absolute or leaves the
// commit directory is refused with ErrFixtureSymlink.
type FixtureReader struct {
	Root string
}

// ErrFixtureSymlink reports a fixture symlink that is absolute or whose
// target leaves the commit directory.
var ErrFixtureSymlink = errors.New("fixture symlink escapes the fixture root")

func (f FixtureReader) repoDir(repo RepoRef) string {
	return filepath.Join(f.Root, filepath.FromSlash(repo.Key))
}

func (f FixtureReader) commitPath(repo RepoRef, commit, p string) (string, error) {
	if !IsCommitSHA(commit) {
		return "", fmt.Errorf("commit must be a full 40-character SHA")
	}
	base := filepath.Join(f.repoDir(repo), "commits", commit)
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return "", fmt.Errorf("commit %s is not in the fixture", commit)
	}
	if p == "" {
		return base, nil
	}
	if strings.HasPrefix(p, "/") || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("invalid path %q", p)
	}
	// No parent component may be a symlink: a path is never resolved
	// through one.
	parts := strings.Split(p, "/")
	cur := base
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		if st, err := os.Lstat(cur); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %s", ErrFixtureSymlink, p)
		}
	}
	return filepath.Join(base, filepath.FromSlash(p)), nil
}

// Read implements PinnedReader.
func (f FixtureReader) Read(repo RepoRef, commit, p string) ([]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("invalid path")
	}
	full, err := f.commitPath(repo, commit, p)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	return os.ReadFile(full)
}

// List implements PinnedReader.
func (f FixtureReader) List(repo RepoRef, commit, dir string) ([]TreeEntry, error) {
	full, err := f.commitPath(repo, commit, dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, dir)
	}
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	base, err := f.commitPath(repo, commit, "")
	if err != nil {
		return nil, err
	}
	entries, _, err := gitTree(base, full)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Path = path.Join(dir, entries[i].Path)
	}
	return entries, nil
}

// Tags implements TagSource.
func (f FixtureReader) Tags(repo RepoRef) ([]Tag, error) {
	raw, err := os.ReadFile(filepath.Join(f.repoDir(repo), "tags.json"))
	if err != nil {
		return nil, err
	}
	var tags map[string]string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tags); err != nil {
		return nil, fmt.Errorf("fixture tags: %w", err)
	}
	out := make([]Tag, 0, len(tags))
	for name, commit := range tags {
		out = append(out, Tag{Name: name, Commit: commit})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func ignoredFixtureName(name string) bool { return name == ".DS_Store" }

// gitTree returns the entries of dir (names only) and the git tree id of
// dir, computed as git computes it. root is the commit directory that no
// symlink target may leave.
func gitTree(root, dir string) ([]TreeEntry, string, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", err
	}
	var entries []TreeEntry
	for _, item := range items {
		if ignoredFixtureName(item.Name()) {
			continue
		}
		full := filepath.Join(dir, item.Name())
		switch {
		case item.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return nil, "", err
			}
			if err := checkSymlinkTarget(root, dir, target); err != nil {
				return nil, "", fmt.Errorf("%w: %s -> %s", ErrFixtureSymlink, full, target)
			}
			entries = append(entries, TreeEntry{Mode: "120000", Type: "blob", SHA: gitObjectID("blob", []byte(target)), Path: item.Name()})
		case item.IsDir():
			_, id, err := gitTree(root, full)
			if err != nil {
				return nil, "", err
			}
			entries = append(entries, TreeEntry{Mode: "040000", Type: "tree", SHA: id, Path: item.Name()})
		case item.Type().IsRegular():
			data, err := os.ReadFile(full)
			if err != nil {
				return nil, "", err
			}
			entries = append(entries, TreeEntry{Mode: "100644", Type: "blob", SHA: gitObjectID("blob", data), Path: item.Name()})
		default:
			return nil, "", fmt.Errorf("fixture %s is neither a file nor a directory", full)
		}
	}
	// git orders tree entries by name, comparing a directory as if its name
	// ended in "/".
	sortName := func(e TreeEntry) string {
		if e.Type == "tree" {
			return e.Path + "/"
		}
		return e.Path
	}
	sort.Slice(entries, func(i, j int) bool { return sortName(entries[i]) < sortName(entries[j]) })
	var buf bytes.Buffer
	for _, e := range entries {
		mode := e.Mode
		if e.Type == "tree" {
			mode = "40000"
		}
		raw, _ := hex.DecodeString(e.SHA)
		buf.WriteString(mode + " " + e.Path + "\x00")
		buf.Write(raw)
	}
	// Listings are returned in tree order, as ls-tree prints them.
	return entries, gitObjectID("tree", buf.Bytes()), nil
}

// checkSymlinkTarget accepts a relative target that, resolved lexically
// from the link's directory, stays inside root. Nothing is read from disk,
// so a dangling target is fine, as it is in git.
func checkSymlinkTarget(root, dir, target string) error {
	if target == "" || filepath.IsAbs(target) || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return ErrFixtureSymlink
	}
	resolved := filepath.Join(dir, filepath.FromSlash(target))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ErrFixtureSymlink
	}
	return nil
}

func gitObjectID(kind string, data []byte) string {
	h := sha1.New() //nolint:gosec // git object ids are SHA-1 by definition
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
