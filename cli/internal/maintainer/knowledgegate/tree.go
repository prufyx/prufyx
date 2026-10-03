// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// MaxFileBytes bounds every knowledge file the gate reads.
const MaxFileBytes = 16 << 20

// ErrMissing reports a file that does not exist in a tree.
var ErrMissing = errors.New("file does not exist")

// Tree is one repository checkout, read-only.
type Tree struct {
	Root string
}

func cleanRel(rel string) (string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("invalid repository path %q", rel)
	}
	return rel, nil
}

// Read returns a regular file's bytes. Symbolic links (at the file or any
// parent inside the tree) and files over limit are refused; a missing file
// is ErrMissing.
func (t Tree) Read(rel string, limit int64) ([]byte, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	if err := t.noLinks(rel); err != nil {
		return nil, err
	}
	full := filepath.Join(t.Root, filepath.FromSlash(rel))
	info, err := os.Lstat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissing, rel)
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", rel, limit)
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", rel, limit)
	}
	return raw, nil
}

// noLinks refuses a path any of whose parent directories inside the tree is
// a symbolic link, so a read can never leave the tree.
func (t Tree) noLinks(rel string) error {
	parts := strings.Split(rel, "/")
	cur := t.Root
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		info, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s: parent %s is not a plain directory", rel, cur)
		}
	}
	return nil
}

// ReadOptional is Read, returning nil and no error for a missing file.
func (t Tree) ReadOptional(rel string, limit int64) ([]byte, error) {
	raw, err := t.Read(rel, limit)
	if errors.Is(err, ErrMissing) {
		return nil, nil
	}
	return raw, err
}

// Exists reports whether rel exists (as anything) in the tree.
func (t Tree) Exists(rel string) bool {
	rel, err := cleanRel(rel)
	if err != nil {
		return false
	}
	_, err = os.Lstat(filepath.Join(t.Root, filepath.FromSlash(rel)))
	return err == nil
}

// Dir lists the regular files directly inside rel, by name, mapped to their
// bytes. A missing directory is empty. Anything that is not a regular file
// (a link, a subdirectory, a device) is refused.
func (t Tree) Dir(rel string, limit int64, maxEntries int) (map[string][]byte, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	if err := t.noLinks(rel + "/x"); err != nil {
		return nil, err
	}
	full := filepath.Join(t.Root, filepath.FromSlash(rel))
	info, err := os.Lstat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", rel)
	}
	items, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	if len(items) > maxEntries {
		return nil, fmt.Errorf("%s holds more than %d entries", rel, maxEntries)
	}
	out := map[string][]byte{}
	for _, item := range items {
		if !item.Type().IsRegular() {
			return nil, fmt.Errorf("%s/%s is not a regular file", rel, item.Name())
		}
		raw, err := t.Read(rel+"/"+item.Name(), limit)
		if err != nil {
			return nil, err
		}
		out[item.Name()] = raw
	}
	return out, nil
}

// fileDigests maps every file below the tree root (except .git) to a digest
// of its content; a symbolic link is recorded by its target.
func (t Tree) fileDigests() (map[string][32]byte, error) {
	out := map[string][32]byte{}
	err := filepath.WalkDir(t.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(t.Root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == ".git" {
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = sha256.Sum256([]byte("link\x00" + target))
		case d.Type().IsRegular():
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			h := sha256.New()
			h.Write([]byte("file\x00"))
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			out[rel] = sum
		default:
			out[rel] = sha256.Sum256([]byte("other\x00" + d.Type().String()))
		}
		return nil
	})
	return out, err
}

// ChangedPaths lists, sorted, every path whose content differs between the
// two trees, including paths present in only one of them.
func ChangedPaths(base, head Tree) ([]string, error) {
	b, err := base.fileDigests()
	if err != nil {
		return nil, fmt.Errorf("walk base: %w", err)
	}
	h, err := head.fileDigests()
	if err != nil {
		return nil, fmt.Errorf("walk head: %w", err)
	}
	var out []string
	for p, d := range b {
		if hd, ok := h[p]; !ok || !bytes.Equal(hd[:], d[:]) {
			out = append(out, p)
		}
	}
	for p := range h {
		if _, ok := b[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}
