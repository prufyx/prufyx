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

	"github.com/prufyx/prufyx/cli/internal/validation"
)

// MaxFileBytes bounds every knowledge file the gate reads.
const MaxFileBytes = 16 << 20

// ErrMissing reports a file that does not exist in a tree. It matches
// fs.ErrNotExist as well.
var ErrMissing = fmt.Errorf("file does not exist: %w", fs.ErrNotExist)

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

// Read returns a regular file's bytes. Every path component is opened
// relative to its parent without following symbolic links, the file is
// opened without blocking (a FIFO or device is refused, never read), and
// at most limit bytes are read. A missing file is ErrMissing.
func (t Tree) Read(rel string, limit int64) ([]byte, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	f, err := t.openFile(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", rel, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", rel, limit)
	}
	return raw, nil
}

// openDir opens the tree directory rel ("" for the root) component by
// component, never following a symbolic link.
func (t Tree) openDir(rel string) (*os.File, error) {
	dir, err := os.Open(t.Root)
	if err != nil {
		return nil, err
	}
	if rel == "" {
		return dir, nil
	}
	for _, part := range strings.Split(rel, "/") {
		kind, err := validation.StatEntry(dir, part)
		if errors.Is(err, fs.ErrNotExist) {
			dir.Close()
			return nil, fmt.Errorf("%w: %s", ErrMissing, rel)
		}
		if err != nil || kind != validation.EntryDirectory {
			dir.Close()
			return nil, fmt.Errorf("%s: parent %s is not a plain directory", rel, part)
		}
		next, err := validation.OpenEntryDirectory(dir, part)
		dir.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: parent %s is not a plain directory: %v", rel, part, err)
		}
		dir = next
	}
	return dir, nil
}

func (t Tree) openFile(rel string) (*os.File, error) {
	parent, name := "", rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		parent, name = rel[:i], rel[i+1:]
	}
	dir, err := t.openDir(parent)
	if err != nil {
		if errors.Is(err, ErrMissing) {
			return nil, fmt.Errorf("%w: %s", ErrMissing, rel)
		}
		return nil, err
	}
	defer dir.Close()
	kind, err := validation.StatEntry(dir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissing, rel)
	}
	if err != nil {
		return nil, err
	}
	if kind != validation.EntryRegular {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	f, err := validation.OpenEntryFile(dir, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", rel, err)
	}
	return f, nil
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
	dir, err := t.openDir(rel)
	if errors.Is(err, ErrMissing) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := dir.Readdirnames(maxEntries + 1)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxEntries {
		return nil, fmt.Errorf("%s holds more than %d entries", rel, maxEntries)
	}
	out := map[string][]byte{}
	for _, name := range names {
		raw, err := t.Read(rel+"/"+name, limit)
		if err != nil {
			return nil, err
		}
		out[name] = raw
	}
	return out, nil
}

// readUnder returns a reader of paths relative to the tree directory dir.
func (t Tree) readUnder(dir string) func(rel string) ([]byte, error) {
	return func(rel string) ([]byte, error) { return t.Read(dir+"/"+rel, MaxFileBytes) }
}

// readPath reads a file named by Root joined with its tree path, the form
// in which the support inventory configuration names its inputs.
func (t Tree) readPath(full string, limit int64) ([]byte, error) {
	rel, err := filepath.Rel(t.Root, full)
	if err != nil {
		return nil, err
	}
	return t.Read(filepath.ToSlash(rel), limit)
}

// SpecialFiles lists, sorted, every path below the tree directory dir that
// is neither a regular file nor a directory: symbolic links, FIFOs,
// devices, sockets.
func (t Tree) SpecialFiles(dir string) ([]string, error) {
	var out []string
	root := filepath.Join(t.Root, filepath.FromSlash(dir))
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			rel, err := filepath.Rel(t.Root, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// fileDigests maps every file below the tree root (except .git) to a digest
// of its executable bit and content; a symbolic link is recorded by its target, any other
// non-regular file by its type (it is never opened).
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
			info, err := d.Info()
			if err != nil {
				return err
			}
			f, err := validation.OpenInputRegularFile(p)
			if err != nil {
				return err
			}
			h := sha256.New()
			// The git mode is part of what merges: an executable bit
			// flipped with no content change is a change.
			if info.Mode().Perm()&0o111 != 0 {
				h.Write([]byte("exec\x00"))
			} else {
				h.Write([]byte("file\x00"))
			}
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

// executable reports whether rel is a regular file with an executable bit.
func (t Tree) executable(rel string) bool {
	info, err := os.Lstat(filepath.Join(t.Root, filepath.FromSlash(rel)))
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
