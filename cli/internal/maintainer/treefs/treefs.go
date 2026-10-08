// SPDX-License-Identifier: AGPL-3.0-only

// Package treefs reads and writes single files below a directory without
// following a symbolic link on any path component below that directory. The
// directory itself is the caller's own choice and is opened as given.
//
// It exists so the maintainer commands that take a checked-out tree (a
// candidate the maintainer may not control) share one hardened reader and
// writer built from the descriptor-relative primitives of the validation
// package, the same ones the knowledge gate reads trees with: every component
// is opened relative to its parent with no-follow semantics, a file is opened
// without blocking (a FIFO or device is refused, never read), its type and
// size are checked on the open descriptor, and at most limit bytes are read.
// A write stages the data in a fresh exclusively created file beside the
// target, fsyncs it and renames it into place, so a symlink at the target is
// replaced and never written through.
package treefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/validation"
)

// ErrMissing reports a file or directory that does not exist. It matches
// fs.ErrNotExist as well.
var ErrMissing = fmt.Errorf("does not exist: %w", fs.ErrNotExist)

func cleanRel(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "\\") {
		return fmt.Errorf("invalid path %q", rel)
	}
	return nil
}

// OpenDir opens the directory rel below root ("" for root itself) component
// by component, never following a symbolic link below root.
func OpenDir(root, rel string) (*os.File, error) {
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		dir.Close()
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	if rel == "" {
		return dir, nil
	}
	if err := cleanRel(rel); err != nil {
		dir.Close()
		return nil, err
	}
	for _, part := range strings.Split(rel, "/") {
		kind, err := validation.StatEntry(dir, part)
		if errors.Is(err, fs.ErrNotExist) {
			dir.Close()
			return nil, fmt.Errorf("%w: %s", ErrMissing, rel)
		}
		if err != nil || kind != validation.EntryDirectory {
			dir.Close()
			return nil, fmt.Errorf("%s: %s is not a plain directory", rel, part)
		}
		next, err := validation.OpenEntryDirectory(dir, part)
		dir.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %s is not a plain directory: %v", rel, part, err)
		}
		dir = next
	}
	return dir, nil
}

func splitRel(rel string) (parent, name string, err error) {
	if err := cleanRel(rel); err != nil {
		return "", "", err
	}
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i], rel[i+1:], nil
	}
	return "", rel, nil
}

// Kind reports what rel is below root without following a link: it returns
// validation.EntryOther with ErrMissing for a missing entry.
func Kind(root, rel string) (validation.EntryKind, error) {
	parent, name, err := splitRel(rel)
	if err != nil {
		return validation.EntryOther, err
	}
	dir, err := OpenDir(root, parent)
	if err != nil {
		return validation.EntryOther, err
	}
	defer dir.Close()
	kind, err := validation.StatEntry(dir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return validation.EntryOther, fmt.Errorf("%w: %s", ErrMissing, rel)
	}
	return kind, err
}

// Read returns the bytes of the regular file rel below root. A symbolic link
// on any component below root, a FIFO, a device or any other non-regular
// file is refused without being read, and a file larger than limit is
// refused before its content is read.
func Read(root, rel string, limit int64) ([]byte, error) {
	parent, name, err := splitRel(rel)
	if err != nil {
		return nil, err
	}
	dir, err := OpenDir(root, parent)
	if err != nil {
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

// Write replaces the file rel below root with data. Every directory on the
// path must already exist as a plain directory (a symbolic link is refused),
// and an existing target must be a regular file (a symbolic link, FIFO or
// directory is refused and nothing is written). The data is staged in a
// fresh exclusively created file in the same directory, chmodded, fsynced
// and renamed into place; on failure the staging file is removed.
func Write(root, rel string, data []byte, perm fs.FileMode) error {
	parent, name, err := splitRel(rel)
	if err != nil {
		return err
	}
	dir, err := OpenDir(root, parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	switch kind, err := validation.StatEntry(dir, name); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case kind != validation.EntryRegular:
		return fmt.Errorf("%s exists and is not a regular file", rel)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	stage := ".treefs-" + hex.EncodeToString(suffix[:])
	f, err := validation.CreateEntryFile(dir, stage, 0o600)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			f.Close()
			_ = validation.RemoveEntry(dir, stage)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := validation.ReplaceEntry(dir, stage, name); err != nil {
		return err
	}
	done = true
	return validation.SyncDirectory(dir)
}
