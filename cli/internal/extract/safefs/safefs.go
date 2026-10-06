// SPDX-License-Identifier: AGPL-3.0-only

// Package safefs holds the file writes of the extract subsystem: no symlink
// is followed or replaced, files are staged beside their target and renamed
// into place after an fsync, and modes are explicit, never derived from the
// umask. It is deliberately outside the extract framework package, whose
// source is part of every extractor's code digest.
package safefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// DirMode and FileMode are the modes of created output directories and files.
const (
	DirMode  fs.FileMode = 0o755
	FileMode fs.FileMode = 0o644
)

// WriteFile atomically writes data to path with mode perm. The path may
// exist only as a regular file (it is replaced, never written through); a
// symlink or any other kind of entry is refused. The data is staged in a
// fresh exclusively created file in the same directory, chmodded, fsynced
// and renamed; on failure the staging file is removed.
func WriteFile(p string, data []byte, perm fs.FileMode) error {
	if fi, err := os.Lstat(p); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file", p)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(p)
	if fi, err := os.Stat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	tmp, err := os.CreateTemp(dir, ".safefs-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, p); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}

// WriteTree writes files (slash-separated relative names) into dir, which
// must not exist or be an empty real directory (a symlink is refused). The
// tree is built in a staging directory beside dir and renamed into place, so
// a failure leaves neither a partial output nor staging leftovers; a dir that
// became non-empty meanwhile makes the final rmdir fail.
func WriteTree(dir string, files map[string][]byte) error {
	dir = filepath.Clean(dir)
	if fi, err := os.Lstat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("output path %s exists and is not a directory (symlinks are refused)", dir)
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(items) > 0 {
			return fmt.Errorf("output directory %s is not empty", dir)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if err := checkName(name); err != nil {
			return err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, DirMode); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".safefs-out-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, DirMode); err != nil {
		return err
	}
	for _, name := range names {
		p := filepath.Join(stage, filepath.FromSlash(name))
		if err := mkdirs(stage, filepath.Dir(p)); err != nil {
			return err
		}
		if err := writeNew(p, files[name]); err != nil {
			return err
		}
	}
	for _, d := range stagedDirs(stage, names) {
		syncDir(d)
	}
	// Go refuses to rename onto an existing directory; rmdir removes only an
	// empty one, so a dir that filled up meanwhile still fails closed.
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, dir); err != nil {
		return err
	}
	ok = true
	syncDir(parent)
	return nil
}

// checkName refuses names that are not clean, relative, slash-separated
// paths under the output root.
func checkName(name string) error {
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") {
		return fmt.Errorf("unsafe output file name %q", name)
	}
	return nil
}

// mkdirs creates the directories from root down to d (all under root) with
// DirMode, refusing anything already there that is not a real directory.
func mkdirs(root, d string) error {
	rel, err := filepath.Rel(root, d)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s escapes the output root", d)
	}
	if rel == "." {
		return nil
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if err := os.Mkdir(cur, DirMode); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return err
			}
			fi, lerr := os.Lstat(cur)
			if lerr != nil || !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", cur)
			}
			continue
		}
		if err := os.Chmod(cur, DirMode); err != nil {
			return err
		}
	}
	return nil
}

// writeNew creates p exclusively, without following a symlink, and writes it.
func writeNew(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, FileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(FileMode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func stagedDirs(stage string, names []string) []string {
	seen := map[string]bool{stage: true}
	out := []string{stage}
	for _, n := range names {
		for d := filepath.Dir(filepath.Join(stage, filepath.FromSlash(n))); !seen[d]; d = filepath.Dir(d) {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// syncDir makes a rename or create durable; directories that cannot be
// synced (some filesystems) are not an error.
func syncDir(d string) {
	if f, err := os.Open(d); err == nil {
		f.Sync()
		f.Close()
	}
}
