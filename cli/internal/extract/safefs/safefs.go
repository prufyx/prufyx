// SPDX-License-Identifier: AGPL-3.0-only

// Package safefs holds the file writes of the extract subsystem: a symlink is
// never written through (one present when the target is checked is refused;
// one that appears later is replaced or fails the rename, never followed),
// files are staged beside their target and renamed into place after an fsync,
// and modes are explicit, never derived from the umask. It is deliberately outside the extract framework package, whose
// source is part of every extractor's code digest.
package safefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/noreplace"
)

// DirMode and FileMode are the modes of created output directories and files.
const (
	DirMode  fs.FileMode = 0o755
	FileMode fs.FileMode = 0o644
)

// WriteFile atomically writes data to path with mode perm. The path may
// exist only as a regular file (it is replaced, never written through); a
// symlink or any other kind of entry present at the check is refused, and a
// symlink that appears afterwards is replaced by the rename, never followed. The data is staged in a
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
	return syncDir(dir)
}

// WriteTree writes files (slash-separated relative names) into dir, which
// must not exist or be an empty real directory (a symlink is refused when it
// is present at the check). The tree is built in a staging directory beside
// dir and renamed into place without replacing anything that appeared at dir
// meanwhile, so a failure leaves neither a partial output nor staging
// leftovers. An existing empty dir is replaced by the staged one, which takes
// over its permission bits (never loosened past DirMode); its owner, ACLs and
// xattrs are not preserved. When dir is the current directory it cannot be
// replaced, so the staged entries are moved into it and removed again on
// failure.
func WriteTree(dir string, files map[string][]byte) error {
	dir = filepath.Clean(dir)
	mode := DirMode
	existing := false
	if fi, err := os.Lstat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("output path %s exists and is not a directory (a symlink is refused)", dir)
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(items) > 0 {
			return fmt.Errorf("output directory %s is not empty", dir)
		}
		existing = true
		mode = fi.Mode().Perm() & DirMode
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	inPlace := existing && isCwd(dir)
	names := make([]string, 0, len(files))
	for name := range files {
		if err := checkName(name); err != nil {
			return err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	parent := filepath.Dir(dir)
	if inPlace {
		parent = "."
	}
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
	if err := os.Chmod(stage, mode); err != nil {
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
		if err := syncDir(d); err != nil {
			return err
		}
	}
	if inPlace {
		if err := moveInto(stage, ".", names); err != nil {
			return err
		}
		ok = true
		os.RemoveAll(stage)
		return syncDir(".")
	}
	// rmdir removes only an empty directory, so one that filled up meanwhile
	// still fails closed; the no-replace rename then fails if anything at all
	// was created at dir in between.
	if existing {
		if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := renameNoReplace(parent, filepath.Base(stage), filepath.Base(dir)); err != nil {
		return err
	}
	ok = true
	return syncDir(parent)
}

// renameNoReplace renames from to to inside parent without replacing an
// existing destination. Where the platform or filesystem has no such rename
// it falls back to os.Rename, which still refuses a non-empty directory.
func renameNoReplace(parent, from, to string) error {
	d, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer d.Close()
	err = noreplace.Rename(d, from, to)
	if errors.Is(err, noreplace.ErrUnsupported) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.ENOTSUP) {
		return os.Rename(filepath.Join(parent, from), filepath.Join(parent, to))
	}
	return err
}

// isCwd reports whether p is the process's current directory.
func isCwd(p string) bool {
	a, err := os.Stat(p)
	if err != nil {
		return false
	}
	b, err := os.Stat(".")
	return err == nil && os.SameFile(a, b)
}

// moveInto moves the top-level entries of the staged names from stage into
// the existing empty directory dst. If one move fails, the entries already
// moved are removed again so that dst is empty as before.
func moveInto(stage, dst string, names []string) error {
	var moved []string
	seen := map[string]bool{}
	for _, n := range names {
		top := strings.SplitN(n, "/", 2)[0]
		if seen[top] {
			continue
		}
		seen[top] = true
		if err := os.Rename(filepath.Join(stage, top), filepath.Join(dst, top)); err != nil {
			for _, m := range moved {
				os.RemoveAll(filepath.Join(dst, m))
			}
			return err
		}
		moved = append(moved, top)
	}
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

// syncDir makes a rename or create durable. A filesystem that cannot sync a
// directory (EINVAL, ENOTSUP), and Windows, which has no directory fsync, are
// not an error; any other failure (such as EIO) is returned.
func syncDir(d string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	return err
}
