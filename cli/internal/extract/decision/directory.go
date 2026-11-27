// SPDX-License-Identifier: AGPL-3.0-only
package decision

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ReadDirectory reads a bounded regular-file snapshot, without following
// symbolic links or permitting resolution outside the opened directory.
func ReadDirectory(dir string) ([]File, error) {
	return readDirectory(dir, maxBytes)
}

func readDirectory(dir string, limit int) ([]File, error) {
	fi, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !fi.IsDir() {
		return nil, errors.New("input must be a real directory")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	var names []string
	e = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink input")
		}
		if d.IsDir() {
			if name != "reads" {
				return errors.New("unsupported input directory")
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("nonregular input")
		}
		names = append(names, name)
		if len(names) > maxFiles {
			return errors.New("file count limit")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Strings(names)
	files := []File{}
	total := 0
	for _, name := range names {
		// Check every component inside the held root before and after the read.
		check := func() error {
			for part := name; part != "."; part = filepath.Dir(part) {
				st, e := root.Lstat(part)
				if e != nil {
					return e
				}
				if st.Mode()&os.ModeSymlink != 0 {
					return errors.New("symlink input component")
				}
			}
			return nil
		}
		if e := check(); e != nil {
			return nil, e
		}
		before, e := root.Lstat(name)
		if e != nil {
			return nil, e
		}
		f, e := root.Open(name)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) {
			f.Close()
			return nil, errors.New("input identity changed")
		}
		b, e := io.ReadAll(io.LimitReader(f, int64(limit-total)+1))
		after, se := f.Stat()
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if se != nil || ce != nil || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
			return nil, errors.New("input changed during read")
		}
		if e := check(); e != nil {
			return nil, e
		}
		total += len(b)
		if total > limit {
			return nil, errors.New("input size limit")
		}
		files = append(files, File{Path: name, Mode: uint32(st.Mode().Perm()), Data: b})
	}
	return files, nil
}
func ReadPair(dir string) (Pair, error) {
	files, e := readDirectory(dir, maxPairBytes)
	if e != nil {
		return Pair{}, e
	}
	if len(files) != 2 {
		return Pair{}, errors.New("pair directory must contain exactly two files")
	}
	p := Pair{}
	for _, f := range files {
		if f.Mode != 0o644 {
			return Pair{}, errors.New("pair mode must be 0644")
		}
		switch f.Path {
		case DecisionFile:
			p.Decision = f.Data
		case ReceiptFile:
			p.Receipt = f.Data
		default:
			return Pair{}, errors.New("unexpected pair file")
		}
	}
	return p, Validate(p)
}
func (p Pair) Files() (map[string][]byte, error) {
	if e := Validate(p); e != nil {
		return nil, e
	}
	return map[string][]byte{DecisionFile: p.Decision, ReceiptFile: p.Receipt}, nil
}
