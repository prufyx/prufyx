// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"io/fs"
	"path"
	"strings"
)

// CodeView is the part of a package source tree that the code digest of one
// project's extractor id covers: the Go files at its root and the project's
// own target file (TargetFileName), and nothing else. The extractor of that
// id reads no other target: it holds one Target and every read, scan, guard
// and remote pin it uses is a field of that target. The other target files
// are read only by LoadTargets, whose cross-file checks can refuse to start
// the program but never change what an extractor derives. So the digest of
// an id moves with the code and with its own target, and with nothing else.
//
// The view is an fs.ReadDirFS whose root lists only those files; every other
// name does not exist in it. Digest lines name the files by their paths in
// the package, with their bytes.
func CodeView(fsys fs.FS, project string) fs.FS {
	return codeView{fsys: fsys, own: TargetFileName(project)}
}

type codeView struct {
	fsys fs.FS
	own  string
}

func (v codeView) keep(name string) bool {
	return name == v.own || (path.Ext(name) == ".go" && !strings.Contains(name, "/"))
}

// Open implements fs.FS.
func (v codeView) Open(name string) (fs.File, error) {
	if name != "." && !v.keep(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	return v.fsys.Open(name)
}

// ReadDir implements fs.ReadDirFS for the root, the only directory.
func (v codeView) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	entries, err := fs.ReadDir(v.fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, e := range entries {
		if !e.IsDir() && v.keep(e.Name()) {
			out = append(out, e)
		}
	}
	return out, nil
}
