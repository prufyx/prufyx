// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
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
// The view is an fs.ReadDirFS whose root lists only those files (test files
// included; extract.CodeFiles skips them); every other name does not exist in
// it, and the root itself cannot be opened, so fs.Stat, fs.WalkDir and fs.Sub
// do not work on it: list it with fs.ReadDir or fs.Glob. Digest lines name the
// files by their paths in the package, with their bytes.
//
// The extractor's output also depends on the custom-resource table (which
// definitions are foreign), so the view adds one synthetic file,
// AttributionFileName, holding the listings of every group the project's own
// row lists and of every project sharing those groups (see
// customresources.Index.ListingsSharing): the digest then moves exactly when
// attribution for this project changes, and not on unrelated table edits. A
// project without a row folds nothing extra. CodeView reads the embedded
// table; CodeViewWithIndex the table the extractor attributes by.
func CodeView(fsys fs.FS, project string) fs.FS {
	return CodeViewWithIndex(fsys, project, customresources.DefaultIndex())
}

// AttributionFileName is the synthetic data file of a CodeView.
const AttributionFileName = "attribution.json"

// CodeViewWithIndex is CodeView for an extractor that attributes by ix.
func CodeViewWithIndex(fsys fs.FS, project string, ix customresources.Index) fs.FS {
	v := codeView{fsys: fsys, own: TargetFileName(project)}
	if lines := ix.ListingsSharing(project); len(lines) > 0 {
		v.attr = []byte(strings.Join(lines, "\n") + "\n")
	}
	return v
}

type codeView struct {
	fsys fs.FS
	own  string
	attr []byte // the synthetic attribution file; nil when there is none
}

// attrFile is the in-memory attribution file.
type attrFile struct {
	data []byte
	off  int
}

type attrInfo struct{ size int64 }

func (i attrInfo) Name() string       { return AttributionFileName }
func (i attrInfo) Size() int64        { return i.size }
func (i attrInfo) Mode() fs.FileMode  { return 0o444 }
func (i attrInfo) ModTime() time.Time { return time.Time{} }
func (i attrInfo) IsDir() bool        { return false }
func (i attrInfo) Sys() any           { return nil }

func (f *attrFile) Stat() (fs.FileInfo, error) { return attrInfo{int64(len(f.data))}, nil }
func (f *attrFile) Close() error               { return nil }
func (f *attrFile) Read(b []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(b, f.data[f.off:])
	f.off += n
	return n, nil
}

func (v codeView) keep(name string) bool {
	return name == v.own || (path.Ext(name) == ".go" && !strings.Contains(name, "/"))
}

// Open implements fs.FS.
func (v codeView) Open(name string) (fs.File, error) {
	if name == AttributionFileName && v.attr != nil {
		return &attrFile{data: v.attr}, nil
	}
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
	if v.attr != nil {
		out = append(out, fs.FileInfoToDirEntry(attrInfo{int64(len(v.attr))}))
	}
	return out, nil
}
