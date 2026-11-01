// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"embed"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// SourceDir is this package's directory under the module's internal/.
const SourceDir = "extract/crdschema"

//go:embed *.go
var own embed.FS

// SourceSet is the code a digest of this extractor must cover: this package
// and the shared member encoder it calls. The encoder's files appear under
// the prefix "membercode_" so that a change to the encoder moves the digest.
func SourceSet() extract.SourceSet { return extract.SourceSet{Dir: SourceDir, Files: unionFS{}} }

// unionFS is a flat, read-only view of the two embedded source trees.
type unionFS struct{}

const encoderPrefix = "membercode_"

func (unionFS) names() []string {
	var out []string
	for _, fsys := range []struct {
		prefix string
		fs     fs.FS
	}{{"", own}, {encoderPrefix, membercode.Source()}} {
		entries, _ := fs.ReadDir(fsys.fs, ".")
		for _, e := range entries {
			if !e.IsDir() {
				out = append(out, fsys.prefix+e.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}

func (unionFS) resolve(name string) (fs.FS, string) {
	if rest, ok := strings.CutPrefix(name, encoderPrefix); ok {
		return membercode.Source(), rest
	}
	return own, name
}

// Open implements fs.FS.
func (u unionFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &rootDir{u: u}, nil
	}
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, n := u.resolve(name)
	return f.Open(n)
}

// ReadFile implements fs.ReadFileFS.
func (u unionFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	f, n := u.resolve(name)
	return fs.ReadFile(f, n)
}

// ReadDir implements fs.ReadDirFS.
func (u unionFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var out []fs.DirEntry
	for _, n := range u.names() {
		f, rn := u.resolve(n)
		info, err := fs.Stat(f, rn)
		if err != nil {
			return nil, err
		}
		out = append(out, fs.FileInfoToDirEntry(renamed{info, n}))
	}
	return out, nil
}

type renamed struct {
	fs.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

type rootDir struct {
	u   unionFS
	pos int
}

func (*rootDir) Stat() (fs.FileInfo, error) { return rootInfo{}, nil }
func (*rootDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: ".", Err: fs.ErrInvalid}
}
func (*rootDir) Close() error { return nil }

func (d *rootDir) ReadDir(n int) ([]fs.DirEntry, error) {
	all, err := d.u.ReadDir(".")
	if err != nil {
		return nil, err
	}
	rest := all[d.pos:]
	if n > 0 && len(rest) > n {
		rest = rest[:n]
	}
	d.pos += len(rest)
	if n > 0 && len(rest) == 0 {
		return nil, io.EOF
	}
	return rest, nil
}

type rootInfo struct{}

func (rootInfo) Name() string       { return "." }
func (rootInfo) Size() int64        { return 0 }
func (rootInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (rootInfo) ModTime() time.Time { return time.Time{} }
func (rootInfo) IsDir() bool        { return true }
func (rootInfo) Sys() any           { return nil }
