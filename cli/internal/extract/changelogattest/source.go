// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"embed"
	"io/fs"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

// SourceDir is this package's directory under the module's internal/.
const SourceDir = "extract/changelogattest"

//go:embed *.go
var own embed.FS

const readerPrefix = "changelogentries_"

// SourceSet is the code a digest of this extractor must cover: this package
// and the entry reader it calls, whose files appear under the prefix
// "changelogentries_" so that a change to the reader moves the digest.
func SourceSet() extract.SourceSet {
	return extract.SourceSet{Dir: SourceDir, Files: union{}}
}

type union struct{}

func (union) pick(name string) (fs.FS, string) {
	if rest, ok := cutPrefix(name, readerPrefix); ok {
		return ce.SourceFS(), rest
	}
	return own, name
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return s, false
}

// Open implements fs.FS.
func (u union) Open(name string) (fs.File, error) {
	if name == "." || !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, n := u.pick(name)
	return f.Open(n)
}

// ReadFile implements fs.ReadFileFS.
func (u union) ReadFile(name string) ([]byte, error) {
	if name == "." || !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	f, n := u.pick(name)
	return fs.ReadFile(f, n)
}

// ReadDir implements fs.ReadDirFS for the root only.
func (u union) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var out []fs.DirEntry
	for _, s := range []struct {
		prefix string
		fsys   fs.FS
	}{{"", own}, {readerPrefix, ce.SourceFS()}} {
		entries, err := fs.ReadDir(s.fsys, ".")
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			out = append(out, fs.FileInfoToDirEntry(renamed{info, s.prefix + e.Name()}))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type renamed struct {
	fs.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }
