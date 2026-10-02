// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// frameworkSource is this package's own Go source, embedded at build time.
// The pattern includes test files; CodeDigest skips them.
//
//go:embed *.go
var frameworkSource embed.FS

// FrameworkDir is the package directory of the framework, relative to the
// module's internal/ tree, as it appears in code digest lines.
const FrameworkDir = "extract"

// CodeFile is one source file covered by a code digest.
type CodeFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SourceSet is a package directory and its embedded files.
type SourceSet struct {
	Dir   string
	Files fs.FS
}

// FrameworkSource returns the framework's own source set.
func FrameworkSource() SourceSet { return SourceSet{Dir: FrameworkDir, Files: frameworkSource} }

// CodeFiles lists the non-test Go files of the given source sets with their
// digests, sorted by path.
func CodeFiles(sets ...SourceSet) ([]CodeFile, error) {
	var out []CodeFile
	seen := map[string]bool{}
	for _, set := range sets {
		names, err := fs.Glob(set.Files, "*.go")
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, err := fs.ReadFile(set.Files, name)
			if err != nil {
				return nil, err
			}
			p := path.Join(set.Dir, name)
			if seen[p] {
				return nil, fmt.Errorf("source file %s listed twice", p)
			}
			seen[p] = true
			sum := sha256.Sum256(data)
			out = append(out, CodeFile{Path: p, SHA256: hex.EncodeToString(sum[:])})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no source files to digest")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// CodeDigest is sha256 over the sorted lines "<path> NUL <hex sha256> LF" of
// the files CodeFiles returns, as "sha256:<hex>".
func CodeDigest(files []CodeFile) string {
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Path + "\x00" + f.SHA256 + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
