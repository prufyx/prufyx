// SPDX-License-Identifier: AGPL-3.0-only

package istionotes

import (
	"embed"
	"io/fs"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// SourceDir is this package's directory under the module's internal/.
const SourceDir = "extract/istionotes"

//go:embed *.go
var own embed.FS

const encoderPrefix = "membercode_"

// SourceSet is the code a digest of an extractor built on this reader must
// cover: this package and the shared member encoder it calls. The encoder's
// files appear under the prefix "membercode_", so a change to the encoder
// moves the digest.
func SourceSet() extract.SourceSet {
	m := fstest.MapFS{}
	add := func(prefix string, src fs.FS) {
		entries, err := fs.ReadDir(src, ".")
		if err != nil {
			panic("istionotes: embedded source unreadable: " + err.Error())
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := fs.ReadFile(src, e.Name())
			if err != nil {
				panic("istionotes: embedded source unreadable: " + err.Error())
			}
			m[prefix+e.Name()] = &fstest.MapFile{Data: b, Mode: 0o444}
		}
	}
	add("", own)
	add(encoderPrefix, membercode.Source())
	return extract.SourceSet{Dir: SourceDir, Files: m}
}
