// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"embed"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// SourceDir is this package's directory under the module's internal/.
const SourceDir = "extract/cliflags"

//go:embed *.go
var own embed.FS

// SourceSet is the code a digest of an extractor built on this scanner must
// cover: the scanner and its reviewed import allowlist are code, so a change
// to either moves the digest.
func SourceSet() extract.SourceSet { return extract.SourceSet{Dir: SourceDir, Files: own} }
