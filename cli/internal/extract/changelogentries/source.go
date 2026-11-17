// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"embed"
	"io/fs"
)

//go:embed *.go
var source embed.FS

// SourceFS is this package's own Go source, so that an extractor that calls
// Locate can fold the reader into its code digest.
func SourceFS() fs.FS { return source }
