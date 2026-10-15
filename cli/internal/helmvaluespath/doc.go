// SPDX-License-Identifier: AGPL-3.0-only

// Package helmvaluespath reads Helm values files in a strict YAML subset
// and names their key paths: as text for people, and as members of a
// chart's values-path set fact. A rule that lists a values key and the
// reader that collects the keys a user sets must render the same path the
// same way, so both use Member here.
package helmvaluespath

import "embed"

// source is this package's own Go source, embedded at build time. The
// pattern includes test files; a code digest skips them.
//
//go:embed *.go
var source embed.FS

// SourceDir is this package's directory under the module's internal/.
const SourceDir = "helmvaluespath"

// Source returns the package's directory and embedded Go source, so an
// extractor that uses it can cover it with its code digest.
func Source() (dir string, files embed.FS) { return SourceDir, source }
