// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Pinned read-only sources (see PinnedSource). A project sometimes ships a
// source template that names the kind (a cue template of an adopt command,
// embedded into a program with //go:embed) and that no scan can read: the
// scan has no parser for it, so the file stays opaque and no definition may
// be taken to be gone while it is in the tree. A reviewed entry may instead
// pin the exact bytes by content digest: the claim "this file applies
// nothing and defines nothing" is then a question about bytes a reviewer
// read once, which the scan holds the file to at every tag.

// pinnedSourceExts is the closed list of extensions a pinned source may
// have; any other kind of file is read by a real reader.
var pinnedSourceExts = []string{".cue"}

// apiextensionsMarker is the text a pinned source may not hold, in any
// letter case: a belt independent of the digest (a heuristic, not a proof;
// the digest is the control).
const apiextensionsMarker = "apiextensions.k8s.io"

// PinnedSource declares that the file an exclusion names is a read-only
// source the reviewer read: it is excluded from reading by class, not from
// the install-surface guard. At every tag the file must have exactly one of
// the listed SHA-256 digests; any other byte voids the entry.
type PinnedSource struct {
	// SHA256 are the accepted digests ("sha256:<64 hex>"), sorted, unique:
	// one per distinct byte content over the tags the entry must hold at.
	SHA256 []string
}

// Equal reports whether two declarations are the same (nil equals nil).
func (p *PinnedSource) Equal(o *PinnedSource) bool {
	if p == nil || o == nil {
		return p == o
	}
	return slices.Equal(p.SHA256, o.SHA256)
}

type pinnedJSON struct {
	SHA256 []string `json:"sha256"`
}

func (p *pinnedJSON) source() *PinnedSource {
	if p == nil {
		return nil
	}
	return &PinnedSource{SHA256: slices.Clone(p.SHA256)}
}

// validPinned checks the shape of a pinned-source entry ("" when it is
// accepted): exactly one file (no directory, no pattern) with an extension
// of the closed list, not together with copies, prePatch, defines or
// foreign, with a sorted unique digest list.
func validPinned(ej exclusionJSON) string {
	switch {
	case ej.Copies || ej.PrePatch != "" || ej.Defines != "" || ej.Foreign != nil:
		return "excludes copies, prePatch, defines and foreign"
	case strings.HasSuffix(ej.Path, "/"):
		return "names one file, not a directory"
	case strings.ContainsAny(ej.Path, globMeta+"\\{}"):
		return "names one file exactly: no pattern"
	case !slices.Contains(pinnedSourceExts, path.Ext(path.Base(ej.Path))):
		return fmt.Sprintf("names a file with one of the extensions %v (lower case)", pinnedSourceExts)
	}
	return strictSortedUnique("sha256", ej.Pinned.SHA256, sha256DigRE)
}

// pinnedSourceProblem checks the bytes of a pinned source at one tag ("" when
// every check holds): within the size bound, one of the pinned digests, no
// template syntax, and no text of the apiextensions group. Every check fails
// closed.
func pinnedSourceProblem(p *PinnedSource, data []byte) string {
	if p == nil || len(p.SHA256) == 0 {
		return "the entry declares no pin"
	}
	if len(data) > maxForeignBytes {
		return fmt.Sprintf("the file is over the %d-byte bound", maxForeignBytes)
	}
	sum := sha256.Sum256(data)
	if !slices.Contains(p.SHA256, sha256Prefix+hex.EncodeToString(sum[:])) {
		return "the file's digest is not one of the pinned digests"
	}
	if bytes.Contains(data, []byte(templateMarker)) {
		return "the file holds template syntax"
	}
	if bytes.Contains(bytes.ToLower(data), []byte(apiextensionsMarker)) {
		return "the file names " + apiextensionsMarker
	}
	return ""
}
