// SPDX-License-Identifier: AGPL-3.0-only

package goldenfile

import "bytes"

// Placeholders that stand for the embedded rule pack's revision and digest in
// stored files. They keep the shape of the real values, so a stored report
// still decodes, and they let a data-only change of the pack leave the files
// alone.
const (
	PackRevisionPlaceholder = "cncf-0000-00-00.0"
	PackDigestPlaceholder   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// MaskPack replaces the pack revision and digest in got with the placeholders.
func MaskPack(got []byte, revision, digest string) []byte {
	got = bytes.ReplaceAll(got, []byte(digest), []byte(PackDigestPlaceholder))
	return bytes.ReplaceAll(got, []byte(revision), []byte(PackRevisionPlaceholder))
}

// UnmaskPack is the reverse: it puts the real revision and digest where the
// placeholders stand.
func UnmaskPack(stored []byte, revision, digest string) []byte {
	stored = bytes.ReplaceAll(stored, []byte(PackDigestPlaceholder), []byte(digest))
	return bytes.ReplaceAll(stored, []byte(PackRevisionPlaceholder), []byte(revision))
}
