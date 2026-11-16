// SPDX-License-Identifier: AGPL-3.0-only

// Package changelogentries locates the changelog entry of one release tag in
// the changelog file as it stands AT THAT TAG, and proves the entry was read
// in full.
//
// For a reviewed Target (repository, file path, heading pattern) and a tag
// with its full commit, Locate reads the file through an extract.PinnedReader
// at that commit and returns an Entry: the file digest, the heading line, the
// section bounds, the section digest, the headings inside the entry, and one
// digest-bearing item per list item or paragraph. Every line of the section
// must be a heading, a blank line, a link reference definition or inside
// exactly one item; a single other line withholds the entry
// (ENTRY_PARSE_RESIDUE). A neighbouring entry is never read instead of a
// missing one, and no source is ever truncated: a file or section over its
// bound is withheld (ENTRY_OVER_BOUND).
//
// A version heading is recognised only by the target's own anchored pattern,
// with one capture "version" that must be a canonical final version
// (2.5.0 is never 2.50.0, a leading zero is not a version, a pre-release is
// not final). Exactly one heading must name the version. The section ends at
// the next heading of the same or a higher level, and that heading must be
// another release heading of the target (a final one, or one of the target's
// listed boundary patterns such as an unreleased or release-candidate
// heading); any other heading there leaves the end unproven
// (ENTRY_BOUNDARY_UNPROVEN). Release headings nested inside the entry are
// refused for the same reason.
//
// Markdown is read by a small closed line grammar (ATX and setext headings,
// fenced code, column-zero list items with indented or lazy continuation,
// column-zero paragraphs). CRLF files are read as LF when every line break
// is CRLF; any other carriage return, a byte order mark, a NUL or invalid
// UTF-8 withholds the entry.
//
// Sources that are not a pinned file at the tag (release bodies, entries that
// land after the tag, upgrade guides, monorepo entries) are not read: the
// typed reason is returned and nothing is fetched.
//
// The package is inert: no attestation, no catalogue registration, no CLI
// wiring. Output is canonical JSON and byte-equal for equal inputs.
package changelogentries
