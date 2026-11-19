// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import "encoding/json"

// Entry is the proof that one tag's own changelog entry was read in full.
// Everything in it is derived from the pinned bytes; nothing is hand-written.
type Entry struct {
	Component string    `json:"component"`
	Tag       string    `json:"tag"`
	Version   string    `json:"version"`
	TagCommit string    `json:"tagCommit"`
	Source    Source    `json:"source"`
	Section   Section   `json:"section"`
	Structure []Heading `json:"structure"`
	Items     []Item    `json:"items"`
	Tiling    Tiling    `json:"tiling"`
	// ResidueLines is the number of section lines that were not a heading, a
	// blank, a link reference definition or inside an item. It is always 0 in
	// a returned Entry; a section with residue is withheld instead.
	ResidueLines int `json:"residueLines"`
}

// Source names the pinned bytes. Commit is the tag commit.
type Source struct {
	Repo       string `json:"repo"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
	FileDigest string `json:"fileDigest"` // sha256 of the whole blob as stored
	Form       string `json:"form"`
	// CheckedBytes is the length of the leading part of the blob the
	// file-wide agreement checks covered (the entry and everything above it,
	// up to and including the heading that follows it; the whole blob when
	// nothing follows). CheckedDigest is the sha256 of exactly those bytes.
	CheckedBytes  int    `json:"checkedBytes"`
	CheckedDigest string `json:"checkedDigest"`
}

// Section is the entry's line span (1-based, inclusive, trailing blank lines
// excluded). Digest is the sha256 of the section's lines, each followed by LF.
type Section struct {
	HeadingLine int    `json:"headingLine"`
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine"`
	Digest      string `json:"digest"`
}

// Heading is a heading inside the span: the version heading (Kind "version")
// or a sub-heading (Kind "sub"). EndLine is its last line (a setext
// underline), equal to Line for an ATX heading.
type Heading struct {
	Level   int    `json:"level"`
	Text    string `json:"text"`
	Kind    string `json:"kind"`
	Line    int    `json:"line"`
	EndLine int    `json:"endLine"`
}

// Item is one list item or one paragraph or fenced block outside a list.
// Digest is hex sha256(component NUL version NUL headingPath NUL marker NUL
// item bytes), where headingPath joins the sub-heading texts with U+001F and
// the item bytes are its lines joined by LF. Moving an item under another
// heading changes its digest.
type Item struct {
	Digest      string   `json:"digest"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	HeadingPath []string `json:"headingPath"`
	Marker      string   `json:"marker"`
	Kind        string   `json:"kind"` // "list" or "block"
	// Occurrence is 1 for the first item with this digest in the entry, 2 for
	// an identical repeat under the same heading, and so on.
	Occurrence int `json:"occurrence"`
}

// Tiling accounts for every line of the section: the five counts add up to
// the section's line count.
type Tiling struct {
	Lines     int `json:"lines"`
	Headings  int `json:"headings"`
	Blanks    int `json:"blanks"`
	LinkDefs  int `json:"linkDefs"`
	ItemLines int `json:"itemLines"`
	// Comments counts C2 single-line comments; they are part of the section
	// (and its digest) but are not items. Omitted when 0.
	Comments int `json:"comments,omitempty"`
}

// Canonical returns the entry as compact JSON; equal inputs give equal bytes.
func (e Entry) Canonical() ([]byte, error) { return json.Marshal(e) }
