# changelog.entries (reader, inert)

Status: implemented and locally verified as a reader library. It is not an
extractor in the catalogue, writes no attestation and is not wired into any
command. Nothing is decided by it yet.

## What it proves

For one reviewed target (repository, changelog file path, heading pattern) and
one release tag with its full commit, `changelogentries.Locate` reads the file
as it stands AT THAT TAG through the pinned reader and returns the tag's own
entry, read in full:

- the whole-file sha256 and the tag commit it was read at;
- the heading line, the section span and the sha256 of the section (LF);
- the headings inside the entry;
- every item (a list item, or a paragraph or fenced block outside a list) with
  its span, heading path, marker and digest;
- a tiling count in which every line of the section is a heading, a blank, a
  link reference definition or inside exactly one item. One other line
  withholds the entry.

The item digest is `sha256(component NUL version NUL headingPath NUL marker NUL
item bytes)` (four NUL separators, no terminator; heading texts are joined with
U+001F, and the file is refused if it holds any control byte other than TAB and
LF). Moving an item under another heading changes its digest. An identical item
repeated under the same heading (real changelogs have them) has the same digest
and an `occurrence` number, so nothing is dropped and one reviewed disposition
covers both copies.

## How an entry is found

- Only the target's anchored heading pattern names a release, and its capture
  must be a canonical final version: `2.5.0` is never `2.50.0`, `02.5.0` is
  not a version, a release candidate is not final.
- Exactly one heading must name the version.
- The section ends at the next heading of the same or a higher level, and that
  heading must be another release heading of the target (final, or one of its
  listed boundary patterns such as unreleased or release candidate). Any other
  heading there, or a release heading nested inside the entry, leaves the end
  unproven.
- The whole file is also read by an independent CommonMark parser, and the two
  readings must agree. Any disagreement anywhere in the file withholds every
  tag of that file with `ENTRY_PARSE_RESIDUE` ("commonmark-disagreement"), not
  only the tag whose entry is affected. It is raised when: a heading differs in
  position or level; a release or other heading sits inside a list item, a
  quote or any other container (a release boundary must be a top-level
  heading); the lines inside fenced code or an HTML block differ; the list
  items and paragraphs differ in count or span anywhere in the file; or a block
  starts before the section and reaches into it, or starts inside it and ends
  after it. Fix the changelog layout (or review the target by hand) rather than
  expecting a partial entry.
- A file or section over its bound is withheld, never truncated.
- CRLF is read as LF only when every line break is CRLF.
- No neighbouring tag, path or entry is ever read instead of a missing one.

## Typed reasons

A pair that cannot be decided carries one of: `NO_CHANGELOG_TARGET`,
`SOURCE_NOT_PINNED_GIT`, `SHAPE_NOT_PER_TAG`, `PATH_MISSING_AT_TAG`,
`ENTRY_MISSING`, `ENTRY_DUPLICATE`, `ENTRY_NOT_FINAL`, `ENTRY_NOT_AT_TAG`,
`ENTRY_EMPTY`, `ENTRY_REFERS_ELSEWHERE`, `ENTRY_BOUNDARY_UNPROVEN`,
`ENTRY_OVER_BOUND`, `ENTRY_PARSE_RESIDUE`, `MONOREPO_ENTRY_AMBIGUOUS`,
`LINE_TOO_MANY_FINALS` (a line whose release window needs more sources than one
record may cite is withheld, never truncated). The list
is closed (`Codes`); codes for later stages are reserved.

Release bodies (`SOURCE_NOT_PINNED_GIT`), entries that land after the tag
(`ENTRY_NOT_AT_TAG`), upgrade guides (`SHAPE_NOT_PER_TAG`) and monorepo entries
are not read at all in this version.

## Notes for later stages

- Mark identity is `(digest, occurrence)`: a disposition or rule citation must be
  keyed by both, and a changed occurrence count is a changed entry.
- A link reference definition is only `[label]: <destination> "optional title"`
  with an http(s), absolute, relative or fragment destination. Any other
  column-zero line, such as `[BREAKING]: removed flag --x`, is an item.
- `SHAPE_NOT_PER_TAG` here also covers per-line and per-version changelog files
  (`{toLine}` templates), which are an open follow-up; it does not always mean an
  upgrade guide, so read the form with the reason.

## What it does not do

It does not decide whether an item is breaking, does not classify, does not
attest and does not read any source other than one pinned file. An entry is
evidence that the text was read completely, not that the text is complete.
