# Reading one changelog entry

`prufyx-maintainer changelog entries` reads the changelog entry of one release
tag and prints a manifest of what it read. It is a maintainer tool: it runs
offline, reads only the factory mirror or a fixture tree, calls no model and no
network service, writes no file and publishes nothing.

## Syntax

```
prufyx-maintainer changelog entries --component NAME --repo github.com/OWNER/NAME \
  --path FILE --form FORM --tag TAG (--mirror-state DIR | --fixture DIR)
```

- `--component`, `--repo`, `--path`, `--form` and `--tag` are all required. The
  reviewed target row of the component decides where the file is and how its
  version headings read; `--repo`, `--path` and `--form` must agree with that
  row and are refused when they do not.
- Give exactly one of `--mirror-state` (the factory mirror state directory) or
  `--fixture` (a fixture tree).
- Unknown flags, a flag given twice, a missing flag and extra arguments are
  refused.
- The tag must be recorded for the repository; the file is read at the tag's
  own commit, never at another tag or path.

## Output

One line of JSON on standard output, in a fixed field order, so equal inputs
give equal bytes:

- `schema`: `prufyx.io/changelog-entries-manifest/v1`.
- `extractor`: `name` `changelog.entries`, `version` `changelog.entries/4`,
  and `codeDigest`, the digest of this reader's source and of the extract
  framework it is built on.
- Exactly one of:
  - `entry`: the proof that the tag's own entry was read in full. It holds the
    source (repository, commit, path, file digest, form, and `checkedBytes` / `checkedDigest`: the length and sha256 of the leading part of the blob the file-wide CommonMark, fence and HTML checks covered, up to and including the heading that follows the entry, or the whole blob when nothing follows), the section (heading
    line, start and end line, digest), the headings inside it, one item per
    list item or paragraph (digest, occurrence, line span, heading path,
    marker, kind), and the line tiling. Every section line is a heading, a
    blank line, a link definition or inside exactly one item.
  - `withheld`: the typed reason the tag has no entry (`component`, `tag`,
    `tagCommit`, `code`, `detail`). `code` is the contract, from the closed list
    of the reader; `detail` is for people.

The manifest classifies nothing and gives no item a disposition.

## Exit codes

- `0`: a manifest was printed, either an `entry` or a `withheld` reason.
- `2`: the input was rejected or a read failed. Nothing is printed to standard
  output. A read failure is never turned into a reason.

## Reviewed target table

The reviewed targets are data: `internal/extract/changelogentries/targets.json`
(schema `prufyx.io/changelog-targets/v1`), embedded in the binary. The schema is
closed, so a row can never carry logic:

- the document is `{"schema", "rows"}`; unknown fields, duplicate keys and
  trailing data are refused; `rows` are sorted by component, strictly ascending;
- a row is `component` (slug), `repo` (canonical `github.com/<org>/<repo>`),
  `form`, and for the file forms: `path` (clean, relative, no `..`),
  `headingStyle` and `boundaryStyles`;
- `form` is one of `changelog-file`, `changelog-per-line-file`,
  `changelog-per-version-file`, `github-release`, `post-tag`, `docs-page`,
  `monorepo`; the other forms are not in the table;
- the two template forms take a `path` template with exactly one placeholder
  from a closed vocabulary, made of `[A-Za-z0-9._/-]` and the placeholder only
  (no glob, regular expression, shell text, space or non-ASCII). The
  placeholder shares its path element with literal text and has no digit
  beside it:

| form | placeholder | meaning | example | styles |
|---|---|---|---|---|
| `changelog-per-line-file` | `{line}` | `major.minor` of the tag | `CHANGELOG/CHANGELOG-{line}.md` | heading style and at least one boundary style, as `changelog-file` |
| `changelog-per-version-file` | `{version}` | full final version of the tag, no `v` | `docs/releases/v{version}.md` | none (the file is the entry); `headingStyle` and `boundaryStyles` are refused |

- styles are names, never regular expressions. Each name maps to a fixed
  expression compiled in code:

| kind | name | expression |
|---|---|---|
| heading | `version-slash-date` | `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| heading | `version-plain` | `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$` |
| heading | `version-v-prefixed` | `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$` |
| heading | `version-bracketed` | `^\[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\]$` |
| heading | `version-bracketed-date` | `^\[(?P<version>...)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| heading | `version-dash-date` | `^(?P<version>...) - [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| heading | `version-space-date` | `^(?P<version>...) [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| heading | `version-v-slash-date` | `^v(?P<version>...) / [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| heading | `version-linked-paren-date` | `^\[v(?P<version>...)\](GitHub tree link) \(date\)$` (the version is the link text only; a duplicate version heading is refused) |
| heading | `version-paren-date` | `^(?P<version>...) \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$` |
| heading | `version-bracketed-long-date` | `^\[(?P<version>...)\] ` then `D Month YYYY` or `Month D, YYYY` (English month names, exact case) |
| heading | `version-linked-spaced-date` | `^\[v(?P<version>...)\](GitHub tree link to release-<line>) - YYYY MM DD$`; the link must name the row repo and the `major.minor` line of the version |
| heading | `release-v-slash-date` | `^Release v(?P<version>...) - [0-9]{4}/[0-9]{2}/[0-9]{2}$` |
| boundary | `master-unreleased` | `^master / unreleased$` |
| boundary | `line-heading-v` | `^v[0-9]+\.[0-9]+$` (never names an entry) |
| boundary | `prerelease-linked-paren-date` | linked `-rc`/`-alpha`/`-beta`/`-ea` heading with a date |
| boundary | `version-in-progress` | `^[0-9]+\.[0-9]+\.[0-9]+ in progress$` (a release still being written; never names an entry) |
| boundary | `version-linked-loose-date` | a linked release heading whose link or date carries a known typo (missing `(`, a ref that is not the release line, a `dd.mm.yyyy` date); it ends a section and never names an entry |
| boundary | `unreleased` | `^Unreleased$` |
| boundary | `unreleased-bracketed` | `^\[Unreleased\]$` |
| boundary | `prerelease-plain` | `^[0-9]+\.[0-9]+\.[0-9]+-(rc\|alpha\|beta)\.[0-9]+$` |
| boundary | `prerelease-v-prefixed` | `^v[0-9]+\.[0-9]+\.[0-9]+-(rc\|alpha\|beta)\.[0-9]+$` |
| boundary | `main-unreleased` | `^main / unreleased$` |
| boundary | `main-unreleased-parenthesised` | `^main / \(unreleased\)$` |

Two more optional row fields, both closed:

- `innerHeadingStyles` (file and per-line rows only): names of same-level
  headings that stay inside the entry above them. `note-first` is `^Note$`,
  absorbed only as the first heading after the release heading with nothing
  but blank lines between; `change-sections` is `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed` or `Security`. A heading that is a release
  heading or a boundary for the row is read as that first, a heading one level
  higher is never absorbed, and any other same-level heading still ends the
  entry unproven. The list may not be empty or repeat a name.
- `minLocatedNewest` (rows that are read): the row's coverage bar for
  `rows-check`, one of 5, 6, 7, 8; absent means 8. At least that many of the
  newest 8 final versions must each have an entry read in full. It only decides
  whether a row passes the check. It never creates an entry: the reader
  withholds a version without one exactly as before, so a lower bar can never
  produce a counted pair; a pair is counted only for a to-line whose every
  final tag locates. An explicit 0, 4, 9, a string or a float is refused.

A heading naming the entry's own version in another wording, whether or not a
boundary style matches it (the exact version as a token, so `1.2.3-rc.1` is not
`1.2.3`), makes the entry ambiguous and is refused (`ENTRY_DUPLICATE`).

Adding a row is a data change; adding a style or a form is a reviewed code
change. A table that does not satisfy the schema is not loaded: every component
is then refused and no code digest is produced. `targets.json` is part of the
extractor's code digest, so any change of a row changes the identity a gate
pins.

The loader also refuses an empty table, two rows with the same component, two
rows with the same repo, a path that is `.` or a directory, and a file row
without a boundary style.

Before a new row merges as data it must show, in its review record:

- the repo is the canonical upstream repository of the component;
- the heading style matches the version heading at its exact line in the
  changelog file at a pinned tag, and an adjacent version is withheld;
- each listed boundary style is present in that file.

A component without a reviewed row is refused with exit 2. A component whose
row has a non-file form (post-tag, github-release) prints a withheld manifest
with its typed code, and nothing is read. Rows of form `changelog-file` exist
for `prometheus` and `alertmanager`: the review window's tags were read in full
and located with no residue and no withheld code. A row is reviewed input only; it attests nothing by itself.

## Checking rows

```
prufyx-maintainer changelog rows-check (--mirror-state DIR | --fixture DIR) [--component NAME]
```

Read-only and deterministic. For every row (or the one named) and every final
release tag the source records for its repository (release candidates and other
non-final tags are counted as `notFinal` and skipped), it runs the same
locate/reader as `entries` and requires an entry or a typed withheld reason.
One line per row: `PASS|FAIL|SKIP component form=... tags=N located=N
withheld=N notFinal=N newest=L/W minLocatedNewest=B CODE=n ...`
(`minLocatedNewest` is the row's own bar, 8 when it has none), failure reasons
indented below, and a final `rows=N failed=N minLocatedNewest=rows
tagsDigest=... mirrorDigest=...` line. `--min-located-newest N` replaces every
row's bar for that run and then reads it strictly: the newest N versions must
all be located (the summary prints `N` instead of `rows`). Exit 0 when no row failed, 1 when a row failed, 2 when
the input is rejected.

A row FAILS when a tag gives an error that is not a typed reason (read failure,
tag the source cannot serve), a tag is recorded twice, a tag is withheld for a
defect of the row itself (`NO_CHANGELOG_TARGET`, `SHAPE_NOT_PER_TAG`,
`SOURCE_NOT_PINNED_GIT`), no final tag is recorded, or no tag has an entry (the
path or the headings never resolve). Tags before a changelog existed may be
withheld with `PATH_MISSING_AT_TAG` and do not fail a row that otherwise
locates entries. A row of a form that is not read is `SKIP` (it claims nothing);
asked for by `--component` it FAILS. This is the check a data change of rows is
judged by, together with its gate receipt.
A `PASS` is a check of the row data (the path and headings resolve, newest tags
locate) and never a compatibility verdict about any release or upgrade. A
version recorded under two tag names (`v1.2.3` and `1.2.3`) is one slot of the
newest window, and the slot counts as located only when every tag of it is.

## Receipt line

`propose-rows` (when a row is printed) and `rows-check` (one per checked row,
after the summary line) print one canonical receipt line per row:

```
receipt/v1 step=<propose|check> component=<slug> rowDigest=<hex64> tagsDigest=<hex64|unreadable> mirrorDigest=<hex|none> codeDigest=sha256:<hex64>
```

The field order is fixed and every field is required; a consumer must refuse
any other order, a missing or repeated field, or an unknown field. The line
holds a component slug and digests only, never changelog text or headings.

- `rowDigest`: sha256 (hex) of the resolved row: compact JSON (no HTML
  escaping, no trailing newline) of the object `{"component","repo","form",
  "path","heading","boundary","maxBytes"}` in that key order, `heading` and
  `boundary` being the resolved fixed regular expressions and `boundary` an
  array (`[]` when none). A proposed row and the same row in `targets.json`
  give the same value; a test pins a real value.
- `tagsDigest`: sha256 of the sorted, newline-joined `repo@tag=commit` lines
  (the peeled tag commit is bound, so a retag changes it) of the row's
  repository. If the tag list cannot be read the command exits 2 and prints no
  receipt; a consumer must still refuse `tagsDigest=unreadable`.
- `mirrorDigest`: the full sha256 (64 hex) of the mirror index file the run
  read, or the explicit `none` when the source is a fixture. It is never
  omitted.
- `codeDigest`: the extractor code digest of the reader that ran, in the
  `sha256:<hex64>` form the other extractors use.

A receipt is printed for failed rows too: it identifies the inputs of a run, it
is not a pass attestation. The `rows-check` summary line and exit code stay the
verdict.

Strict consumer rule: parse with `ParseReceiptStrict(line, fixtureRun)` (or
`ParseReceipt` then `Admissible`). It refuses any line that is not the exact
shape above (order, fields, lower-case hex, no trailing characters), always
refuses `tagsDigest=unreadable`, and refuses `mirrorDigest=none` unless the run
is a declared fixture run. A production consumer (batcher, QA gate) must also
compare the receipt against the mirror index re-read at that time.

For one row the `propose` and `check` receipts are equal except for `step`.
The `rows-check` summary line also prints `mirrorDigest=none` for a fixture.

## Proposing rows

```
prufyx-maintainer changelog propose-rows (--mirror-state DIR | --fixture DIR) --component NAME --repo github.com/OWNER/NAME [--tags TAG,TAG]
```

Rows are not written by hand. The command tries a closed, ordered list of
candidate rows (single files, per-line and per-version path templates, each
with the closed heading styles; the boundary styles a result does not need are
dropped) over the newest 8 final tags (or `--tags`) with the same reader, and
prints the candidate with the most located entries as a `targets.json` row,
with its per-tag hit table. Inner heading styles are tried only for a candidate
that otherwise misses a version, and dropped again when they change no hit. A
candidate that locates every scored version is printed as it is; one that
locates 5 to 7 of the 8 is printed with `minLocatedNewest` set to that number
(only for the newest-8 scan, never with `--tags`); fewer is `PARTIAL_COVERAGE`. Equal scores go to the first candidate in the fixed
order. Read-only and deterministic; exit 0 row printed, 1 `NO-ROW <reason>`, 2
input rejected. The row it prints is run through the strict loader before it is
printed; `rows-check` is then the judge of a data change.

NO-ROW reasons: `NO_FINAL_TAGS`, `NO_CANDIDATE_LOCATES`, `PARTIAL_COVERAGE`, and `NON_MARKDOWN_SOURCE`
(the changelog is a known toml or yaml path; such files are never read as
markdown, and the schema and the reader refuse any path that does not end in
`.md`).

## A printed manifest is never evidence

The manifest is a derivation to be re-derived and checked, not a claim. A
printed manifest, with or without an `entry`, is not a compatibility fact, an
attestation or evidence of anything; only a gate that re-derives it from the
pinned bytes and accepts it can use it.

## Older-line floor (optional row field)

A read row may carry `floor`, the oldest release line (canonical `major.minor`) whose every final tag the row locates, joined without a gap to the newest lines. Absent means the newest 5 lines; absence is the only way to say so (an explicit empty value, `newest5`, a floor equal to or newer than the oldest of the newest 5 lines, or any non-canonical spelling is refused).

- `propose-rows ... --upstream-tags FILE` computes the floor of the chosen row. The tag set is the injected upstream list (lines `repo<TAB>40-hex object id<TAB>tag name`), never the mirror. A line joins the run only if every upstream final tag is in the mirror and is located by exactly one heading style with no residue, and the mirror holds no final tag of the line that upstream lacks. The run stops at the first failing line.
- `rows-check ... --upstream-tags FILE` re-derives the run and fails a row whose stored floor is older than the re-derived one, is not an upstream line, or has no provable run beyond the newest 5 lines. A floor row without the list fails.
- The receipt line of a floor row carries `floor`, `derivedFloor` and `windowTags` (digest over tag name plus object id of the window). Rows without a floor print exactly what they printed before.
- Caps are constants (tags 200, blobs 400, bytes). An unset byte cap refuses with `WANTS_TOO_LARGE:bytes`; it is unset until measured, so floor derivation refuses until then. Exhausted capped retries (3) give NO-ROW and no floor.
