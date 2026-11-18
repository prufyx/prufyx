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
- `extractor`: `name` `changelog.entries`, `version` `changelog.entries/1`,
  and `codeDigest`, the digest of this reader's source and of the extract
  framework it is built on.
- Exactly one of:
  - `entry`: the proof that the tag's own entry was read in full. It holds the
    source (repository, commit, path, file digest, form), the section (heading
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
  `form`, and for form `changelog-file` only: `path` (clean, relative, no `..`),
  `headingStyle` and `boundaryStyles`;
- `form` is one of `changelog-file`, `github-release`, `post-tag`, `docs-page`,
  `monorepo`; the other forms are not in the table;
- styles are names, never regular expressions. Each name maps to a fixed
  expression compiled in code:

| kind | name | expression |
|---|---|---|
| heading | `version-slash-date` | `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| boundary | `main-unreleased` | `^main / unreleased$` |
| boundary | `main-unreleased-parenthesised` | `^main / \(unreleased\)$` |

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

## A printed manifest is never evidence

The manifest is a derivation to be re-derived and checked, not a claim. A
printed manifest, with or without an `entry`, is not a compatibility fact, an
attestation or evidence of anything; only a gate that re-derives it from the
pinned bytes and accepts it can use it.
