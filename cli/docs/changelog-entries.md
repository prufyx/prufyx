# Reading changelog entries and attesting a line hop

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

The table of reviewed targets (file path, heading pattern, boundary patterns)
is part of the reader's code. A component without a reviewed row is refused
with exit 2. A component whose row has a non-file form (post-tag,
github-release) prints a withheld manifest with its typed code, and nothing is
read.
Rows of form `file` exist for `prometheus` and `alertmanager`: the review
window's tags were read in full and located with no residue and no withheld
code. A row is reviewed input only; it attests nothing by itself.

## A printed manifest is never evidence

The manifest is a derivation to be re-derived and checked, not a claim. A
printed manifest, with or without an `entry`, is not a compatibility fact, an
attestation or evidence of anything; only a gate that re-derives it from the
pinned bytes and accepts it can use it.

# Attesting one line hop

`prufyx-maintainer changelog attest` derives, for one component and one hop
from a release line to the next minor line of the same major, the line
attestation of the changelog-attested family, or prints the typed reason it
cannot. It is offline and deterministic like `entries`: it reads only the
offline mirror or a fixture tree through the pinned reader and one dispositions
file, calls no model and no network service, writes no file and publishes
nothing.

## Syntax

```
prufyx-maintainer changelog attest --component NAME --repo github.com/OWNER/NAME \
  --path FILE --form FORM --from-tag TAG --to-tag TAG --dispositions FILE \
  (--mirror-state DIR | --fixture DIR)
```

- `--component`, `--repo`, `--path` and `--form` are checked against the
  reviewed target row exactly as for `entries`. A row that is not a changelog
  file is refused: there is nothing to attest.
- `--from-tag` and `--to-tag` must be recorded for the repository. They are
  the first final release of each line (`v3.14.0` and `v3.15.0`); any other
  pair is printed as a withheld reason, never attested.
- `--dispositions` is a reviewed dispositions file of the component, read once
  and parsed strictly: an unknown field, another component, a mark that is not
  in the reviewed state or a bound violation refuses the input.
- Unknown flags, a flag given twice, a missing flag and extra arguments are
  refused.

No classifier and no pack rule is given: every item of the window must carry a
reviewed `not-operator-facing` mark. A `rule` mark has no rule to cite and
leaves its item unresolved.

## The window

The entries read are those of the from-line's patch releases (`x.y.1` and
later; the entry of `x.y.0` describes the hop into the from-line and is never
read) and of every release of the to-line. Each entry is read at its own tag's
commit, and again at the newest recorded tag to refuse an entry that was
amended afterwards. Every item of every entry must be resolved by a reviewed
mark bound to the item digest, tag and occurrence; a mark that matches no item
of its window tag is refused, never ignored.

## Output

One line of JSON on standard output:

- `schema`: `prufyx.io/changelog-attestation-manifest/v1`.
- `extractor`: `name` (`changelog.entries.` plus the component), `version` and
  `codeDigest`, the digest of the attestation code, the entry reader and the
  extract framework.
- `pair`: component, repository and the two tags with their commits.
- `dispositionsDigest`: sha256 of the dispositions file as read.
- Exactly one of:
  - `attestation`: basis, component, line, fact family, rule ids (always
    empty here), the releases of both lines, the entry sources, the family's
    scope statement and the proof (window, every entry, every item's
    disposition).
  - `withheld`: `code`, the typed reason from the closed list of the reader
    (for example `ITEM_UNRESOLVED`, `NOT_PREVIOUS_MINOR`, `ENTRY_MISSING`,
    `ENTRY_AMENDED`), and `detail` for people.

## Exit codes

- `0`: a manifest was printed, either an `attestation` or a `withheld` reason.
  A consumer must read which of the two it is.
- `2`: the input was rejected or a read failed. Nothing is printed to standard
  output.

## A printed attestation is never evidence

Like an entries manifest, a printed attestation is a derivation to be
re-derived and checked by a gate that holds the pinned bytes; it is not a
compatibility fact by itself. The family attests only that every item of the
window's changelog entries was read and carries a reviewed disposition; it says
nothing about changes the changelog does not mention.

## Reviewed dispositions of prometheus

`internal/extract/changelogattest/dispositions/prometheus.json` holds the
reviewed marks of the prometheus changelog items for the releases 3.13.1 to
3.15.1; `prometheus.review.tsv` next to it lists every item of those releases
with its line, digest, disposition and a one-line reason. An item that changes
a flag, a configuration key, an API, a default, a metric or label, a storage or
wire format, a minimum version, or that removes or deprecates anything, is
listed as `operator-facing` and has no mark, so the pair it belongs to is
withheld. The changelog text is read as data only.
