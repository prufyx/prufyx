# Verifying removal claims read from release notes

`prufyx-maintainer consensus` checks a claim that an upstream release removed
something, such as "Kubernetes v1.41.0 removed the `RetiredKnob` feature
gate", against pinned upstream bytes. It is a maintainer tool: it runs
offline, reads only the factory mirror or a fixture tree, calls no model and
no network service, and publishes nothing.

A claim names only a kind and the names it is about. Everything else, the
quote, the line numbers and the pull request, is computed by this tool from
the release's own release notes, the mechanical inventories of the two
releases and the commit history between them. A claim passes only when every
check passes; anything that fails or cannot be checked leaves the claim a
`lead` (not usable as evidence, worth a human look) or `dropped`
(contradicted).

The knowledge gate re-runs the same verifier, built from the base branch, on
any consensus rule a change adds, and reports the verdict. It still does not
admit consensus rules: the verdict is information for reviewers only.

## Commands

```
prufyx-maintainer consensus normalise (--mirror-state DIR | --fixture DIR) --repo R --commit SHA --path P --section VERSION --out DIR [--wants-out FILE]
prufyx-maintainer consensus verify --claims FILE (--mirror-state DIR | --fixture DIR) --out FILE [--wants-out FILE]
```

| Flag | Meaning |
| --- | --- |
| `--mirror-state DIR` | The factory mirror's state directory. Read strictly offline. |
| `--fixture DIR` | A fixture tree instead of the mirror (layout below). Give exactly one of the two. |
| `--repo R` | Repository, `owner/name` or `github.com/owner/name`. |
| `--commit SHA` | Full 40-character commit of the release notes file. |
| `--path P` | Release notes path at that commit. |
| `--section VERSION` | The release whose section is selected, for example `v1.41.0`. |
| `--out` | `normalise`: output directory (created if missing). `verify`: report file. Written atomically. |
| `--claims FILE` | The claims bundle to verify (at most 1 MiB). |
| `--wants-out FILE` | When files are missing from the mirror, write them here in the form `factory mirror --wants` reads. |

### normalise

`normalise` selects the release's citable subsections of a release notes
file, checks every line against the line grammar and writes three files:

- `normalised.txt`: the selected subsections;
- `linemap.json`: for every normalised line, its line in the original file,
  the characters removed from it, and why it is outside the grammar, if it
  is; and the list of such problems;
- `source.json`: the `source` object of a claims bundle, with the file digest
  and the normalised digest.

Whatever proposes claims must work from `normalised.txt`, and copies
`source.json` into its bundle unchanged.

```
$ prufyx-maintainer consensus normalise --fixture fixture --repo kubernetes/kubernetes \
    --commit 0000000000000000000000000000000000014100 --path CHANGELOG/CHANGELOG-1.41.md \
    --section v1.41.0 --out norm
normalised CHANGELOG/CHANGELOG-1.41.md v1.41.0: 20 lines, 0 outside the line grammar, sha256 02304dcf9c476e029b30f8d03bbd0e0023310c7a44042d13d9065799343fa5e2
$ cat norm/source.json
{
  "commit": "0000000000000000000000000000000000014100",
  "fileSha256": "7b4720a5fe333e8d792c2503992bc5ac2860d874dcade985ef85888857b5a122",
  "normalisedSha256": "02304dcf9c476e029b30f8d03bbd0e0023310c7a44042d13d9065799343fa5e2",
  "normaliserVersion": "3",
  "path": "CHANGELOG/CHANGELOG-1.41.md",
  "repo": "github.com/kubernetes/kubernetes",
  "section": "v1.41.0"
}
```

### verify

`verify` checks every claim of a bundle and writes a report.

```
$ prufyx-maintainer consensus verify --claims claims.json --fixture fixture --out report.json
1 verified, 0 lead, 1 dropped
$ echo $?
4
```

### Exit codes

| Code | `normalise` | `verify` |
| --- | --- | --- |
| 0 | Files written. | Report written; every claim verified. |
| 2 | Misuse, or the file or section was refused. | Misuse, or the bundle was refused. |
| 3 | The file is not held by the mirror (see `--wants-out`). | An input is missing: the release notes, a file an inventory needs, a tag, or a commit. No report is written. |
| 4 | — | Report written; at least one claim is not verified. This is a normal outcome. |

## Release sections

Only Kubernetes has a section rule today. The file must be
`CHANGELOG/CHANGELOG-1.N.md` and the release `v1.N.0`. The release's section
starts at the line `# v1.N.0`, which must appear exactly once, and ends at the
next level-1 heading at column 0. Inside it, only the subsections
`## Urgent Upgrade Notes` and `## Changes by Kind` are read (each heading
matched exactly, at most once, at least one present); each ends at the next
heading of level 1 or 2 at column 0. Download tables, dependency lists, known
issues and anything else in the section are not read for citations. Any
other repository or path is refused (`no-section-rule`).

## The line grammar

Nothing in the selected subsections is rewritten or stripped. Instead every
line must be inside a small, strict grammar (`normaliserVersion` 3):

- blank lines;
- ATX headings of level 3 to 6, starting at column 0 (`### Feature`);
- list items `- ` or `* ` with their text exactly one space after the
  marker; a top-level item at column 0 and a child exactly two columns right
  of its parent, at most 4 levels deep;
- continuation lines of an open item, indented by at most five columns more
  than the item's marker (never deep enough to be code);
- paragraph lines starting at column 0.

Inside a line, outside inline code spans: plain text, emphasis, character
references, and inline links without a title whose target is a pull request
or issue of the repository (`https://github.com/kubernetes/kubernetes/pull/N`
or `/issues/N`), a contributor's profile written as
`[@login](https://github.com/login)`, anything under the project's GitHub
organisations (`https://github.com/kubernetes*/...`, which includes
`kubernetes-sigs`), or a page on `kubernetes.io`, `k8s.io`, `docs.k8s.io` or
`pkg.go.dev`. Code spans never pair across lines: a backtick run without a
matching run on its line, or a backtick escaped with a backslash, is a
problem. Link text is never read as a citation, and only an exact pull
request link of the repository counts as provenance.

Anything else is a problem, among them: raw HTML of any kind (`<` followed by
a letter, `!`, `?` or `/`, which includes comments, CDATA, processing
instructions and autolinks), the comment marker `-->`, images (`![`), link
reference definitions, footnotes, reference-style links, links with a title
or to any other target, fenced code, indented code, block quotes, ordered
lists, `+` list markers, setext underlines and thematic breaks, tables (`|`),
strikethrough (`~`), tabs, and badly indented items or headings (a `#` line
inside a list item included). A block construct (fenced code, an HTML block
or comment) left open when a heading is reached is a problem at that
heading.

Some things can hide later text when the page renders, whatever section they
are in. They are barriers: no citation at or after one verifies (`lead`,
`unparsed-section`). They are raw HTML anywhere in the release section, read
subsections or not (an HTML element such as `<details>` stays open in the
browser across blank lines and headings); a line inside an HTML block or
comment; a level-1 or level-2 heading indented by one to three spaces (what
follows renders under another heading than the one read); the release
heading inside an HTML block, comment or fenced code; and an HTML element
GitHub keeps (`details`, `div`, `span`, `a`, `p` and the like) left open
anywhere before the release heading.

Problems are scoped to heading sections. A heading section runs from a
heading to the next heading of the same or a higher level, its child
sections included. When any line of a heading section is a problem:

- no item in it is cited;
- every claim whose name appears anywhere in it is `lead` (`unparsed-section`),
  even when another, clean section also cites the name.

Names are matched after character references are decoded (`&#68;` is `D`),
so a name spelled with references elsewhere still counts against the
citation; the cited item itself must spell the name literally, or the claim
is `lead` (`hidden-content`).

Characters that render as nothing or reorder text are removed and the line is
flagged: zero-width characters and joiners (U+200B–U+200F), bidirectional
controls (U+202A–U+202E, U+2066–U+2069), invisible operators (U+2060–U+2065),
the byte order mark, the soft hyphen, line and paragraph separators,
variation selectors, tag characters and blank fillers, and C0 and C1 control
characters other than tab (including NUL and a carriage return that is not
part of CRLF). CRLF line endings become LF. A cited item with a flagged line
is `lead` (`hidden-content`).

The file must be valid UTF-8, at most 2 MiB, with lines of at most 64 KiB.

Unicode normalisation (NFC) is not applied. Instead, names must be ASCII
(see the kinds below) and a name only matches where the characters around it
are not letters, digits or combining marks, so a decomposed or look-alike
spelling never matches.

## Claims bundle

Schema `prufyx.io/consensus-claims/v1`, strict JSON: no repeated or
case-variant members, no members other than these.

```json
{
  "schema": "prufyx.io/consensus-claims/v1",
  "source": { "...": "the contents of source.json" },
  "fromRelease": {
    "repo": "github.com/kubernetes/kubernetes",
    "commit": "0000000000000000000000000000000000014000",
    "tag": "v1.40.0"
  },
  "toRelease": { "tag": "v1.41.0" },
  "claims": [
    { "id": "gate-1", "kind": "removed_feature_gate", "names": ["RetiredKnob"] }
  ]
}
```

`fromRelease` is the minor release just before `toRelease`, pinned by the
commit its tag points at. A claim has an `id` (`[a-z0-9][a-z0-9._-]{0,63}`,
unique), a `kind`, an optional `component` and 1–16 `names`. A bundle holds
1–500 claims. There is no field for a quote, a line or any text.

## Checks

For each claim, in order; the first failure decides:

| Step | Check | On failure |
| --- | --- | --- |
| 1 | The releases match the section rule and the source's recorded tags (`fromRelease` is the previous minor and its tag points at the given commit). The release notes are read at the commit of a recorded `v1.N.P` tag of the later release's line, or at a commit that descends from the `v1.N.0` tag commit and is reachable from the `release-1.N` branch head; a source without commit history accepts tag commits only. The file digest matches the bytes, and the normalised digest is recomputed equal with the same normaliser version. | `dropped`: `release-mismatch`, `source-unbound`, `source-mismatch` or `source-refused` |
| 2 | The kind is `removed_feature_gate` or `removed_api_version` of Kubernetes. | `lead`: `kind-not-allowed` |
| 3 | Every name has the kind's form: a feature gate `[A-Z][A-Za-z0-9]{2,60}`; an API version `group/version` such as `apps.example.io/v1beta1` or `batch/v2alpha1`. | `dropped`: `name-invalid` |
| 4 | No name appears in a heading section outside the line grammar. Every name occurs, as a whole token, in a list item that contains a removal cue; all such items are identical copies; the name appears nowhere else in the read subsections; no copy held hidden content and the cited item spells the name literally; no barrier precedes the item; the cited item has no negated, future or undone cue. | `lead`: `unparsed-section`, `ambiguous-citation`, `hidden-content`, `hedged-cue`; `dropped`: `no-cited-cue` |
| 5 | Every name is in the complete inventory of the earlier release (feature gates the release declares; group/versions its OpenAPI specification declares a kind for). | `lead`: `inventory-incomplete`; `dropped`: `not-in-inventory` |
| 6 | No name is in the complete inventory of the later release (every feature gate name its source spells; the served group/versions). | `lead`: `inventory-incomplete`; `dropped`: `still-present` |
| 7 | The cited item links to at least one pull request of the same repository, and every such pull request appears as `(#N)` or `Merge pull request #N from` in the subject of a commit reachable from the later release's tag and not from the earlier one. | `lead`: `no-provenance`, `provenance-unbounded`, `provenance-unavailable` |

A list item is a line starting with `- ` or `* ` and the non-empty lines after
it that are neither list items nor headings; a nested item is its own item.
Names and cues are matched in the item's text with link targets and URLs
removed.

Only inline link targets count as pull request references, and only outside
code spans, when the target is exactly `https://github.com/<repo>/pull/N` and
the link text is exactly `#N`. A bare `#N`, a bare URL, a link title, an
issue, a link to another repository or host, or `owner/name#N` is never a
reference. When a pull request link's text is not exactly `#N`, there is no
provenance.

The removal cue list (`cueVersion` 2) is `remov`, `dropp`, `delet`,
`no longer`, `gone`, `purg` (case-insensitive). A cited item is `hedged-cue`
when a cue is negated (`not removed`, `never deleted`, `isn't removed`), in
the future (`will be removed`, `to be removed`, `may be dropped`,
`scheduled for removal`) or undone (`reverted`, `restored`, `re-added`,
`reintroduced`).

## What the checks prove, and what they do not

When a claim verifies, the release's own notes show the name, visibly and
unambiguously, in a removal item that links to merged pull requests of the
release, and the releases' own source agrees that the name existed before and
is gone after. The checks do not prove:

- that a linked pull request is the one that removed the name: any merged
  pull request of the release satisfies step 7;
- that the item means what its cue says beyond the hedge list: a negation or
  condition worded another way ("removal is not planned", "only on Windows")
  is not recognised.

- that nothing outside the read subsections contradicts the item: a note
  under "Known Issues", say, that the removal was reverted, is not read;
- that the mirror's branches are upstream's: the release-branch check of step
  1 trusts the mirror to be an honest copy of the upstream repository (it
  fetches the upstream branch heads as they are).

All are bounded by step 6: a verified name is always one the later
release's complete inventory no longer has.

## Bounds

- Release notes: 2 MiB per file, 64 KiB per line; claims bundle: 1 MiB, at
  most 500 claims of at most 16 names.
- Commit walk: at most 50,000 commits per release range; more is
  `provenance-unbounded`.
- `Verify` checks its context between claims and stops when it ends.
- The knowledge gate verifies at most 20 claims bundles per run (further ones
  are reported as not run), gives all bundles of a run one budget of ten
  minutes together (every upstream read honours it), and shares one
  inventory cache between them.

## Report

Schema `prufyx.io/consensus-report/v1`, canonical JSON (keys sorted, two-space
indentation): the bundle's source, the releases as resolved, the normaliser
and cue versions, the commit walk bound, a summary, and per claim its verdict,
reason and detail, its citations (normalised and original line ranges, the
full item text as the quote, the number of identical copies), the digests of
the two inventories, and each pull request with the commit that carries it.

## Mirror isolation

The commit walk runs git against the mirror repository named explicitly
(`--git-dir`), with no system or global configuration, every transport,
lazy fetching and replace objects disabled, hooks and the file system monitor
off, signatures never checked (both by option and by configuration), and
repository discovery bounded by `GIT_CEILING_DIRECTORIES`.

## Fixture layout

A fixture tree has the layout of `extract --fixture`, plus an optional commit
graph for the walk and the source check:

```
<root>/github.com/<owner>/<name>/tags.json            {"v1.41.0": "<commit>", ...}
<root>/github.com/<owner>/<name>/commits/<commit>/... the tree at that commit
<root>/github.com/<owner>/<name>/history.json         {"commits": [{"commit": "...", "parents": ["..."], "subject": "..."}],
                                                        "branches": {"release-1.41": "<commit>"}}
```

Without `history.json`, release notes must be read at a tag commit, and every
claim that reaches step 7 is `provenance-unavailable`.

## The knowledge gate

For a changed rule with basis `consensus`, the gate looks for a claims bundle
at `cli/knowledge/consensus-claims/<pack>/<rule id>.json` in the proposed
change, runs `verify` against the gate's own upstream source, and adds the
counts and per-claim verdicts to the change in the gate report (`consensus`)
and to its detail line. The change is refused exactly as before. With
`--source github` there is no commit history: release notes must be read at a
tag commit, and claims stop at `provenance-unavailable`. With
`--source fixture:DIR` the fixture's `history.json` is used.

## Test corpus

`cli/internal/consensus/testdata/injection/` holds a synthetic corpus written
for this tool (no upstream text): release notes that try to get a false or
hidden claim verified (hidden comments, breakout text, phantom names, fake or
foreign pull requests, invisible and bidirectional characters, look-alike
letters, link reference definitions, image alt text, code blocks, other
releases' sections, nested lists, duplicated items, over-long lines, mixed
line endings, release notes at a commit outside the release, and more), each
expected to verify nothing, and real-shaped removals that must verify. Further
regression tests cover multi-line HTML, HTML blocks, processing instructions,
CDATA, indented code, link titles, comment markers in code spans and fences,
and section boundaries.
