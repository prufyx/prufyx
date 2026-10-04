# Verifying removal claims read from release notes

`prufyx-maintainer consensus` checks a claim that an upstream release removed
something, such as "Kubernetes v1.41.0 removed the `RetiredKnob` feature
gate", against pinned upstream bytes. It is a maintainer tool: it runs
offline, reads only the factory mirror or a fixture tree, calls no model and
no network service, and publishes nothing.

A claim names only a kind and the names it is about. Everything else, the
quote, the line numbers and the pull request, is computed by this tool from
the pinned release notes, the mechanical inventories of the two releases and
the commit history between them. A claim passes only when every check
passes; anything that fails or cannot be checked leaves the claim a `lead`
(not usable as evidence, worth a human look) or `dropped` (contradicted).

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

`normalise` selects the release's own section of a release notes file,
normalises it and writes three files:

- `normalised.txt`: the normalised section;
- `linemap.json`: for every normalised line, its line in the original file and
  what was removed from it;
- `source.json`: the `source` object of a claims bundle, with the file digest
  and the normalised digest.

Whatever proposes claims must work from `normalised.txt`, and copies
`source.json` into its bundle unchanged.

```
$ prufyx-maintainer consensus normalise --fixture fixture --repo kubernetes/kubernetes \
    --commit 0000000000000000000000000000000000014100 --path CHANGELOG/CHANGELOG-1.41.md \
    --section v1.41.0 --out norm
normalised CHANGELOG/CHANGELOG-1.41.md v1.41.0: 26 lines, sha256 7e55647bb1132074d014dcca30f7aa8a1eb0f0b3a3bd6a3334dd5bca1acdd3b3
$ cat norm/source.json
{
  "commit": "0000000000000000000000000000000000014100",
  "fileSha256": "7b4720a5fe333e8d792c2503992bc5ac2860d874dcade985ef85888857b5a122",
  "normalisedSha256": "7e55647bb1132074d014dcca30f7aa8a1eb0f0b3a3bd6a3334dd5bca1acdd3b3",
  "normaliserVersion": "1",
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
| 3 | The file is not held by the mirror (see `--wants-out`). | An input is missing: the release notes, a file an inventory needs, a tag, or a commit of the range. No report is written. |
| 4 | — | Report written; at least one claim is not verified. This is a normal outcome. |

## Release sections

Only Kubernetes has a section rule today: the file must be
`CHANGELOG/CHANGELOG-1.N.md`, the release `v1.N.0`, and the section runs from
the line `# v1.N.0` to the next line starting with `# v`. The heading must
appear exactly once (outside HTML comments). Any other repository or path is
refused (`no-section-rule`).

## Normalisation

Applied in this order; every rule is deterministic and versioned
(`normaliserVersion`, currently `1`):

1. The file must be valid UTF-8, at most 2 MiB, with lines of at most 64 KiB.
2. CRLF line endings become LF.
3. Invisible characters are removed: zero-width characters and joiners
   (U+200B–U+200F), bidirectional controls (U+202A–U+202E, U+2066–U+2069),
   invisible operators (U+2060–U+2065), the byte order mark (U+FEFF), the
   soft hyphen, line and paragraph separators, variation selectors, tag
   characters and blank fillers. C0 and C1 control characters other than tab
   are removed, including NUL and a carriage return that is not part of CRLF.
4. HTML comments are removed, also across lines. An unterminated comment
   removes everything after its start.
5. The release's section is selected.
6. Fenced code blocks (```` ``` ```` or `~~~`) are emptied with their fences;
   an unterminated block empties everything after it.
7. Link reference definitions are emptied; images (`![alt](url)`, alt text
   included) are removed; autolinks `<https://...>` keep their URL; raw HTML
   tags are removed outside inline code spans.

Lines are never joined or split, so normalised line N maps to exactly one
original line. Every line records what was removed from it. Comments, raw
HTML, invisible characters and control characters are hidden content: they
can make a page show something other than its bytes, and a claim is never
verified from a list item that held any of them.

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
| 1 | The file digest matches the bytes at the commit, the normalised digest is recomputed equal with the same normaliser version, the section is `toRelease`, `fromRelease` is the previous minor and its tag points at the given commit. | `dropped`: `source-mismatch`, `source-refused` or `release-mismatch` |
| 2 | The kind is `removed_feature_gate` or `removed_api_version` of Kubernetes. | `lead`: `kind-not-allowed` |
| 3 | Every name has the kind's form: a feature gate `[A-Z][A-Za-z0-9]{2,60}`; an API version `group/version` such as `apps.example.io/v1beta1` or `batch/v2alpha1`. | `dropped`: `name-invalid` |
| 4 | Every name occurs, as a whole token, in a list item of the section that contains a removal cue; all such items are identical copies; none held hidden content. | `dropped`: `no-cited-cue`; `lead`: `ambiguous-citation`, `hidden-content` |
| 5 | Every name is in the complete inventory of the earlier release (feature gates the release declares; group/versions its OpenAPI specification declares a kind for). | `lead`: `inventory-incomplete`; `dropped`: `not-in-inventory` |
| 6 | No name is in the complete inventory of the later release (every feature gate name its source spells; the served group/versions). | `lead`: `inventory-incomplete`; `dropped`: `still-present` |
| 7 | The cited item references at least one pull request of the same repository (`#N`, a link to `https://github.com/<repo>/pull/N`, or that URL), and every such number appears as `(#N)` or `Merge pull request #N from` in the subject of a commit reachable from the later release's tag and not from the earlier one. | `lead`: `no-provenance`, `provenance-unbounded`, `provenance-unavailable` |

A list item is a line starting with `-`, `*`, `+` or `N.`/`N)` and the
non-empty lines after it that are neither list items nor headings; a nested
item is its own item. Names and cues are matched in the item's text with
link targets and URLs removed. A link to another repository's pull request,
`owner/name#N`, and the text of any non-pull-request link are not references.
When a link's text names a different number than its target, there is no
provenance.

The removal cue list (`cueVersion` 1) is: `remov`, `dropp`, `delet`,
`no longer`, `gone`, `purg` (case-insensitive).

The commit walk is bounded to 50,000 commits per range. The mirror holds
commit objects even where it holds no file contents, so the walk is offline.

What the checks prove: the pinned release notes visibly say the name was
removed in a list item tied to merged pull requests of the release, and the
releases' own source agrees that the name existed before and is gone after.
They do not prove that the pull request is the one that removed the name.

## Report

Schema `prufyx.io/consensus-report/v1`, canonical JSON (keys sorted, two-space
indentation): the bundle's source, the releases as resolved, the normaliser
and cue versions, the commit walk bound, a summary, and per claim its verdict,
reason and detail, its citations (normalised and original line ranges, the
full item text as the quote, the number of identical copies), the digests of
the two inventories, and each pull request with the commit that carries it.

## Fixture layout

A fixture tree has the layout of `extract --fixture`, plus an optional commit
graph for the walk:

```
<root>/github.com/<owner>/<name>/tags.json            {"v1.41.0": "<commit>", ...}
<root>/github.com/<owner>/<name>/commits/<commit>/... the tree at that commit
<root>/github.com/<owner>/<name>/history.json         {"commits": [{"commit": "...", "parents": ["..."], "subject": "..."}]}
```

Without `history.json`, every claim that reaches step 7 is
`provenance-unavailable`.

## The knowledge gate

For a changed rule with basis `consensus`, the gate looks for a claims bundle
at `cli/knowledge/consensus-claims/<pack>/<rule id>.json` in the proposed
change, runs `verify` against the gate's own upstream source, and adds the
counts and per-claim verdicts to the change in the gate report (`consensus`)
and to its detail line. The change is refused exactly as before. With
`--source github` there is no commit history, so claims stop at
`provenance-unavailable`; with `--source fixture:DIR` the fixture's
`history.json` is used.

## Test corpus

`cli/internal/consensus/testdata/injection/` holds a synthetic corpus written
for this tool (no upstream text): release notes that try to get a false or
hidden claim verified (hidden comments, breakout text, phantom names, fake or
foreign pull requests, invisible and bidirectional characters, look-alike
letters, link reference definitions, image alt text, code blocks, other
releases' sections, nested lists, duplicated items, over-long lines, mixed
line endings, and more), each expected to verify nothing, and real-shaped
removals that must verify.
