# Evidence repin

`prufyx-maintainer evidence repin` is a maintainer tool that checks, for every
source cited by the shipped rule packs, whether the cited upstream content has
changed since the commit the rule pinned. It is deterministic, uses no model,
reads the rule packs and public GitHub data, and writes only a worklist (and an
optional resumable state file). It never edits a rule pack or a review record,
and it never makes or alters a compatibility claim.

```sh
prufyx-maintainer evidence repin --state "$PWD/state" --output "$PWD/worklist.json"
```

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise GitHub's API rate limit; the token
is never logged or written. Re-run with the same `--state` to resume after a
rate limit.

## Classes

Each citation is compared against a baseline commit (see below) and gets one
class:

| Class | Meaning |
|---|---|
| `NO_NEW_RELEASE` | The baseline commit is the citation's own pinned commit. |
| `FILE_IDENTICAL` | The whole file at the baseline commit is byte-identical to the recorded `contentDigest` (a whole-file sha256). |
| `SPAN_IDENTICAL` | The file changed, but the cited lines are byte-identical at the same line range. |
| `SPAN_MOVED` | The cited bytes appear at a different line range. |
| `CONTENT_CHANGED` | The path exists and the cited bytes are gone. |
| `PATH_GONE` | The path does not exist at the baseline commit. |
| `CORPUS_DIGEST_MISMATCH` | The file at the citation's own pinned commit does not hash to the recorded `contentDigest`; an integrity finding, not drift. |
| `NO_RELEASE_BASELINE` | Terminal: the citation's repository definitively publishes no GitHub Releases and no tags (typically a website or docs repository), so there is nothing to compare against. See below. |
| `PENDING` | Not resolved this run (rate limit, transport error, unresolved baseline); retried on the next run. |

Only `NO_NEW_RELEASE`, `FILE_IDENTICAL` and `SPAN_IDENTICAL` can make a rule
eligible for batch renewal (see [evidence-reattestation.md](evidence-reattestation.md)).
The other classes need a human reviewer.

### `NO_RELEASE_BASELINE` versus `PENDING`

`PENDING` means the answer is not known yet and a later run can supply it;
it blocks batch renewal of the whole pack. `NO_RELEASE_BASELINE` means the
answer is known and is "there is no release or tag to compare against". It is
recorded only when, for that repository, the Releases list request and the
tags list request (the fallback described under Baselines) each returned a
success status with a JSON array holding no entry. The first page of either
list is conclusive, so an empty first page is an empty list. Anything else
stays `PENDING`: a 404, a rate limit (403 or 429), any other error status, a
transport error, a body that is not a JSON array, a Releases list holding only
drafts and pre-releases, or a tag that exists but does not resolve to a commit.

The repository's resolution in the worklist's `repos` list then has status
`NO_RELEASES_OR_TAGS` and a `determination` object
(`{"releasesListEmpty": true, "tagsListEmpty": true}`), and each of its
citations carries class `NO_RELEASE_BASELINE` with a `detail` stating how it
was determined. The class is never resumed from the state file: it is derived
from the repository's current resolution on every run, so a repository that
later publishes a release is compared against it. It counts as classified (not
pending) in the summary, so it also counts in the denominator of
`batchAttestableFraction`. It is never batch-attestable: the rules that cite
it need individual review or expire.

## Baselines: `--baseline release-line|latest`

Many rules describe a fixed historical version pair (for example `1.24` to
`1.25`) and cite files at a tag of that release line. Comparing such a citation
with the repository's newest release, which is usually on a different line,
reports "changed" for changes that do not bear on the pair. The relevant
question for a pinned pair is whether the cited content changed in later
releases of the same line (patch releases and errata).

* `--baseline release-line` (the default) compares a citation with the newest
  GitHub Release on the release line of its pinned tag when that line can be
  proven, and with the repository's most recent release otherwise.
* `--baseline latest` compares every citation with the repository's most recent
  non-draft, non-pre-release GitHub Release (or, for a repository with no
  Releases, its highest tag, marked `tag_fallback`). This is the original
  behaviour.

### Why release-line is the default, and what it does not cover

A release-line comparison is not strictly "never weaker" than a latest
comparison: a change on a newer release line is not visible to it. That is
intended, because a rule bound to a fixed pair makes a claim about those
versions only. The default is safe for such rules because the line baseline
is only used when it is proven, every use is recorded, and a batch renewal
that relies on it carries extra checks. Use `--baseline latest` when you want
to see every change to a cited file on any line, for example when reviewing a
rule whose claim is meant to hold for "this version and later". The worklist
records the requested mode (`scope.baseline`) and each citation records the
baseline it actually used, so the two kinds of result are never confused.

### How the line is derived

1. **Pinned tag.** The line comes from the citation's pinned commit, never
   from a name. Version-looking tokens in the source id, rule id and rule
   subject only suggest candidate release tags. A candidate is accepted only
   when that tag, among the repository's published GitHub Releases, resolves
   to exactly the citation's pinned commit. A wrong hint can only cause a
   missed derivation.
2. **Strict tag grammar.** The pinned tag must be a conservative prefix
   followed by exactly `MAJOR.MINOR.PATCH`: no prefix, `v`, or word segments
   ending in `-`, `_` or `/` optionally followed by `v` (for example
   `release-1.2.3`, `release-v1.2.3`, `api/v1.2.3`, `knative-v1.23.0`). Pre-release
   or build suffixes, four components, zero-padded numbers, calendar-style
   versions and anything else do not derive a line.
3. **Line members.** The line is `MAJOR.MINOR` under the pinned tag's exact
   prefix. Its newest release is the highest patch among non-draft,
   non-pre-release GitHub Releases with that prefix and line, found by
   scanning the repository's complete Releases list.
4. **Ambiguity falls back.** The citation keeps the latest baseline when the
   pinned commit has no proven release tag, when the repository publishes no
   Releases (tags-only repositories are never given a line), when the Releases
   list is too long to scan completely, when the pinned tag is not a published
   release, when the same numeric line is released under more than one prefix,
   or when any release on the line has a tag the strict grammar rejects.
   If the scan is cut short by a rate limit or an error, the citation stays
   `PENDING` rather than falling back silently.

### What the worklist records

The worklist schema is `prufyx.io/evidence-repin-worklist/v2` (the earlier `v1`
shape had no baseline fields and is still accepted by `evidence reattest`,
which treats every `v1` citation as a latest-release comparison). Each citation
carries:

| Field | Meaning |
|---|---|
| `baselineMode` | The requested mode, `release-line` or `latest`. |
| `baseline` | The baseline actually used, `release_line` or `latest`. |
| `baselineTag` | The release tag whose commit was compared (`newCommit`). |
| `baselineLine` | The `MAJOR.MINOR` line, for `release_line`. |
| `pinnedTag` | The release tag proven to point at `oldCommit`, for `release_line`. |
| `lineStatus` | For `release_line`: `pinned_is_latest` when the pinned tag is itself the newest release of its line (the line can no longer change, so the comparison is trivially unchanged), otherwise `later_releases_on_line`. Recorded for downstream policy; eligibility does not depend on it. |
| `baselineNote` | Why a release-line request used `latest` instead. |
| `observedDigest`, `observedSize` | For `CORPUS_DIGEST_MISMATCH` only: the digest and byte size of the file actually served at the citation's own pinned commit. |

The top-level `lines` list holds one resolution per release line a baseline
relies on (`owner`, `repo`, `prefix`, `line`, `tag`, `commit`, `resolvedAt`),
and `summary.baselineDistribution` counts citations by baseline. The state
file schema is `prufyx.io/evidence-repin-state/v2`; a `v1` state keeps its
repository resolutions and recomputes citation results.

### Limits to keep in mind

* Corrections published only on later release lines are not seen in
  release-line mode. This matters most for `pinned_is_latest` citations: the
  line is closed, so the result stays unchanged even if a later line corrects
  the cited content. Use `--baseline latest` to see such changes.

* A line baseline compares the pinned commit with the line's newest release
  only; a change made and reverted between two releases of the line is not
  visible, exactly as with the latest baseline.
* Pinned tags and lines are only as good as the repository's tag naming. A
  monorepo that tags independent modules under different prefixes on the same
  numeric line is treated as ambiguous and falls back.
* The unit of comparison is still the cited file at a whole-repository commit;
  a change released only under a different tag prefix is not seen.
