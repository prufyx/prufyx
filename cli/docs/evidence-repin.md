# Evidence repin

`prufyx-maintainer evidence repin` is a maintainer tool that checks, for every
source cited by the shipped rule packs, whether the cited upstream content has
changed since the commit the rule pinned. It is deterministic, uses no model,
reads the rule packs and public GitHub data (or a local mirror of it, see
below), and writes only a worklist (and an optional resumable state file). It never edits a rule pack or a review record,
and it never makes or alters a compatibility claim.

```sh
prufyx-maintainer evidence repin --state "$PWD/state" --output "$PWD/worklist.json"
```

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise GitHub's API rate limit; the token
is never logged or written. Re-run with the same `--state` to resume after a
rate limit.

## Sources: `--source http|mirror`

By default repin asks GitHub (`--source http`). With `--source mirror` it reads
tags, release metadata and file bytes only from a local mirror made by
`prufyx-maintainer factory mirror`, and makes no network request of any kind:

```sh
prufyx-maintainer evidence repin --source mirror --mirror-state "$PWD/mirror-state" \
  --wants-out "$PWD/wants.json" --output "$PWD/worklist.json"
```

The classification code is the same for both sources, so the same repositories,
tags and files classify identically either way. The mirror source recomputes
everything on each run (it is offline, so that is cheap) and does not use
`--state`.

What the mirror cannot answer is `PENDING`, never "unchanged". The citation's
`detail` says why:

| Situation | Result |
|---|---|
| A cited file's contents are not materialized in the mirror (the mirror never downloads on demand) or the commit is not in the mirror | `PENDING`, with a note to add the file to the mirror's wants |
| The repository has an unacknowledged alarm (a tag moved or vanished) | `PENDING` for every citation of the repository: nothing is compared against tags that may have been rewritten, until a person acknowledges the alarm with `factory ack` |
| The repository is not in the mirror | `PENDING` |
| Release metadata is unknown (the mirror had no GitHub credential), stale, or missing | `PENDING` for the repository |
| Release metadata is known but the mirror cut the list short | The newest release is still used, but no release line is derived: citations keep the latest-release baseline and `baselineNote` says the line scan is incomplete |

A repository with a complete, known, empty release list falls back to its tags
exactly as over HTTP (`tag_fallback`, never batch-attestable). With the mirror,
that fallback considers every recorded tag rather than the first page GitHub
returns.

### Getting the files into the mirror: a two-step flow

Which commit a citation is compared with (the newest release, or the newest on
its release line) is only known once the mirror has the repository's tags and
releases, so the files to materialize cannot be listed from the rule packs
alone. The flow is:

1. `factory mirror --registry ... --state DIR` (refs, tags, releases).
2. `evidence repin --source mirror --mirror-state DIR --wants-out wants.json ...`
   lists in `wants.json` every file it could not read, at both the pinned and
   the baseline commit (the file at the pinned commit of the same path is
   requested in the same round, so one more round is enough). The file has the
   shape `factory mirror --wants` reads and is deterministic. It is empty when
   nothing is missing.
3. `factory mirror --registry ... --state DIR --wants wants.json` materializes
   them.
4. Run repin again. Steps 2 to 4 are only needed for files not yet in the
   mirror; once a warm mirror holds them, repin needs no further step.

(`factory registry derive --wants-out` still lists the pinned files only,
which is all that can be known before the first mirror run.)

### Freshness comes from the mirror

A worklist built from a mirror that was last refreshed days ago must not look as
fresh as the moment it was built. For `--source mirror`:

* every repository carries `source: "mirror"`, `mirrorCheckedAt` (the mirror's
  last successful look at the repository's refs; if its last check failed, the
  time its refs last changed) and `mirrorReleasesAt` (the last successful
  revalidation of its release metadata);
* `resolvedAt` of a repository and of each release line is the older of those
  two times (never later than the run), so `summary.oldestResolvedAt` is the
  mirror's age;
* a repository, line or classified citation older than `--max-age` is marked
  `stale`;
* the worklist records `source` (also in `scope.source`) and `mirror`
  (`indexUpdatedAt`, `indexDigest`) to identify the mirror snapshot used.

`evidence reattest` applies its 72-hour freshness bound to that time: it takes
the oldest of `resolvedAt`, `mirrorCheckedAt` and `mirrorReleasesAt` of a
repository or line whose `source` is `mirror`, and treats a missing or
unparsable time, or an unknown `source`, as stale.

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

Repin also classifies the citations of a pack's line attestations and
upgrade-path policies. Their `ruleId` is the record ID (`line-attestation.…`
or `path-policy.…`, see
[evidence-reattestation.md](evidence-reattestation.md#line-attestations-and-path-policies))
and their `project` is `line-attestations` or `path-policies`. A pack whose
attestation or policy section does not parse, or whose top-level member names
are not exact, is refused.

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
* `--baseline latest` compares every citation with the repository's latest
  release under the rule below (or, for a repository with no Releases, its
  latest tag, marked `tag_fallback`).

### The "latest" rule (the same for `--source http` and `--source mirror`)

One function chooses the latest release for both sources, so the two cannot
pick different baselines from the same data:

* Drafts and pre-releases are never candidates.
* Only tags with no prefix, `v` or `go`, followed by `MAJOR.MINOR.PATCH` and
  nothing after it (a strict version), compete. The highest version wins, so
  `v1.10.0` is newer than `v1.9.0` and a backport such as `v1.7.36` published
  after `v2.4.1` does not displace it.
* The rule never guesses. A repository is **ambiguous** when strict tags carry
  a prefix other than none, `v` or `go` (a chart, SDK or API tag), or more than
  one prefix, or when its newest release (highest release id) is not a strict
  version while older strict ones exist (calendar tags such as `2025.1.0`, or
  two-part tags). Its baseline is not chosen: the repository is
  `PENDING_AMBIGUOUS_LATEST` and every citation that needs the latest baseline
  is `PENDING` with the reason in its detail, for a human to decide. In
  release-line mode a citation whose release line is proven still uses that
  line.
* When no release tag is a strict version, the release with the highest id
  wins.
* For the tags fallback only strict-version tags count, under the same
  ambiguity rule; tags such as `weekly.2012-03-27` or `release.r60.3` never do.
  A repository with no such tag has no baseline and stays `PENDING`.
* The order in which a source lists releases or tags plays no part. The whole
  release list is read once per run, in pages of 20 (at most 100 pages, that
  is the 2000 newest releases), and shared by the latest rule and the release
  lines; a list cut by that bound is marked `releaseListTruncated` on the
  repository. The whole tags list is read in pages of 100 (at most 50 pages; a
  longer list is not trusted).

The prefix rule lives in `latestrelease.AmbiguousPrefixes`
(`cli/internal/maintainer/latestrelease`); code that derives versions from tags
uses it rather than its own definition.

The rule is recorded in the worklist limitations.

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
