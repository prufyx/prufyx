# Public project onboarding

Use this workflow to turn a public GitHub project's recent release metadata or
an explicit set of Git tags, plus commit-pinned changelog bytes, into a private
snapshot for maintainer review.
It is a source-observation workflow: a successful sync does not create a rule,
assert compatibility, or publish a project.

## Build the local runner

Run these commands from a shell with Go 1.26.8. Replace the two path values;
keep `PRIVATE` outside the checkout and any shared or public directory.

```sh
set -eu
umask 077
COMMUNITY_ROOT=/path/to/prufyx
PRIVATE=/path/to/private/prufyx-project
test "$(go env GOVERSION)" = go1.26.8
mkdir -m 700 -p "$PRIVATE/bin" "$PRIVATE/corpus"
(cd "$COMMUNITY_ROOT/cli" && \
  CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off \
  GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false \
  -o "$PRIVATE/bin/prufyx-maintainer" ./cmd/prufyx-maintainer)
export PATH="$PRIVATE/bin:$PATH"
cd "$PRIVATE"
```

The build uses the checked-in `cli/vendor` tree and does not download Go
modules. `init` writes a new private request file; `sync` creates a new
`corpus/snapshot-<sha256>` directory. Keep the request, snapshots, receipts,
and object files under the private directory.

## Create a request without network access

The smallest request is:

```sh
prufyx-maintainer project init \
  --repository https://github.com/OWNER/REPOSITORY \
  --release-limit 5 \
  --output "$PRIVATE/project-request.json"
```

`--repository` must be the exact canonical HTTPS form with two GitHub path
segments. `init` rejects credentials, ports, query strings, fragments, encoded
characters, `.git`, repeated slashes, dot segments, and non-canonical names.
It creates the closed `prufyx.io/public-project-onboarding-request/v1` object
with `review.state=NOT_REVIEWED` and `review.admissionState=NOT_ADMITTED`.

The bounded selectors are:

```text
--slug SLUG
--release-limit 1..10             (default 5)
--tag-prefix PREFIX               (optional, may end in /)
--changelog-paths PATH,...        (replaces the default candidate paths)
--license-disposition NOT_REVIEWED|DECLARED_UNKNOWN
```

## Explicit Git-tag observations

Repositories that intentionally publish no GitHub Releases can be captured with
an explicit selection. This writes the separate closed request v2 schema; it
does not list tags, infer a latest version, or claim that caller order is
chronology.

```sh
prufyx-maintainer project init \
  --repository https://github.com/OWNER/REPOSITORY \
  --exact-tag v1.2.3 --exact-tag v1.2.2 \
  --license-anchor-tag v1.2.3 \
  --output "$PRIVATE/project-tags-request.json"
```

Supply one through ten unique `--exact-tag` values in the order intended for
this capture. The anchor must be one of them. Exact-tag mode rejects
`--release-limit` and `--tag-prefix`; sync resolves only the named tag refs
(and at most one annotated-tag object per ref), never the Releases or tag-list
endpoints. Its v2 receipt and proposal remain `NOT_REVIEWED` and
`NOT_ADMITTED`; a tag observation is not signature authority, support,
admission, or an executable compatibility conclusion. `inspect --include-notes`
is unavailable for v2 because no release body is captured.

Without `--changelog-paths`, the candidate paths are `CHANGELOG.md`,
`CHANGES.md`, `CHANGES`, `RELEASES.md`, and `docs/CHANGELOG.md`. A path is a
repository-relative candidate; it is not fetched until `sync`. The optional
license disposition records a declaration for review and is not a legal or
license determination.

Example request files are available at
`examples/project-onboarding/mariadb-operator-request.json`,
`examples/project-onboarding/datadog-operator-request.json`, and
`examples/project-onboarding/victoriametrics-operator-request.json`.

## Sync one bounded public snapshot

`sync` is the only network operation:

```sh
prufyx-maintainer project sync \
  --manifest "$PRIVATE/project-request.json" \
  --output-parent "$PRIVATE/corpus"
```

It contacts only the public GitHub API and `raw.githubusercontent.com`, then
writes a new immutable snapshot below `corpus`. The normal request shape for a
five-release window is one repository lookup, one first-page release listing,
and up to five tag-reference lookups: seven API requests. Annotated tags may
add one tag-object lookup per selected release. Candidate changelog paths and
the bounded built-in license filename probe use raw-content requests. With ten
releases, eight changelog paths, ten annotated tags, and no matching file until
the last probe, the release route reaches the 108-request cap. The explicit-tag
route does not list releases and needs at most 107 requests. No token, cookie,
proxy, redirect, custom endpoint, or source checkout is used.

The release listing is page 1 with at most 30 candidates. It selects up to the
requested limit of published, non-draft, non-prerelease releases with valid
tags. This is a recent bounded window, not a latest-version assertion or a
full-history crawl. In release mode, a repository with no eligible published
GitHub Releases returns `NO_ELIGIBLE_RELEASES`. The separate v2 exact-tag mode
observes only the tags explicitly named by the operator; it does not discover,
order, or infer tags.

The retained first-page release-list response is bounded at 4 MiB. Other
GitHub API responses remain bounded at 1 MiB; JSON depth, JSON node count,
aggregate bytes, and request limits are unchanged. The snapshot window stays
the same first 30 candidates. Older CLI versions may reject a newly retained
snapshot whose release-list object is larger than their 1 MiB API bound.

Unauthenticated GitHub API requests share an IP-based limit of 60 requests per
hour. The CLI reports `GITHUB_RATE_LIMITED` when GitHub returns a rate-limit
response. Other bounded failures are reported as
`REPOSITORY_UNAVAILABLE` or `NETWORK_FAILURE`; malformed input and integrity
failures use `INVALID_INPUT_OR_INTEGRITY_FAILURE`.

## Refresh with a previous snapshot

Pass the exact earlier snapshot directory when continuity matters:

```sh
prufyx-maintainer project sync \
  --manifest "$PRIVATE/project-request.json" \
  --output-parent "$PRIVATE/corpus" \
  --previous "$PRIVATE/corpus/snapshot-PASTE_THE_PREVIOUS_DIGEST"
```

The previous snapshot must be for the same repository. For tags visible in both
bounded windows, the commit must remain the same; release-body changes are
marked `CHANGED`, unchanged bodies are marked `UNCHANGED`, and retained bytes
are reused by digest. A tag outside the current 30-candidate page is outside
the comparison window and is not treated as a deletion. A successful refresh
still remains unreviewed evidence.

For exact-tag v2, the current request may add or omit selected tags and may
choose a new license anchor from the current selection. The project identity,
changelog paths, and license declaration must remain unchanged. Shared tags are
reobserved and must retain the same direct or annotated ref identity and peeled
commit. Added tags are new observations. Omitted tags are recorded as
`NOT_REOBSERVED_NOT_REVALIDATED`; omission is not a deletion or freshness claim.

## Verify, inspect, and report locally

All commands below read only an already-created snapshot and make no network
request:

```sh
SNAPSHOT="$PRIVATE/corpus/snapshot-PASTE_THE_DIGEST"

prufyx-maintainer project verify --snapshot "$SNAPSHOT"
prufyx-maintainer project status --snapshot "$SNAPSHOT"
prufyx-maintainer project inspect --snapshot "$SNAPSHOT"
prufyx-maintainer project inspect --snapshot "$SNAPSHOT" --tag TAG
prufyx-maintainer project inspect --snapshot "$SNAPSHOT" --include-notes
prufyx-maintainer project proposal --snapshot "$SNAPSHOT" > "$PRIVATE/project-proposal.json"
```

For a v2 snapshot created with `sync --previous`, replay continuity against the
exact retained prior snapshot:

```sh
prufyx-maintainer project verify \
  --snapshot "$PRIVATE/corpus/snapshot-CURRENT_DIGEST" \
  --previous "$PRIVATE/corpus/snapshot-PRIOR_DIGEST"
```

`verify` checks the closed snapshot, object hashes, release/tag bindings,
commit-pinned source records, and receipt. Its result is
`VERIFIED_RETAINED_PUBLIC_PROJECT_EVIDENCE` with
`NOT_REVIEWED`/`NOT_ADMITTED` states. `status` reports the repository, snapshot
digest, release count, source count, and review state. `inspect` emits bounded
metadata; `--include-notes` includes retained public release bodies and should
remain a local review action.

For v2, verification binds the repository object, exact tag-reference and
optional annotated-tag objects, peeled commits, commit-pinned source corpus,
anchor license observation, receipt, and current request. An initial snapshot
reports `NO_PREVIOUS_SNAPSHOT`. A current snapshot that contains lineage but is
verified without `--previous` reports
`CONTINUITY_NOT_REPLAYED_PREVIOUS_NOT_SUPPLIED`; replay with both independently
verified snapshots reports `CONTINUITY_REPLAYED_VERIFIED`. Omitted prior tags
remain `NOT_REOBSERVED_NOT_REVALIDATED`. V2 status reports tag and source counts
and the stored lineage partition. V2 inspect and proposal expose only retained
references, digests, spans, and declarations; they never expose raw objects or
invent GitHub Release fields.

Sync retains at most one selected changelog candidate for each distinct peeled
commit. Offline verification binds that selected file to the request and commit;
it does not claim that earlier candidate paths still return 404 upstream.

`proposal` emits the closed
`prufyx.io/public-project-source-only-proposal/v1` for release mode or the
additive `/v2` schema for exact-tag mode. It contains the applicable repository,
release or exact-tag identities, commits, immutable references, digests, and
license observation metadata. It deliberately excludes retained raw bodies and
the object store, and requests `INDEPENDENT_REVIEW_REQUIRED`.

## Evidence and ownership boundary

The snapshot records public observations and retained bytes only. It does not
prove repository ownership, maintainer authority, license permission, release
authenticity beyond the observed GitHub response, project support, upgrade
compatibility, runtime behavior, signing, admission, or publication. The CLI
does not clone, build, execute, render, or send upstream source to a model.

Do not place customer configuration, cluster objects, credentials, Secrets,
logs, private paths, production data, or proprietary source in a request,
snapshot handoff, or issue. A source-only proposal is suitable for a maintainer
review record; it is not an automatic feed, server queue, client upload, or
training submission.
