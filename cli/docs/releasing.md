# Releasing a pre-release

This is the maintainer procedure for cutting a Prufyx pre-release tag, and the
procedure for a user to verify the result. It describes what
`.github/workflows/release.yml` does at the time of writing; if the workflow and
this page disagree, the workflow is authoritative and this page is a bug.

A pre-release is a candidate build. It is not a signed compatibility statement
(see [`candidateOnly`](#what-candidateonly-and-unpinned-mean) below).

## Tag name

Tags must match `v<major>.<minor>.<patch>[-<prerelease>]`, for example
`v0.0.1-alpha.1`; build metadata (`+...`) is refused, and a pre-release part
starts with a letter or digit. The workflow triggers on any tag starting with
`v`, and `scripts/action/install.sh` accepts only that shape. Do not reuse a
tag that was ever pushed, even if its release was deleted: the tag, the
attestation and the `SHA256SUMS` of a version must stay one-to-one.

## Cutting a pre-release tag

1. Decide the commit. It must be on `main`, merged through the normal pull
   request flow, with CI green on that exact commit. The workflow refuses a
   tagged commit that is not on the first-parent line of `origin/main`. This is
   defense in depth only: the tagged commit carries its own copy of the
   workflow, so the real boundary is a repository tag ruleset on `refs/tags/v*`
   (only the owner may create such tags).
2. Generate the CHANGELOG entry and the release notes from the tree diff, in
   a normal pull request, before tagging. Both state exactly what the release
   adds since the previous tag: projects added to the catalogue, rules per
   project, line attestations and Kubernetes minors, owner-approved onboarding
   batches, the README coverage figures (A+B, S, G) and the merged pull
   requests. Nobody types these figures; the maintainer subcommand computes
   them from the data files of the two revisions (`rules.json` of the CNCF and
   community packs, the generated support inventory, `cli/knowledge/onboarding`
   and the README coverage block that `scripts/readme-coverage.sh` writes) and
   evaluates no rule. Freeze data merges first, then, with `<prev>` the
   previous tag and `<head>` the `main` commit that holds the last data merge:

   ```sh
   cd cli
   go run ./cmd/prufyx-maintainer release-notes --repo .. --from <prev> --to <head> --to-label <tag> --level 4 --into ../CHANGELOG.md
   go run ./cmd/prufyx-maintainer release-notes --repo .. --from <prev> --to <head> --to-label <tag> --into docs/release-notes-<tag>.md
   ```

   For the second command, first create `docs/release-notes-<tag>.md` with the
   hand-written text and an empty marker pair. `--into` rewrites only the text between the
   `<!-- release-notes:begin -->` and `<!-- release-notes:end -->` lines of the
   file and refuses a file without exactly one such pair.
   For `CHANGELOG.md`, first run `scripts/changelog-assemble.sh` from the repository root: it moves
   the `changelog.d/` fragments into `CHANGELOG.md` below the generated block
   and deletes them (`--check` only validates). The new section headings land above the hand-written
   ones of the same name; merge duplicate headings by hand. Then rename `## [Unreleased]` to `## [<version>] - <date>`, keep the generated
   block, and open a new `## [Unreleased]` section with its own marker pair.
   The release notes file is `cli/docs/release-notes-<tag>.md`: hand-written
   text above the marker pair (what the build is, its limits; see
   `release-notes-v0.0.1-alpha.1.md`) and the generated block inside it. The
   workflow uses this file as the draft release text and fails before building
   anything if it is missing. The generator prints counts and lists only: it
   does not say a project is safe, a catalogued project is not tested
   coverage, and decided is not safe. Do not add claims to the generated block;
   add them above the markers, from the same commands, or not at all. Read the
   result before merging: a figure shown as `n/a` means a data file or the
   README block was missing in one revision.

   After the pull request merges, tag the merge commit. Before the tag push,
   run both commands again with `--to <tagged commit>` and the same `--to-label`; `git diff` must show
   only the commit hash in the first line of each generated block. Any other
   difference means a data file changed after the freeze: commit the
   regenerated files in a new pull request and tag after it.
3. Check the embedded rule expiry dates against the planned publication date.
   After a rule expires its verdict is `UNKNOWN` by design, so a release
   published shortly before an expiry date ships rules that are about to lapse.
4. Before the first tag push, the owner creates the GitHub environment
   `release`. Settings > Environments > New environment > `release`, then:

   - Required reviewers: the owner (1 reviewer).
   - Leave "Prevent self-review" OFF. The owner pushes the tag, so with it ON
     nobody could approve the run.
   - Deployment branches and tags: Selected branches and tags. Add a rule
     with Ref type Tag and pattern `v*`.
   - No secrets and no variables.

   Create the environment before the first run. If it does not exist, GitHub
   creates the referenced environment automatically with no protection rules,
   and the approval gate does not exist.
5. Create an annotated tag on that commit and push only the tag:

   ```sh
   git fetch origin main
   git tag -a v0.0.1-alpha.1 <full-40-character-commit> -m "v0.0.1-alpha.1"
   git push origin v0.0.1-alpha.1
   ```

6. Watch the `Release` workflow. The "Checksums and provenance" job waits for
   the owner's approval. Approve it within 7 days of the tag push: the build
   artifacts are kept 7 days (`retention-days: 7` in `release.yml`), and after
   that the run fails and the tag must be redone. When the run succeeds it
   leaves a **draft** GitHub release. Nothing is public until a maintainer
   publishes the draft.
7. Before publishing, download the draft's assets and run the verification
   steps below against them. A tag with a hyphen (`-alpha.1`) is created as a
   pre-release by the workflow; keep that flag when publishing.
8. Publish the draft. Then run the verification once more from the public
   download URLs, and run `scripts/action/install.sh` through the composite
   action with `version: <tag>` on a throwaway repository.

A tag cannot be edited after it has been published: if something is wrong,
delete the draft, leave the tag as burned, and cut the next prerelease number.

## What CI does

The workflow has four jobs. Third-party actions are pinned by commit SHA.

1. **Build** (one job per `linux`/`darwin` x `amd64`/`arm64`, on
   `ubuntu-24.04`, `CGO_ENABLED=0`). For each platform it builds two binaries
   with `-trimpath -buildvcs=false`: `prufyx` from `./cmd/prufyx-community` with
   the build identity linked in, and `prufyx-collector` from
   `./cmd/prufyx-collector`. Each is packed as
   `<name>_<tag>_<os>_<arch>.tar.gz` holding one directory
   `<name>_<tag>_<os>_<arch>/` with the single executable inside.
   The build identity records the tag, the full commit, the SHA-256 of
   `git archive` of that commit, the SHA-256 of
   `release/community-shipping-policy-v2.json`, the profile
   `community-<os>-<arch>`, the commit's own commit time as build epoch, and the
   Go version.
2. **Linux packages.** For `linux` x `amd64`/`arm64` it unpacks the `prufyx`
   binary from the built archive and packs it with a pinned `nfpm` release
   (exact version and SHA-256 digest in the workflow) into
   `prufyx_<tag>_linux_<arch>.deb` and `.rpm`: `/usr/bin/prufyx` plus the
   licence files (`LICENSE`, `NOTICE`, `THIRD-PARTY.md`, `LICENSES/`) under
   `/usr/share/doc/prufyx/`, no install scripts. The job then unpacks every
   package and fails unless `/usr/bin/prufyx` is byte-identical to the binary
   of the archive, so a package never holds another binary than the attested
   archive. File times are the tagged commit's commit time; building the same
   inputs twice gave byte-identical packages (checked for nfpm 2.48.0).
3. **Checksums and provenance.** Downloads all archives and packages, writes
   `SHA256SUMS` (sha256sum format, one line per archive and package), and
   creates a GitHub build provenance attestation
   (`actions/attest-build-provenance`) for every `.tar.gz`, `.deb` and `.rpm`.
   `SHA256SUMS` itself is not an attested subject. This job runs in
   the protected GitHub environment `release`: it waits until the owner, the
   environment's only required reviewer, approves the run, and the
   environment admits only tags matching `v*` as deployment refs. The draft
   release job needs this job, so nothing is attested or drafted without that
   approval.
4. **Draft release.** Creates a draft release for the tag with the archives,
   packages and `SHA256SUMS` attached, using `cli/docs/release-notes-<tag>.md` as the text and
   marking hyphenated tags as pre-releases.

The workflow does not run the test suite, does not sign with any maintainer key
and does not publish. Maintainer-side signing with an offline key is a separate
tool, described in [Release provenance](signing-provenance.md).

## Verifying a release

Do all of this before executing anything from the archive. Use the tag you
intend to install, and take the expected commit from a source you trust
independently (for example `git rev-parse <tag>^{commit}` in your own clone of
the repository), not from the archive.

```sh
TAG=v0.0.1-alpha.1
ARCHIVE="prufyx_${TAG}_linux_amd64.tar.gz"
BASE="https://github.com/prufyx/prufyx/releases/download/$TAG"
curl -fsSLO "$BASE/SHA256SUMS" && curl -fsSLO "$BASE/$ARCHIVE"

# 1. The archive matches the published checksum (detects changed bytes only).
grep " $ARCHIVE\$" SHA256SUMS | sha256sum -c -

# 2. The archive was built by this repository's release workflow from this tag.
gh attestation verify "$ARCHIVE" \
  --repo prufyx/prufyx \
  --signer-workflow prufyx/prufyx/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" \
  --deny-self-hosted-runners

# Optionally also pin the commit you reviewed:
#   --source-digest <40-character-commit>

# 3. Unpack, and compare what the binary reports with what you verified.
tar -xzf "$ARCHIVE"
"./prufyx_${TAG}_linux_amd64/prufyx" version
```

What each step establishes:

- The checksum proves only that the archive equals the one named in
  `SHA256SUMS`. Both come from the same release, so on its own it says nothing
  about who built them.
- The attestation is the origin check. `--repo` and `--signer-workflow` pin the
  repository and the workflow file that signed; `--source-ref` pins the tag.
  Verification needs network access to GitHub and the `gh` CLI.
- `prufyx version` prints the embedded build identity. Its `sourceRevision`
  should equal the commit you expect for the tag. It is self-reported by the
  binary, so treat it as a consistency check after steps 1 and 2, not as
  evidence on its own.

### Linux packages

The `.deb` and `.rpm` assets are verified the same way (steps 1 and 2), then
installed:

```sh
PKG="prufyx_${TAG}_linux_amd64.deb"        # or _arm64.deb, _amd64.rpm, _arm64.rpm
curl -fsSLO "$BASE/$PKG"
grep " $PKG\$" SHA256SUMS | sha256sum -c -
gh attestation verify "$PKG" --repo prufyx/prufyx \
  --signer-workflow prufyx/prufyx/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
sudo dpkg -i "$PKG"                         # Debian, Ubuntu
sudo rpm -i "$PKG"                          # Fedora, RHEL, openSUSE
```

The package installs `/usr/bin/prufyx` and the licence files under
`/usr/share/doc/prufyx/`; it has no install scripts and is not signed with a
package-manager key, so there is no repository to add and no automatic update.
The workflow checks that its `/usr/bin/prufyx` equals the binary in the
`.tar.gz`. The RPM `Release` field is `1` and a pre-release tag becomes
`0.1.0~beta.0` in both formats.

The composite GitHub Action performs steps 1 and 2 itself
(`scripts/action/install.sh`) with `verify-attestation` defaulting to `auto`
(on), and refuses to install on any mismatch. Turning the attestation off is
accepted only together with an `archive-sha256` pin that the caller holds.

## What `candidateOnly` and `UNPINNED` mean

`prufyx version` reports these fields for every release build:

- `"candidateOnly": true`. The binary is a candidate build, not a
  maintainer-signed release. The release workflow does not run the offline
  release signing described in [Release provenance](signing-provenance.md), and
  the build profile is `community-<os>-<arch>`, which is deliberately distinct
  from the strict profile that signed releases require. The field does not
  change the verdicts a scan produces. It says the binary does not carry a
  signed compatibility claim, and that a report from it must not be presented as
  signed Prufyx compatibility evidence.
- `"trustRootDigest": "UNPINNED"`. The build identity does not bind a release
  signing trust root. The binary is built before any release statement that
  could name one exists, so this is expected for every CI build until the
  release signing flow is changed.

## The embedded knowledge trust-root pin

This is a different thing from `trustRootDigest` above. The package
`cli/internal/knowledgepin` holds, per knowledge profile, the SHA-256 of the
initial (version 1) TUF root of that profile's official knowledge feed. It is
compiled into the binary and is used by `prufyx db update` (see
[Knowledge updates](knowledge-updates.md)).

Today the only profile, `cncf-projects`, has an **empty** pin. An empty pin
means no root is pinned: `db update` requires the operator to pass an explicit
bootstrap root and digest, and nothing is trusted implicitly. Releases cut now
therefore ship without a pinned official feed root.

The pin is set by a reviewed source change that puts the digest of the
offline-created version 1 `root.json` into the `pins` table. That requires the
owner's key ceremony; an agent or CI job must not create it. A release built
after the pin lands will accept only a store rooted in that pin. Pins are part
of the source tree, so they are covered by the `sourceTreeDigest` in the build
identity; a release tag therefore fixes the pin for that version.

## Embedded knowledge freshness

A tag build fails unless the knowledge embedded in the binary is still valid
well after the release. The step "Check the embedded knowledge is fresh" runs
`prufyx-maintainer release-freshness --commit-date <tagged commit date>
--min-days 30`. It reads the end date (`validUntil`) of all active embedded
evidence with the same rules the binary applies at run time: CNCF rules, project
rules, line attestations, served-API lists, path policies, image identity
records and chart identity records. It takes the earliest date and fails when
that date is earlier than the tagged commit's date plus 30 days. A binary that
fails this rule would answer UNKNOWN, or report evidence as not current, soon
after it ships.

Check it before tagging, from `cli/`:

```sh
go run ./cmd/prufyx-maintainer release-freshness
```

It prints the earliest expiry as an RFC 3339 UTC time. Add
`--commit-date <RFC 3339 date of the commit you plan to tag>` to apply the
rule; any commit dated within 30 days of that expiry cannot be tagged until the
affected evidence is renewed.

Release checklist, in addition to the steps above:

- Renewals land first. Evidence that would expire inside the 30-day window is
  re-attested and merged to `main` before the tag, never after.
- The latest patch releases of the key projects are present in the data (the
  generated release notes list what was added; check the projects you
  announce).
- The embedded revision labels (`revision` at the top of
  `cli/internal/cncfcheck/data/rules.json` and
  `cli/internal/projectcheck/data/rules.json`) name the data being shipped. No
  command bumps them: they are edited by hand in the same pull request as the
  data change.
- The knowledge root pin is current. The tag build checks the pin only when the
  repository variable `KNOWLEDGE_ROOT_DIGEST` is set (see the section below);
  when it is set, confirm that the embedded root and the compiled-in pin match
  the root the publisher signs under at the time of the cut.

## Reproducibility

Binaries are built with `-trimpath -buildvcs=false` and the build epoch is the
tagged commit's own commit time, so rebuilding the same tag with the same Go
toolchain yields byte-identical binaries. The workflow pins the exact Go patch
release (`go-version: "1.26.8"`; the build identity records it) and packs the
archives deterministically (sorted members, the tagged commit's time as every
mtime, numeric root ownership, normalized modes, no gzip name or time). A
rebuild with the same Go release and GNU `tar` and `gzip` therefore yields
identical `.tar.gz` files: compare the `.tar.gz` digests with `SHA256SUMS`.
If a different `tar` or `gzip` implementation is used, compare the extracted
binaries instead.

## Pre-release checks that can run before tagging

`scripts/action/test.sh` (also run by `go test ./internal/actionscript`) checks
that `install.sh` and `release.yml` agree on the archive name, the binary path,
the checksum file name, the signer workflow and the platform matrix. A change
to either file that breaks that contract fails the test before a tag is pushed.
