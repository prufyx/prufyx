# Releasing a pre-release

This is the maintainer procedure for cutting a Prufyx pre-release tag, and the
procedure for a user to verify the result. It describes what
`.github/workflows/release.yml` does at the time of writing; if the workflow and
this page disagree, the workflow is authoritative and this page is a bug.

A pre-release is a candidate build. It is not a signed compatibility statement
(see [`candidateOnly`](#what-candidateonly-and-unpinned-mean) below).

## Tag name

Tags must match `v<major>.<minor>.<patch>[-<prerelease>]`, for example
`v0.0.1-alpha.1`. The workflow triggers on any tag starting with `v`, and
`scripts/action/install.sh` accepts only that shape. Do not reuse a tag that was
ever pushed, even if its release was deleted: the tag, the attestation and the
`SHA256SUMS` of a version must stay one-to-one.

## Cutting a pre-release tag

1. Decide the commit. It must be on `main`, merged through the normal pull
   request flow, with CI green on that exact commit.
2. Update the release notes file `cli/docs/release-notes-<tag>.md` in a normal
   pull request before tagging. The workflow's draft release text is a stub and
   does not read this file.
3. Check the embedded rule expiry dates against the planned publication date.
   After a rule expires its verdict is `UNKNOWN` by design, so a release
   published shortly before an expiry date ships rules that are about to lapse.
4. Create an annotated tag on that commit and push only the tag:

   ```sh
   git fetch origin main
   git tag -a v0.0.1-alpha.1 <full-40-character-commit> -m "v0.0.1-alpha.1"
   git push origin v0.0.1-alpha.1
   ```

5. Watch the `Release` workflow. When it succeeds it leaves a **draft** GitHub
   release. Nothing is public until a maintainer publishes the draft.
6. Before publishing, download the draft's assets and run the verification
   steps below against them. Mark the release as a pre-release when publishing
   (the workflow does not set that flag).
7. Publish the draft. Then run the verification once more from the public
   download URLs, and run `scripts/action/install.sh` through the composite
   action with `version: <tag>` on a throwaway repository.

A tag cannot be edited after it has been published: if something is wrong,
delete the draft, leave the tag as burned, and cut the next prerelease number.

## What CI does

The workflow has three jobs. Third-party actions are pinned by commit SHA.

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
2. **Checksums and provenance.** Downloads all archives, writes `SHA256SUMS`
   (sha256sum format, one line per archive), and creates a GitHub build
   provenance attestation (`actions/attest-build-provenance`) for every
   `.tar.gz`. `SHA256SUMS` itself is not an attested subject.
3. **Draft release.** Creates a draft release for the tag with the archives and
   `SHA256SUMS` attached.

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

## Reproducibility

Binaries are built with `-trimpath -buildvcs=false` and the build epoch is the
tagged commit's own commit time, so rebuilding the same tag with the same Go
toolchain yields byte-identical binaries. Archive byte-reproducibility depends
on how the workflow runs `tar` and `gzip`; compare the extracted binaries, not
the `.tar.gz` digests, unless the workflow documents otherwise.

## Pre-release checks that can run before tagging

`scripts/action/test.sh` (also run by `go test ./internal/actionscript`) checks
that `install.sh` and `release.yml` agree on the archive name, the binary path,
the checksum file name, the signer workflow and the platform matrix. A change
to either file that breaks that contract fails the test before a tag is pushed.
