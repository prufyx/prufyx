# Prufyx Community v0.0.1-alpha.1

**Early alpha pre-release.** This is the first tagged build of Prufyx
Community. Expect gaps, and read "Known limitations" before relying on a
result. A result is a scoped finding about the rules that were checked, not a
statement that a whole upgrade is safe.

Prufyx checks a planned upgrade of Kubernetes or a CNCF project against
reviewed, source-cited rules and answers `PASS`, `BLOCKED` or `UNKNOWN`. It
runs locally and offline, and a deterministic engine computes every verdict.
When the evidence does not decide the question the answer is `UNKNOWN`.

## What this build is

- **Candidate build.** `prufyx version` reports `"candidateOnly": true` and the
  profile `community-<os>-<arch>`. The release workflow builds from the tag and
  attests the archives; it does not apply maintainer signing. A report from
  this build is not signed Prufyx compatibility evidence.
- **Unpinned trust root.** `prufyx version` reports `"trustRootDigest":
  "UNPINNED"`. The build identity binds no release trust root.
- **No official knowledge feed yet.** The knowledge pin for `cncf-projects`
  is empty, so `prufyx db update` trusts nothing implicitly: you must pass an
  explicit bootstrap root and its digest. Without a store, the knowledge
  embedded in the binary is used. See
  [knowledge updates](https://github.com/prufyx/prufyx/blob/main/cli/docs/knowledge-updates.md).
- **Embedded rules expire.** Every rule in the CNCF and community-project
  packs is time-limited and stops being valid between 2026-12-07 and
  2026-12-22 unless its review is renewed. A renewal is planned before then,
  but it is not done: a build without newer knowledge answers `UNKNOWN` for an
  expired rule. The named cert-manager and Prometheus checks are pinned to
  fixed versions and do not expire.

## Coverage

These numbers are copied from the generated block in the repository
`README.md` (generated 2026-10-08 by `scripts/readme-coverage.sh`).

| Executable rules | Count |
| --- | --- |
| CNCF source rules, active | 190 across 53 projects (1 withdrawn, not used) |
| Rules for further, non-CNCF projects | 34 across 8 projects |
| Projects with at least one executable check | 65 |
| Projects catalogued with retained public sources | 58 (11 of them source-only, no check) |

Version-coverage depth, measured over the last five minor upgrades of each of
the 55 projects with a release-line snapshot (275 upgrades between consecutive
release lines):

| Status | Upgrades | Share |
| --- | --- | --- |
| Decided for the whole release-line pair (A attested, B bounded) | 0 | 0% |
| Rule for one exact version pair only (S) | 44 | 16% |
| Gap, no valid rule (G) | 231 | 84% |

Kubernetes: 26 valid rules, but 0 fall in its window 1.32 to 1.37; 5 of 5
upgrades in that window are gaps.

In plain terms: the rules are exact, reviewed transitions, mostly for older
releases. No upgrade between two release lines is decided as a whole yet. The
metric is defined in the [coverage report guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/coverage-report.md); it is
not a statement that any upgrade is safe.

## What works today

Merged and usable from this build:

- `prufyx scan`: reads rendered Kubernetes manifests and a target version and
  reports API versions that a release on the way to the target stops serving.
  Human, Markdown, JSON and SARIF output. It covers Kubernetes only. With the
  knowledge shipped today it cannot answer a complete `PASS`; expect `BLOCKED`
  or `UNKNOWN`. An upgrade that skips release lines reports every blocker a
  reviewed rule establishes on a line it enters. See the [scan guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/scan.md).
- `prufyx check cncf`, `check project`, `check batch` and the named checks
  (cert-manager values, Prometheus, and others listed in the
  [support inventory](https://github.com/prufyx/prufyx/blob/main/cli/docs/community-support-inventory.md)), including
  `--strict-exit`, which makes a scoped `PASS` exit `14` so CI cannot read it
  as a complete pass. See [exit codes](https://github.com/prufyx/prufyx/blob/main/cli/docs/exit-codes.md).
- Reviewed Kubernetes API-removal rules exist for upgrades to 1.22, 1.24-1.27,
  1.29 and 1.32. A rule that pins a removal or change boundary answers
  `UNKNOWN` for a hop that crosses the boundary outside the reviewed range.
- `prufyx catalog cncf` and `catalog checks`: list the projects, the embedded
  rules and the exact command and input each rule reads.
- `prufyx assess` (opt-in, the only command that reads a cluster, read-only
  through kubectl with an explicit kubeconfig and context): includes
  image-based component detection from a reviewed image registry. Unlisted,
  digest-only, `latest` and mirrored images give no version.
- `prufyx db update`, `db import` and `db status` for signed knowledge
  packages, with an explicit bootstrap root (see above).
- Coverage tooling for maintainers: `prufyx-maintainer coverage report`
  (reporting only; no verdict changes). See the
  [coverage report guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/coverage-report.md).

The [quickstart](https://github.com/prufyx/prufyx/blob/main/cli/docs/quickstart.md) takes a clean clone to a real `BLOCKED`
verdict on a Kubernetes API removal, with its upstream citation.

## Install and verify

Archives are built for linux and darwin on amd64 and arm64:
`prufyx_<tag>_<os>_<arch>.tar.gz` (the `prufyx` CLI) and
`prufyx-collector_<tag>_<os>_<arch>.tar.gz`. `SHA256SUMS` lists every archive,
and each archive has a GitHub build provenance attestation. Verify before you
run anything from an archive:

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

# 3. Unpack and compare the self-reported build identity.
tar -xzf "$ARCHIVE"
"./prufyx_${TAG}_linux_amd64/prufyx" version
```

The checksum alone says nothing about who built the archive; the attestation
is the origin check (it needs the `gh` CLI and network access). `prufyx
version` is self-reported by the binary, so use it only as a consistency check
after steps 1 and 2. Details, including reproducing the build, are in
[releasing](https://github.com/prufyx/prufyx/blob/main/cli/docs/releasing.md).

You can also build from source; see the [README](https://github.com/prufyx/prufyx/blob/main/README.md).

## Known limitations

- Most checks need operator-declared inputs (an effective config, a
  kubeconfig-derived snapshot, or similar); Prufyx does not infer them.
- A multi-minor jump (for example `1.24.17 -> 1.30.4`) is evaluated line by
  line: `scan` checks the step that enters each release line with known API
  removals, and a reviewed rule that blocks a step makes the answer `BLOCKED`,
  naming the crossed line. Where no reviewed rule decides a crossed line the
  answer is `UNKNOWN`, and without a reviewed path policy the skipped lines
  stay listed as not checked. A patch-only upgrade within one line (for
  example `1.30.4 -> 1.30.5`) is not evaluated for removals; check the patch
  release notes by hand.
- `scan` does not look at a live cluster, custom resources, stored versions,
  admission or component configuration, or node version skew.
- Kubernetes has no rule for upgrades after 1.32 yet, and most projects have
  rules for exact version pairs only (see Coverage).
- The collector (`prufyx-collector`) observes only a few components today; most
  component facts have to be declared by the operator.
- Input files for `check` must be regular, owner-only files (for example mode
  `0600`) and not symlinks. A symlinked path is refused rather than followed.
- No Windows archive is published, and file or directory input to `prufyx scan`
  is not supported on Windows.
- Planned, not in place: an official signed knowledge feed with a pinned trust
  root, and maintainer-signed releases.
- A knowledge pack that carries line attestations of custom-resource versions
  (the `crd.custom_resource_versions` family of a later build) is refused
  whole by this build, fail-closed: install a later build before using such a
  pack.

## Reporting issues

Use the repository's issue templates at
https://github.com/prufyx/prufyx/issues. Report security issues privately as
described in [SECURITY.md](https://github.com/prufyx/prufyx/blob/main/SECURITY.md). Never include customer
configuration, cluster snapshots or credentials.
