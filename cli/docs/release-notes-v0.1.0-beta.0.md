# Prufyx Community v0.1.0-beta.0

**Public beta pre-release.** This is a build for testers. Expect gaps, and
read "Known limitations" before relying on a result. A result is a scoped
finding about the rules that were checked, not a statement that a whole upgrade
is safe. The [beta tester guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/beta-tester-guide.md) walks through install,
the main commands and how to report a wrong answer.

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
  "UNPINNED"` unless the release notes of a later build say otherwise. The
  build identity binds no release trust root.
- **No official knowledge feed published.** There is no Prufyx-operated
  download endpoint for knowledge packages. `prufyx db update` trusts nothing
  implicitly: you must pass an explicit bootstrap root and its digest, and a
  source URL you operate or chose. Without a store, the knowledge embedded in
  the binary is used. See
  [knowledge updates](https://github.com/prufyx/prufyx/blob/main/cli/docs/knowledge-updates.md).
- **Embedded rules expire.** Every rule in the CNCF and community-project
  packs is time-limited and stops being valid on its expiry date unless its
  review is renewed. A build without newer knowledge answers `UNKNOWN` for an
  expired rule. Check the dates of the knowledge store you use with
  `prufyx db status` before you rely on a result.

## What works

- `prufyx scan`: rendered Kubernetes manifests and a target version; reports
  API versions that a release on the way to the target stops serving. Human,
  Markdown, JSON, SARIF and CSV output. Kubernetes only. See the
  [scan guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/scan.md).
- `prufyx plan`: the hops of a multi-hop upgrade as ordered stages, built from
  one `scan`. No stage is `PASS` yet (hop actions and node rolls are not
  checked). See the [plan guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/plan.md).
- `prufyx check cncf`, `check project`, `check batch` and the named checks
  (listed in the [support inventory](https://github.com/prufyx/prufyx/blob/main/cli/docs/community-support-inventory.md)),
  including `--strict-exit`, which makes a scoped `PASS` exit `14` so CI cannot
  read it as a complete pass. See [exit codes](https://github.com/prufyx/prufyx/blob/main/cli/docs/exit-codes.md).
- `prufyx prepare cncf` and `prepare project`: build a check input from a
  project's own configuration file.
- `prufyx catalog cncf` and `catalog checks`: list the projects, the embedded
  rules and the exact command and input each rule reads.
- `prufyx assess` (opt-in, the only command that reads a cluster, read-only
  through kubectl with an explicit kubeconfig and context).
- `prufyx db verify`, `db import`, `db update` and `db status` for signed
  knowledge packages, with an explicit bootstrap root (see above).

The [quickstart](https://github.com/prufyx/prufyx/blob/main/cli/docs/quickstart.md) takes a clean clone to a real `BLOCKED`
verdict on a Kubernetes API removal, with its upstream citation.

## Coverage

The figures for this release (projects, rules, line attestations, Kubernetes
minors and the A+B / S / G split of the last five minor upgrades) are in the
generated block at the end of this file. They are computed from the data files
of the two revisions; nobody types them. The method is in the
[coverage report guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/coverage-report.md). Most upgrades are still not decided as a
whole: a gap (G) is `UNKNOWN`, never a pass, and a catalogued project is not
tested coverage. These figures are not a statement that any upgrade is safe.

## Install and verify

Archives are built for linux and darwin on amd64 and arm64:
`prufyx_<tag>_<os>_<arch>.tar.gz` (the `prufyx` CLI) and
`prufyx-collector_<tag>_<os>_<arch>.tar.gz`. For linux on amd64 and arm64 the
`prufyx` CLI is also published as `prufyx_<tag>_linux_<arch>.deb` and `.rpm`.
`SHA256SUMS` lists every archive and package, and each of them has a GitHub
build provenance attestation. Verify before you
run anything from an archive:

```sh
TAG=v0.1.0-beta.0
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

To install a package instead, run steps 1 and 2 with the package file name
(`prufyx_${TAG}_linux_amd64.deb`, or `.rpm`, or an `arm64` one), then
`sudo dpkg -i` the `.deb` or `sudo rpm -U` the `.rpm`. The package holds the
binary of the attested archive, the licence files and no install scripts.

The checksum alone says nothing about who built the archive; the attestation
is the origin check (it needs the `gh` CLI and network access). `prufyx
version` is self-reported by the binary, so use it only as a consistency check
after steps 1 and 2. Details are in
[releasing](https://github.com/prufyx/prufyx/blob/main/cli/docs/releasing.md). On macOS, `sha256sum` may be missing: use
`shasum -a 256 -c -` instead.

You can also build from source; see the [README](https://github.com/prufyx/prufyx/blob/main/README.md).

## Known limitations

- Most checks need operator-declared inputs (an effective config, a
  kubeconfig-derived snapshot, or similar); Prufyx does not infer them.
- `scan` does not look at a live cluster, custom resources, stored versions,
  admission or component configuration, or node version skew. A patch-only
  upgrade within one line is not evaluated for removals; check the patch
  release notes by hand.
- A multi-minor jump is evaluated line by line. Where no reviewed rule decides
  a crossed line the answer is `UNKNOWN`.
- Most projects have rules for exact version pairs only. Check coverage for
  your versions with `prufyx catalog checks --project SLUG --from X --to Y`
  before reading an `UNKNOWN` as "nothing found".
- The collector (`prufyx-collector`) observes only a few components; most
  component facts have to be declared by the operator.
- Input files for `check` must be regular, owner-only files (for example mode
  `0600`) and not symlinks. A symlinked path is refused rather than followed.
- No Windows archive is published, and file or directory input to `prufyx scan`
  is not supported on Windows.
- Planned, not in place: an official signed knowledge feed with a pinned trust
  root, and maintainer-signed releases.
- A knowledge pack with a feature a build does not know is refused whole,
  fail-closed.

## Reporting issues

Use the repository's issue templates at
https://github.com/prufyx/prufyx/issues, and see the
[beta tester guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/beta-tester-guide.md#report-a-wrong-answer). Report security issues
privately as described in [SECURITY.md](https://github.com/prufyx/prufyx/blob/main/SECURITY.md). Never include customer
configuration, cluster snapshots or credentials.

## What changed in this release

<!-- release-notes:begin -->
<!-- release-notes:end -->
