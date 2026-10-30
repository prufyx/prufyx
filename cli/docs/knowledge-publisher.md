# Offline CNCF knowledge publisher preparation

`prufyx-maintainer knowledge-publish` prepares and finalizes one externally
signed CNCF knowledge package. It is an offline maintainer tool. It
does not generate or load private keys, call a signer, fetch metadata, publish
bytes, choose a trust authority, or change the CLI's `OPERATOR_PROVISIONED` and
`CANDIDATE_ONLY` report labels.

The input target must be a canonical `operator_provided` replacement snapshot
for `knowledge/constraints.v1.json` (or, with `--targets-dir`, the index and
project targets of the per-project layout described below) and the exact
capability compiled into this source tree. Replacement means the selected feed target stands on its own and
is never merged with an installed snapshot. Its reviewed rules may differ from
the embedded set, including data-only additions, removals, or an empty snapshot
that intentionally supplies no coverage. The separately reviewed CNCF exporter
can produce the current complete embedded snapshot; use its export receipt and
the generated support inventory for the exact rule count and digests. Supply a
signed public TUF root and its SHA-256 through an independent trusted process.
The root stays separate from the target and package.

TUF signing is sequential. Snapshot metadata hashes the finalized targets
metadata, including its signatures; timestamp metadata hashes the finalized
snapshot. A signer therefore cannot sign all three payloads in parallel.

Use a private working directory and absolute paths:

```sh
umask 077
mkdir -m 700 /absolute/publisher

prufyx-maintainer knowledge-publish prepare-targets \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --version 1 --expires 2026-12-01T00:00:00Z \
  --output /absolute/publisher/targets-step
```

The new step directory contains mode-`0600` files:

- `targets.payload.json`: exact OLPC-canonical JSON bytes to sign;
- `targets.request.json`: payload/root/target digests, authorized key IDs,
  threshold, role version, and expiry;
- `targets.unsigned.json`: the exact unsigned TUF metadata envelope.

Give the payload and request to the external targets-role signer. It returns
one canonical signature envelope:

```json
{"schema":"prufyx.io/external-tuf-signatures/v1","role":"targets","payloadDigest":"sha256:<payload>","signatures":[{"keyid":"<64-lowercase-hex>","sig":"<lowercase-hex-ed25519-signature>"}]}
```

Signature entries are sorted by key ID and contain enough authorized distinct
keys to satisfy the public root's threshold. The signature is over the payload
file's exact bytes. Finalize the role:

```sh
prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role targets \
  --unsigned /absolute/publisher/targets-step/targets.unsigned.json \
  --signatures /absolute/targets-signatures.json \
  --output /absolute/publisher/1.targets.json
```

Role finalization rejects the wrong TUF role type, extra fields, unexpected
targets or metadata entries, and signatures that do not meet the supplied
root's authorization threshold. It validates the exact closed role shape for
this repository. Cross-role byte identities and expiry at the current clock are
checked again before a package can be emitted.

Prepare and externally finalize snapshot next:

```sh
prufyx-maintainer knowledge-publish prepare-snapshot \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --version 1 --expires 2026-11-15T00:00:00Z \
  --output /absolute/publisher/snapshot-step

prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role snapshot \
  --unsigned /absolute/publisher/snapshot-step/snapshot.unsigned.json \
  --signatures /absolute/snapshot-signatures.json \
  --output /absolute/publisher/1.snapshot.json
```

Then prepare and externally finalize timestamp:

```sh
prufyx-maintainer knowledge-publish prepare-timestamp \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --version 1 --expires 2026-10-01T00:00:00Z \
  --output /absolute/publisher/timestamp-step

prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role timestamp \
  --unsigned /absolute/publisher/timestamp-step/timestamp.unsigned.json \
  --signatures /absolute/timestamp-signatures.json \
  --output /absolute/publisher/timestamp.json
```

Close the package only after every role is finalized:

```sh
prufyx-maintainer knowledge-publish finalize-package \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --timestamp /absolute/publisher/timestamp.json \
  --output /absolute/publisher/cncf-1.tar \
  > /absolute/publisher/finalization-receipt.json
```

The same successful in-memory finalization can also create an unsigned client
release plan. The command does not read a saved receipt:

```sh
prufyx-maintainer knowledge-publish finalize-package \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --timestamp /absolute/publisher/timestamp.json \
  --output /absolute/publisher/cncf-1.tar \
  --package-url https://metadata.example.org/cncf-1.tar \
  --release-plan-output /absolute/publisher/cncf-1.release-plan.json \
  > /absolute/publisher/finalization-receipt.json
```

The plan binds the exact package URL and digest, target revision/digest/purpose
and capability, publisher initial-root identity, one-entry root history, and all
verified role versions, digests, and expiries. It is routing plus assertions,
not a trust root, signature, maintainer identity, or client bootstrap authority.
This v1 plan shape rejects rotated root history; use the existing manual path for
a rotated store.

Finalization reconstructs the fixed content-addressed repository, packages it
canonically, and invokes the same `knowledge.VerifyConstraints` path used by
`prufyx db verify`. Verification uses the actual UTC clock and must authenticate
the root, role thresholds, metadata chain, target digest, complete external
envelope, revision, capability, and evidence admission before the new package
file is created. The JSON receipt records those exact identities and states
that no network or private key was used.

The output parent and every step parent must already be owned by the current
user with mode `0700`. Outputs are new mode-`0600` files or a new mode-`0700`
step directory; overwrite is rejected. If a create, write, close, or sync step
fails, the publisher leaves the incomplete new file or directory in place for
explicit operator inspection or cleanup and returns a generic failure. Retry
with a different new path. A successful finalization does not publish the
package. Hosting, root bootstrap, key custody, expiry policy, source review,
and release authority remain separate gates.

Paired output is ordered and durable rather than crash-atomic. The package is
created and synchronized first, then the plan. The command reports success only
after both exist durably. If plan creation fails, the already durable package and
any pre-existing plan file remain untouched and the command fails without a
finalization receipt on stdout. Retry with new output paths.

## One-command release

`knowledge-publish release` builds a complete signed release from the knowledge
embedded in this source tree in one offline, deterministic step. It exports the
embedded CNCF knowledge at the given revision, prepares the targets, snapshot
and timestamp roles, signs each with its encrypted role key, finalizes and
verifies the package through the consumer verifier, and writes the files into a
new `0700` directory.

```sh
prufyx-maintainer knowledge-publish release \
  --revision 81 --version 1 \
  --root /absolute/root.json --root-digest sha256:<root> \
  --targets-key /absolute/targets.key.pem \
  --snapshot-key /absolute/snapshot.key.pem \
  --timestamp-key /absolute/timestamp.key.pem \
  --passphrase-file /absolute/passphrase \
  --package-url https://metadata.example.org/cncf-81.tar \
  --output-dir /absolute/release-81
```

The output directory holds `root.json`, `constraints.v1.json`,
`<version>.targets.json`, `<version>.snapshot.json`, `timestamp.json`,
`cncf-<revision>.tar` and `cncf-<revision>.release-plan.json`; the JSON receipt
goes to standard output. Host the package at `--package-url`; clients run
`prufyx db update --release-plan cncf-<revision>.release-plan.json ...` as
described in [knowledge-updates.md](knowledge-updates.md).

- Key paths come from flags. The command never creates or stores keys. Role keys
  are the encrypted files made by `knowledge-sign init`; the passphrase is read
  from `--passphrase-file`, which must be a regular file readable only by its
  owner. Keep the root key offline: it is not used here.
- Every role expires at the earliest evidence expiry of the exported rules, so
  metadata never outlives the reviewed knowledge. `--expires` can only make it
  earlier. A release whose knowledge has already expired is refused.
- No clock enters the metadata and Ed25519 signing is deterministic, so the
  same inputs produce byte-identical files.
- `--version` must be larger than the previous release: clients may keep a rollback
  floor and refuse an older version.
- It does not choose a trust root and does not change what `scan` uses by
  default; a client still needs the independently verified root and digest.

## Per-project layout (`cncf-projects`)

The CNCF knowledge is published as an index plus one target per project (see
[cncf-knowledge-per-project.md](cncf-knowledge-per-project.md)), so no single
target caps the coverage. The publisher builds, signs, packages and finalizes
this layout with the same role keys and the same single targets role as the
single-bundle layout: the targets role simply lists the index and every project
target, and the snapshot and timestamp roles are unchanged. No new key or key
ceremony is involved. The single-bundle path above is unchanged.

```sh
# 1. The per-project targets of this source tree, or of the next revision.
prufyx-maintainer export-knowledge --profile cncf-projects --revision 82 \
  [--previous-index /absolute/committed-index.json] --output /absolute/publisher/targets

# 2. The same prepare / sign / finalize steps, with --targets-dir instead of --target.
prufyx-maintainer knowledge-publish prepare-targets --root ... --root-digest ... \
  --targets-dir /absolute/publisher/targets --version 1 --expires ... --output ...
prufyx-maintainer knowledge-publish finalize-package --root ... --root-digest ... \
  --targets-dir /absolute/publisher/targets --targets ... --snapshot ... --timestamp ... \
  --output /absolute/publisher/cncf-projects-82.tar

# 3. Package an already signed directory from the content-addressed members.
prufyx-maintainer package-knowledge --profile cncf-projects --input ... --output ...
```

`--targets-dir` is the tree written by `export-knowledge --profile cncf-projects`
or `knowledge-targets build`: `knowledge/cncf/index.v1.json` and one
`*.v1.json` per project under `knowledge/cncf/projects` and, when present,
`knowledge/community/projects`. The publisher checks that the project targets
are exactly the ones the index lists, each admitted against its index entry,
before anything is signed; `finalize-package` and `finalize-rotated-package`
verify the finished package with the per-project consumer verifier
(`prufyx db verify --profile cncf-projects`). The package members are
`targets/knowledge/cncf/<sha256>.index.v1.json` and
`targets/knowledge/{cncf,community}/projects/<sha256>.<project>.v1.json`; the
packer applies the consumer's member names and bounds (at most 1024 project
targets, 8 MiB package, 7 MiB of members) and checks every member against the
digest in its name. `finalize-package --package-url/--release-plan-output` is
refused for this layout (see below).

`knowledge-publish release --profile cncf-projects` does all of this in one
step. It builds the targets with the **previous index** so that a project whose
target bytes did not change keeps its previous revision (a changed project, or a
new one, gets the new revision; a revision that does not advance the previous
index is refused). Exactly one of the following is required, so a forgotten
index cannot bump every project and move every rollback floor:

- `--previous-index /absolute/index.json`: the index of the last release. The
  `knowledge-publish.yml` workflow takes it from the package of the last
  successful sign run (see the recovery runbook); nothing is committed. The
  release writes the next index to `knowledge/cncf/index.v1.json` inside its
  output directory. The workflow refuses `first_release=true` when a
  successful sign run on `main` exists.
  Review duty: a hand-edited index (for example lowering a project's revision)
  could regress a project below client rollback floors. `release` checks only
  that the previous index parses under the compiled engine capability and that
  the new revision is greater than the index revision; it does not verify that
  the file is the one last published, nor that no project revision was lowered.
- `--first-release`: no index was ever published. Use it only then, or when the
  engine capability changed (an index of an older capability no longer parses
  and every target changes anyway); the new revision must still be larger than
  every revision published before.

The output directory holds `root.json`, `<version>.targets.json`,
`<version>.snapshot.json`, `timestamp.json`, `cncf-projects-<revision>.tar` and
the targets under `knowledge/`. `--package-url` is not used. No release plan is
written: the release-plan format (`prufyx db update --release-plan`) describes
the single-target layout only and stays `cncf`-only, so clients of the
per-project layout update with `prufyx db update --profile cncf-projects` from
the package. A pack that holds distribution records cannot be published in this
layout (no project target carries them); the release is refused with a message
that says so.

## Root-transition preparation

A root transition is a separate, offline producer step. It does not publish a
package, activate trust, replace an initialized store, or create a release plan.
The trusted root and the self-signed successor template are supplied at every
preparation and finalization boundary with independently checked digests. The
template is only a proposed next policy until the old and successor root
thresholds sign the same canonical successor payload.

```sh
prufyx-maintainer knowledge-publish prepare-root-transition \
  --trusted-root /absolute/current-root.json --trusted-root-digest sha256:<current> \
  --successor-template /absolute/proposed-root.json --successor-template-digest sha256:<template> \
  --output /absolute/publisher/root-transition-step
```

Use `knowledge-sign sign-root-transition` once per root-key contribution, with
both root files, the prepared unsigned metadata and request, its payload digest,
and `--authority trusted|successor`. Then finalize with repeated `--signatures`
paths. A key present in both root policies supplies one unique signature that may
satisfy each threshold once. Duplicate key IDs, a contribution for another
payload, a template/request mismatch, or either unsatisfied threshold is
rejected. The JSON receipt proves only the returned successor-root bytes and
threshold identities; it is not a trust bootstrap, custody proof, or publication.

```sh
prufyx-maintainer knowledge-publish finalize-root-transition \
  --trusted-root /absolute/current-root.json --trusted-root-digest sha256:<current> \
  --successor-template /absolute/proposed-root.json --successor-template-digest sha256:<template> \
  --unsigned /absolute/publisher/root-transition-step/root.unsigned.json \
  --request /absolute/publisher/root-transition-step/root.request.json \
  --signatures /absolute/publisher/root-old-signature.json \
  --signatures /absolute/publisher/root-successor-signature.json \
  --output /absolute/publisher/2.root.json \
  > /absolute/publisher/root-transition-receipt.json
```

## Rotated package finalization

After each successor root has been finalized through the root-transition workflow,
create a **manual** package anchored to the independently pinned initial root. Give
the ordered, finalized successor roots from `N+1` through the final authority; the
initial root is supplied for bootstrap verification and is never packaged as a
metadata member.

```sh
prufyx-maintainer knowledge-publish finalize-rotated-package \
  --initial-root /absolute/1.root.json --initial-root-digest sha256:<root-1> \
  --successor-root /absolute/2.root.json \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --timestamp /absolute/publisher/timestamp.json \
  --output /absolute/publisher/cncf-rotated.tar \
  > /absolute/publisher/rotated-finalization-receipt.json
```

The route accepts one through eight contiguous successor roots. It verifies every
root transition from the supplied initial root, authenticates all final-authority
metadata at the actual UTC clock, and emits a receipt whose `rootDigest` and
`verification.initialRootDigest` both bind that exact initial root. The package
contains only successor-root metadata and is therefore intentionally
starting-root-specific: an already advanced store must use its normal update
path instead.

This command creates no release plan, feed, trust bootstrap, or custody proof.
It preserves a complete valid empty replacement target for an intentional
withdrawal; malformed or incomplete target metadata is rejected.

## Hosted knowledge publish workflow

`.github/workflows/knowledge-publish.yml` signs and publishes the knowledge
database that `prufyx db update` fetches. The workflow runs on
every push to `main` that touches `cli/knowledge/**`, weekly, and on manual
dispatch from `main`. It is off until the repository variable
`KNOWLEDGE_RELEASE_ENABLED` is exactly `true`, and it never runs pull request
code.

Two jobs keep the signing keys and the Pages deploy token apart:

- `sign` runs in the environment `knowledge-release`, which holds the three
  online role keys and their passphrase (`KNOWLEDGE_TARGETS_KEY`,
  `KNOWLEDGE_SNAPSHOT_KEY`, `KNOWLEDGE_TIMESTAMP_KEY`,
  `KNOWLEDGE_KEY_PASSPHRASE`). It builds the package from the checked-out
  `main` commit, signs it, verifies it with `prufyx db verify` against the
  pinned root, and uploads it as the artifact `knowledge-<revision>-<sha256>`
  (kept 90 days). All roles expire at the earlier of 14 days from now and the
  earliest reviewed-evidence expiry; the weekly run leaves one missed run of
  margin. The package digest is a job output, and the job summary logs the
  revision and digest. A push or dispatch run is skipped when the signed content
  is unchanged and the last publish is under 7 days old. The weekly scheduled run
  is never skipped: it always re-signs, so the timestamp expiry moves every
  week (a skip near 7 days would leave the next run on the 14-day expiry).
- `deploy` runs in the environment `github-pages` and holds no keys. It
  downloads the artifact, checks its SHA-256 against the sign job's output,
  verifies it again against the pinned root, refuses to run if a later run has
  already succeeded, and deploys `knowledge/cncf-projects.tar`,
  `knowledge/root.json` and `knowledge/status.json` with `actions/deploy-pages`.
  The last two files are informational and never trusted by clients.

The previous revision, TUF version and index are read from the last successful
run of this workflow on `main` (GitHub API, not the Pages CDN, which caches
for about ten minutes). Its artifact is verified against the pinned root and
the digest in its name, and one index member is extracted with a size cap.
Revision and TUF version advance by one. With no previous run the workflow
fails; the very first publish needs `first_release=true`, which itself fails
when any successful run exists.

The pinned root is `cli/internal/knowledgepin/root.json`. The workflow stops
unless that file, the compiled-in pin and the repository variable
`KNOWLEDGE_ROOT_DIGEST` agree. Release tag builds make the same check when the
variable is set (nothing is checked when it is not).

### Publish self-check

`.github/workflows/knowledge-publish-verify.yml` runs daily (and on dispatch)
and needs no human and no secret: job permissions are `contents: read` and
`issues: write`, the second only for one tracking issue. It runs only on `main`
and only when `KNOWLEDGE_RELEASE_ENABLED` is `true`. It calls
`scripts/publish-verify.sh`, which fetches the public feed
(`https://prufyx.github.io/prufyx/knowledge/cncf-projects.tar`), verifies it
with `prufyx db verify` against the pinned root (the same trust as
`prufyx db update`) and prints one line. It fails, listing every reason, when:

- the feed is unreachable or does not verify (including an expired timestamp);
- the feed is older than 8 days (signing time is the verified timestamp expiry
  minus 14 days; when the evidence expiry capped the expiry instead, the
  `Last-Modified` of the deploy is used);
- the timestamp expires in less than 5 days;
- the last successful `Knowledge publish` run on `main` is older than 8 days;
- the feed is older than the newest merge touching `cli/knowledge` on `main`,
  unless that merge is under 2 hours old or a later successful run (for
  example one that skipped an unchanged bundle) has accounted for it.

On failure the workflow opens the issue "Knowledge publish self-check failed"
(or comments on the open one) and the job fails; when the check passes again it
closes the issue. To check by hand, dispatch the workflow. To fix a failure,
see the recovery runbook below.

### Oldest-supported-client gate

Before the package is uploaded, the `sign` job builds the oldest client that
is still supported and runs `db verify` with it on the candidate package. The
client is pinned in `cli/knowledge/oldest-supported-client.txt`:

```
ref=<40-hex commit>
version=v0.1.0-beta.0
```

The steps "Read the oldest supported client pin", "Check out the oldest
supported client" (a pinned `actions/checkout` of `ref` into `oldest/`, no
persisted credentials), and "Verify with the oldest supported client" run
after "Build, sign and verify" and before "Upload the signed package", only
when a package was produced. The signing keys are already gone then (the
signing step removes them on exit) and none of these steps has a secret. The
client is built with `version` injected, so its version checks are real, and
it verifies against its own compiled-in root with the package digest and
revision of the candidate. If it refuses the package, or cannot be built, the
job fails with "the oldest supported client (...) refuses this package", the
upload and the deploy do not run, and the feed keeps the last package. An
unverifiable gate counts as a failed gate.

Until the first beta tag exists, `ref` is a commit of `main`. After the
`v0.1.0-beta.0` cut, a PR sets `ref` to that tag.

**Bump the pin** only after the old version is out of support: a PR that sets
`ref` and `version` to the new oldest supported release. Changing
`cli/knowledge/**` runs the publish workflow, which then proves the new pin
accepts the package.

**Recovery when the ref cannot be built** (for example the toolchain moved on
or the commit is unreachable): the gate fails every run and nothing is
published. Open a PR that fixes the pin file (a buildable ref of the same
supported version, or the next supported release when the old one is out of
support), then start a new run with `workflow_dispatch`. Do not remove the
gate step to unblock a publish.

### Repository setup (owner)

1. Enable GitHub Pages with source "GitHub Actions". Limit the environment
   `github-pages` to deployment branch `main`, so no other branch can deploy
   to the feed host.
2. Create the environment `knowledge-release` with deployment branch `main`
   only and no required reviewer (a reviewer would stop the unattended
   weekly run). Store the four signing secrets in that environment, and make
   sure no repository-level secret has the same names.
   Upload each key file from the file itself, `gh secret set NAME --env
   knowledge-release < file.key.pem`, not by pasting into the web form: a key
   whose final newline is lost is rejected at signing time with a generic
   `operation rejected` error.
3. Set the variable `KNOWLEDGE_ROOT_DIGEST` (`sha256:<hex>` of the pinned
   `root.json`), then `KNOWLEDGE_RELEASE_ENABLED=true`.
4. Keep no OIDC federation (cloud or other) configured for this repository
   without binding `environment` and `job_workflow_ref`, because the deploy
   job holds an OIDC token.

The root signing key is never used by CI and stays offline. The root has its
own passphrase, which CI never sees.

The workflow passes the pinned version 1 root (`cli/internal/knowledgepin/root.json`)
to the publisher as `--root` and to `db verify` as `--bootstrap-root`. The
publisher refuses keys that are not in the root it is given, so rotating the
online keys through a root transition also needs a workflow change that
supplies the successor root to the signing step.

### What protects the online keys

There is no required environment reviewer. Anyone who can land a commit on
`main` runs the publish workflow with the online keys, and editing the
workflow in that commit could exfiltrate them. A holder of the three online
keys can sign arbitrary knowledge, and clients check shape and evidence expiry,
not truth. The controls that stand in the way:

- Branch protection on `main` (pull request required). Code Owner review is
  not enforced, because every pull request is authored by the only code owner
  and GitHub forbids self-approval; `CODEOWNERS` still lists `.github/` and
  `cli/internal/knowledgepin/` as documentation of intent. A second reviewer
  identity is the upgrade path.
- The knowledge gate, an independent review of the exact head, and the
  maintainer's merge decision.
- The environment `knowledge-release` accepts deployments from `main` only.
- The `sign` job runs only the checked-out `main` commit, never pull request
  code; user input reaches shell code only through environment variables;
  every action is pinned by commit SHA; no Go build cache is restored and the
  job token is not kept in the checkout.

### Recovery runbook

Never use "Re-run failed jobs" or "Re-run all jobs" on this workflow. A rerun
reuses an old run's state; start a new run with `workflow_dispatch` instead.
The deploy job refuses an old run once a later run has succeeded.

- **Online keys compromised or suspected.** Run a root transition with the
  offline root key that removes the three online keys and adds new ones (see
  "Root-transition preparation" above). Create new online keys, store them as secrets of
  a fresh environment, and point the workflow at it. Then republish with a
  revision higher than any malicious one: the workflow always advances the
  revision, so one dispatch after the new keys are in place is enough. Clients
  refuse anything older than what they have seen, so a rollback is always a
  republish with a higher number, never a lower one. If the root key itself is
  compromised, create a new root and pin, which needs a new binary.
- **Previous artifact lost or expired** (artifacts are kept 90 days). Verify
  the live feed yourself with `prufyx db verify` against the pinned root, then
  dispatch with `previous_revision`, `previous_tuf_version` and
  `previous_index` (the HTTPS URL of the live `cncf-projects.tar`). The
  workflow downloads that package, verifies it against the pinned root and the
  stated revision, checks the TUF version, and continues from it. Recovery
  cannot use a package whose timestamp has expired.
- **Dead end: more than 14 days without a successful publish.** The previous
  package's timestamp has expired, so `prufyx db verify` cannot verify it. The
  artifact path and the recovery inputs both fail, and `first_release` is
  refused because successful runs exist. The way out is an explicit owner
  decision, taken through the coordinator (for example a new root and pin).
  A follow-up adds a verify option for expired timestamps, for recovery only.
  Until then the weekly run and its failure notification are the guard.
- **A publish failed.** The feed keeps serving the previous package until its
  timestamp expires, which is at most 14 days. Fix the cause and dispatch a
  new run; the revision is recomputed, so nothing is lost.
- **Online keys rotated routinely.** Use a root transition as above; no
  binary change is needed.
