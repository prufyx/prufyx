# Offline CNCF knowledge publisher preparation

`prufyx-maintainer knowledge-publish` prepares and finalizes one externally
signed CNCF knowledge package. It is an offline maintainer tool. It
does not generate or load private keys, call a signer, fetch metadata, publish
bytes, choose a trust authority, or change the CLI's `OPERATOR_PROVISIONED` and
`CANDIDATE_ONLY` report labels.

The input target must be a canonical `operator_provided` replacement snapshot
for `knowledge/constraints.v1.json` and the exact capability compiled into this
source tree. Replacement means the selected feed target stands on its own and
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

## Hosted knowledge release workflow

`.github/workflows/knowledge-release.yml` can build one signed knowledge
release from CI. It is disabled until the repository variable
`KNOWLEDGE_RELEASE_ENABLED` is exactly `true`. Its job runs in the protected
GitHub environment `knowledge-release`, and the three TUF role keys and their
passphrase are the only secrets it reads. Before setting the variable, the
repository owner must:

1. Create the environment `knowledge-release` (Settings, Environments) with
   the owner as required reviewer, so every run waits for an explicit approval.
2. Limit the environment's deployment branches to `main`, so a run started
   from another branch (a branch copy of the workflow) cannot use the secrets.
3. Store the signing secrets as secrets of that environment, not as
   repository secrets, and make sure no repository-level secret with the same
   names exists, so no other job can read them.

Create the environment before the first run: GitHub creates a referenced
environment that does not exist automatically, with no protection rules.

The job does not restore a Go build cache and does not keep the job token in
the checkout, so nothing another workflow run wrote can reach the signing step.
The root signing key is never used by CI and stays offline.
