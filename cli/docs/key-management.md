# Key management

This page lists every signing key and pinned digest that the code in this
repository defines, where the public part of each one is pinned, and what to
do when a key is rotated, lost or compromised.

Read this first: **no production key or trust root is pinned in this
repository today.** The tools below exist and are tested with throwaway keys.
Nothing here is a published trust anchor, a published feed or a signed
release. Each procedure describes what the code supports; where the code has
no mechanism, the section says so instead of describing a promise.

No private key, passphrase or token is stored in this repository, and none is
described by value. Public keys and public digests are the only trust inputs
that may be committed or placed in repository variables.

## Summary

| Role | Algorithm | Private part | Public part is pinned in | Pinned today |
| --- | --- | --- | --- | --- |
| [Knowledge package roles](#knowledge-package-roles-root-targets-snapshot-timestamp): `root`, `targets`, `snapshot`, `timestamp` | Ed25519 (TUF) | encrypted file per role, held by the operator | the operator's own process: the initial root file plus its SHA-256, passed as `--bootstrap-root` and `--bootstrap-root-digest` | No. Official root not published. |
| [Release statement key](#release-statement-key) | Ed25519 | one encrypted file, held offline by the release owner | the release trust root digest, passed to `release verify-signature` | No. No release has been signed. |
| [Artifact attestation](#artifact-attestation) | keyless (GitHub-issued) | none held by the project | the workflow identity (repository, workflow file, source revision) | Workflow exists; no tagged release has been published. |
| [Re-attestation keys](#re-attestation-keys-human-and-automation): `human`, `automation` | Ed25519 | encrypted file per key | the trust root file, pinned by the repository variable `REATTEST_TRUST_ROOT_DIGEST` | No. No trust root file or digest is recorded in this repository. |
| [Owner-approval key](#owner-approval-key) (`web-approval`) | Ed25519 | held by the owner, outside this repository | the key file, pinned by the repository variable `WEB_APPROVAL_KEYS_DIGEST` | No. No key file or digest is recorded in this repository. |
| [Build identity `trustRootDigest`](#build-identity-trustrootdigest) | digest field | none | the binary's build identity | `UNPINNED` |

Passphrase rules shared by the key creation commands (`knowledge-sign init` and
`release-sign init`): the passphrase is read from a terminal with echo disabled
and is at least 16 and at most 1024 bytes. The key file is a PKCS#8 Ed25519 key
in an `ENCRYPTED SIGSTORE PRIVATE KEY` PEM written with mode `0600` inside a
new `0700` directory whose parent is a private directory outside any Git
checkout. Signing with a human re-attestation key, a release key or a knowledge
role key also reads the passphrase at a terminal only. The one exception is the
unattended `automation` re-attestation role, described below.

Every digest used as a pin is `sha256:` and the lowercase hex SHA-256 of the
file, with the trailing newline removed for the re-attestation trust root and
the owner-approval key file. A pin must come from a source other than the file
it pins; a digest computed from the file you just received is not a pin.

## Knowledge package roles (root, targets, snapshot, timestamp)

**What they do.** Signed knowledge packages use four TUF roles. A package is
accepted by `prufyx db verify`, `db import` and `db update` only when its
metadata chain verifies from the operator's root, every role meets its
threshold, and nothing has expired. The client accepts only Ed25519 keys, lower
case 64-hex key IDs, four roles, a consistent snapshot and a threshold of at
least one that the role's key list can satisfy.

**Creating them.** `prufyx-maintainer knowledge-sign init` creates one
Ed25519 key per role (four keys), a self-signed `root.json` at version 1 and
four encrypted key files (`root.key.pem`, `targets.key.pem`, `snapshot.key.pem`,
`timestamp.key.pem`). Each role has threshold 1 in that root. The root expiry
must be exact UTC RFC3339, in the future and no more than 366 days ahead. A
multi-key root with a higher threshold can be authored by hand and is accepted
by the publisher and the client, but this repository has no command that
generates one. See [Offline operator role signer](knowledge-signer.md) and
[Offline CNCF knowledge publisher preparation](knowledge-publisher.md).

**Where the public part is pinned.** On the client. The first import into an
empty store needs the root file and its independently verified digest. The
store then records that initial root digest and refuses a different bootstrap
root for the same store. There is no Prufyx feed, official root or default root
(see [Explicit knowledge downloads](knowledge-updates.md)).

**Checks you can run.** `knowledge-sign verify-key` decrypts one key and
reports only whether its public key matches the chosen role in a root you
supplied. It does not prove backup health, custody or that the root is current.

**What users see (all procedures below).** `prufyx db status` reports one of
`NO_SELECTION`, `RECOVERY_REQUIRED`, `READY`, `EXPIRED`, `TRUST_ADVANCED` or
`INTEGRITY_FAILURE`, with a `nextAction`. Exit code 11 means no selection,
expired metadata or trust advanced beyond the selected admission, and 3 means
an integrity failure. `prufyx scan --knowledge-db` stops with exit 3 on any
verification failure and never falls back to the rules built into the binary.
A signed package cannot make an expired or unreviewed rule current: source
review expiry is separate from TUF freshness. See
[Inspect a local knowledge store](knowledge-status-adopter.md).

### Rotation

Routine rotation of any role is a root transition: a new root version that lists
the new keys.

1. `knowledge-publish prepare-root-transition` with the current root, its
   digest, a self-signed successor template and the template's digest.
   The successor version is the current version plus one.
2. Each required root key holder runs `knowledge-sign sign-root-transition`
   (`--authority trusted` for current-root keys, `--authority successor` for
   keys that are new in the successor). The signer reads the encrypted root key
   at a terminal.
3. `knowledge-publish finalize-root-transition` checks both thresholds: the
   current root's threshold and the successor root's threshold must each be met.
   A key listed in both roots contributes one signature that can count for each.
4. Sign fresh `targets`, `snapshot` and `timestamp` metadata under the new root
   and package them. Normal packages carry consecutive `N.root.json` members
   only for a rotation. For a store that starts from the original root, the
   publisher also provides `finalize-rotated-package` for one to eight
   contiguous successor roots, anchored to the independently pinned initial
   root. An already advanced store uses its normal update path.

The key lifetime is bounded by role expiry, not by a rotation timer. The
timestamp and snapshot roles are the short-lived ones in practice, because
each package needs fresh metadata; `knowledge-publish` takes the expiry of each
role from you. Choose short expiries for `timestamp` and `snapshot` and
rotate the keys when you change who holds them.

**What users see.** A client that imports the package with the new root
moves its store forward and `db status` shows the new root version. A client
that has not imported it keeps working on its retained revision until that
metadata expires, then reports `EXPIRED` (exit 11).

### Loss

- **A `targets`, `snapshot` or `timestamp` key is lost.** Nothing is wrong yet,
  but that role can no longer sign. If the role's threshold can still be met by
  the remaining keys, continue. Otherwise perform the rotation above, signing the
  root transition with the root keys, and publish new metadata.
- **The `root` keys are lost below the root threshold.** No successor root can
  be signed, because both the current and successor thresholds are required.
  Existing stores cannot be moved to a new root. The only recovery is a new
  root and a new, empty store directory, bootstrapped with a root and digest
  you distribute through an independent channel. Nothing in the code
  transfers trust between unrelated roots. Keep an encrypted offline copy of
  every private key and an independently held passphrase backup, as the
  [signer guide](knowledge-signer.md) says. The code does not prove custody or
  backup recovery.

**What users see.** The same as for expiry: a store whose metadata can no longer
be renewed reaches `EXPIRED` (exit 11) and scans that use it fail closed with
exit 3. A new root requires users to run a fresh bootstrap import.

### Compromise

There is no revocation list. The client learns a key is no longer trusted only by
importing a package whose root dropped it.

- **`targets`, `snapshot` or `timestamp` key.** The holder of such a key can
  sign metadata that clients accept until they import a root that no longer
  lists it. Rotate through a root transition immediately (it needs the
  uncompromised root keys), publish new metadata with a higher version, and tell
  users to import it. A store's retained rollback and clock floors still
  apply.
- **`root` keys at or above the root threshold.** The attacker can sign a
  successor root that clients accept. Rotation cannot repair this. Stop
  distributing the compromised root, publish a new root and digest through an
  independent channel, and have users bootstrap a new empty store.
- **Passphrase only.** The key file is still needed to use it. Treat the
  passphrase and the file as one secret, and rotate as above if the file may
  have been copied.

**What users see.** Until a user imports the replacement package, nothing
changes locally: the client cannot know. After import, `db status` shows the
new root version, and a package signed only by the old keys is rejected.

## Release statement key

**What it does.** `prufyx-maintainer release-sign init` creates one Ed25519
key and a single-key trust root (`release.key.pem` and
`release-trust-root.json`, threshold 1, at most 32 keys allowed by the
verifier). `release sign` signs a canonical release statement that binds the
version, source revision, source and manifest digests, build epoch, expiry, the
trust root digest, and the SHA-256 and size of every published asset. See
[Release provenance and local check evidence](signing-provenance.md).

**Where the public part is pinned.** Nowhere in the repository. The verifier
requires the trust root digest as an independent argument:
`release verify-signature VERSION OUTPUT_DIR TRUST_ROOT sha256:<digest>`. The
root and every statement expire in at most 366 days. A verified signature
proves integrity and signer identity only; the result always reports
`compatibilityAuthority: none`.

### Rotation

Run `release-sign init` again with a new key directory and a new expiry, sign
new releases with the new key, and publish the new root's digest through a channel
that is independent of the release assets. The old root verifies old statements
only while it and the statement are unexpired. There is no code that
re-signs an older release or chains the new root to the old one.

### Loss

Old statements keep verifying against the old root and digest until they expire.
You cannot sign new releases with the lost key: initialize a new key and root and
publish the new digest as above.

### Compromise

The verifier has no revocation list. It accepts any unexpired statement signed by
a key in the root you pin. After a compromise, stop pinning the old root digest,
initialize a new key and root, re-verify the affected release outputs from source,
sign them with the new key and publish the new digest. Users who still pin the old
digest continue to accept statements signed with the stolen key until those
statements or the old root expire.

**What users see.** `release verify-signature` fails closed on an unknown signer,
a substituted or expired trust root, an expired statement, a changed or missing
asset, or an unsigned file in the output directory. Users who pin a new digest
reject the old signatures; users who do not are not told.

## Artifact attestation

The release workflow (`.github/workflows/release.yml`) builds archives on
tag pushes matching `v*`, writes `SHA256SUMS` and creates GitHub artifact
provenance attestations. The project holds no private key for this: GitHub issues
a short-lived certificate to the workflow run (keyless signing). What a user verifies is the
repository, workflow file and source revision (`gh attestation verify`,
see [Release provenance](signing-provenance.md)), plus the checksum file.

There is nothing to rotate, lose or revoke in the repository. If the workflow
file or the repository identity changes, users must change the identity they pass
to `gh attestation verify`. A compromised repository or workflow can produce a
valid attestation for malicious content, so the independently reviewed source
commit is part of the check. No tagged release has been published, so there is
nothing yet for a user to verify.

## Re-attestation keys (human and automation)

**What they do.** `prufyx-maintainer evidence reattest` renews the review lease
(`reviewedAt` and `validUntil`) on a batch of rules in one signed statement. A
`human` key signs human-mode statements, at a terminal. An `automation` key signs
automated-mode statements, unattended. A statement is signed only by keys of its
own role. The trust root (`prufyx.io/evidence-reattestation-trust-root/v2`) lists
every key with its role, one threshold, an expiry and at most 32 keys; every role
it lists must have at least `threshold` keys. A version 1 root is still accepted
and makes all its keys `human`. See [Batch evidence re-attestation](evidence-reattestation.md).

**Where the public part is pinned.** The trust root file is meant to live at
`cli/knowledge/reattestation/trust-root.json`, and its digest in the repository
variable `REATTEST_TRUST_ROOT_DIGEST`, which the knowledge gate reads. Neither
is present in this repository: the code deliberately leaves
`ProductionTrustRootPath` unset and no trust root file is committed. The gate
accepts no statement unless that variable is set to the root's digest. The gate
reads the trust root from the base branch only.

**Creating keys.** This repository has no command that generates a `human` or
`automation` key. Any Ed25519 key in the encrypted PEM format the other signers
use works. `evidence reattest trust-root migrate` builds a root from public keys
only.

### Rotation

Use `trust-root migrate` with the current root and its pinned digest. It can add
`automation` keys (`--add-automation-key`, repeatable) and remove keys
(`--remove-key`, repeatable), keeps the threshold, can set a new `--expires`,
never adds a `human` key and never changes a kept key's role. It prints the new
digest. A new `human` key can only enter through a newly authored root. Change the
pin in the same place for `prepare`, `sign` and `verify`: update the repository
variable first, then merge the new file, as the gate requires.

Every chain entry is verified under the one root supplied, so a new root must keep
every key that signed an entry still in the chain, in the same role. `migrate` does
not stop you removing such a key; `prepare` and `verify` then reject the chain.
The code has no way to retire a key that signed a chain entry and keep that chain
verifiable.

### Loss

Losing a `human` key stops human-mode statements until the root is replaced with
one that lists a working key (and keeps the keys behind existing chain entries).
Losing the `automation` key stops automated renewals. A rule whose lease runs out
without a renewal evaluates as `UNKNOWN`. Nothing makes a rule safer when renewal
stops.

### Compromise

A stolen `automation` key is bounded, not harmless. It can sign a statement only
for reviewed (not mechanical), active rules without a version range that are due
within 21 days of lease end, under the two-cycle cap, for at most 90 days, whose
citations were reported unchanged on their own release line by the signing job's
`evidence repin` run. It cannot sign a human statement, reset a cycle count or renew
a rule a person last reviewed outside the chain. Because that worklist comes from
the signing job, the gate runs `evidence repin` itself in a separate job and
compares the result. If the key is exposed, review every statement it signed since the exposure. To
stop it signing, remove its key id with `trust-root migrate --remove-key`, update
`REATTEST_TRUST_ROOT_DIGEST` first and then merge the new root. Handle a `human`
key the same way. A removed key makes `prepare` and `verify` reject any chain entry
it signed (see Rotation), so the existing chain does not verify under the new root.
This is a limit of the current code, and the owner must decide how to handle it
before such a key is ever used for a real chain.

The automation key and its passphrase belong only to the one job that signs
automated statements, in an environment restricted to the protected branch.
`--key-env` and `--passphrase-env` exist but leave the secret visible to the rest of
the job; prefer `--key` and `--passphrase-file` with `0600` files.

**What users see.** Users do not see these keys. They see the effect of
renewals: a rule's evidence window and, when a lease expires without renewal, an
`UNKNOWN` answer for what that rule covers.

## Owner-approval key

**What it does.** The owner signs approval records (`prufyx.io/knowledge-approval/v2`)
that admit one exact reviewed rule entry in place of one exact base state. The
signature covers a domain prefix, a NUL byte and the compact record. The gate
accepts an approval only when the key is pinned and unexpired, the signature
verifies, the decision is `approve`, the identity is a pinned owner, the decision
is at most 14 days old and not in the future, and the candidate and base digests
match. Approvals never admit a mechanical rule.

**Where the public part is pinned.** The key file
`cli/knowledge/trust/web-approval-keys.json` (schema
`prufyx.io/web-approval-keys/v1`, role `web-approval`, a list of owners and keys
with a `notAfter` each), whose digest sits in the repository variable
`WEB_APPROVAL_KEYS_DIGEST`. Neither is recorded in this repository, and the gate
accepts no approval unless the variable is set to the file's digest.
The key ID is `sha256:` and the hex SHA-256 of the raw 32-byte public key.

### Rotation

Add the new public key to the key file with its own `notAfter`, update
`WEB_APPROVAL_KEYS_DIGEST` first, then merge the file. A person must make that
change and it must match the pin. The old key can stay until its `notAfter` or be
removed in the same change. An approval older than 14 days is not accepted
anyway.

### Loss

Approvals cannot be created until a key is pinned. Pin a replacement as above. No
rule is affected, because an approval admits a change only at the moment it is made.

### Compromise

An attacker could forge approvals for loosening changes that the gate accepts on
that path alone. Remove the key from the file, update the variable, merge, and then
review every rule admitted by an approval signed with that key. Every approval is
bound to the exact entry and base digest, so forged approvals can only admit the
entry they name, and none lasts beyond 14 days.

**What users see.** Nothing directly. Users see the rule changes that merged.

## Build identity `trustRootDigest`

Every build identity carries a `trustRootDigest`, either `sha256:<64 hex>` or
`UNPINNED`. The release workflow sets `UNPINNED` for every build, because the binary
is built before any statement that could pin a root exists. `UNPINNED` together with
`candidateOnly: true` means the binary makes no trust-root claim, and local reports
are not signed Prufyx compatibility evidence. Nothing to rotate until a release is
signed.

## Trust material in this repository

The knowledge gate treats these as trust material and reads them from the base
branch only:

- everything under `cli/knowledge/trust/`;
- the re-attestation trust root, `cli/knowledge/reattestation/trust-root.json`;
- any file named `trust-root*` or `*approval-keys*` anywhere.

A change touching trust material fails the `trust-material` check unless a
person (not the automation account) proposes it and the changed file is the trust
root or the approval key file and matches the digest pinned in its repository
variable. Other files under `cli/knowledge/trust/` cannot pass. `.github/CODEOWNERS`
additionally requires the code owner's review for the same paths, for the gate
and its supporting code, for dependencies, and for `.github/`.

The knowledge gate workflow also reads one secret, `OPS_ISSUES_TOKEN`, used only
to open alarm issues in a separate repository. It is an access token, not a signing
key, and it cannot sign or approve anything.

## Code owners and emergency access

`.github/CODEOWNERS` currently names one owner, `@airstand`, for trust material,
the gate and the kill switch (`factory/PAUSE`). Loss of that one account leaves no
person who can approve a change to trust material.

**Second emergency code owner: not yet named.** The project owner has not
named a second person yet, so this page names nobody. When the owner decides,
add that person's account to `.github/CODEOWNERS` for the trust-material entries and
record the change here.

## What this page does not cover

- Hardware-backed key custody. The signing keys are passphrase-encrypted local
  files. The code does not claim hardware custody, backup recovery or an official
  trust root.
- Any service key outside this repository.
- Reporting a suspected key compromise: see [SECURITY.md](../../SECURITY.md).
