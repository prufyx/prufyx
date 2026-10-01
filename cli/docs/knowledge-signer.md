# Offline operator role signer

`prufyx-maintainer knowledge-sign` is a local, offline helper for one operator.
It creates four encrypted Ed25519 role keys and signs the exact canonical
payload prepared for one `targets`, `snapshot`, or `timestamp` role. It never
fetches, publishes, uploads a key, configures a feed, or activates a root.

Initialize only in a new absolute `0700` directory outside any Git checkout. The expiry must be exact UTC RFC3339, future, and no more than 366 days ahead.
The command reads the passphrase twice from a terminal with echo disabled; it
accepts no passphrase flag, environment variable, file, default, or redirected
standard input.

```sh
umask 077
mkdir -m 700 /absolute/operator-private
prufyx-maintainer knowledge-sign init \
  --key-dir /absolute/operator-private/prufyx-keys \
  --root-expires 2027-09-12T00:00:00Z
```

Initialization writes `root.json` and four mode-`0600` encrypted key files:
`root.key.pem`, `targets.key.pem`, `snapshot.key.pem`, and `timestamp.key.pem`.
Each is a PKCS#8 key wrapped in `ENCRYPTED SIGSTORE PRIVATE KEY` PEM using the
vendored scrypt and secretbox implementation with the `encrypted.OWASP` KDF
parameters. The code makes a best effort to overwrite its own temporary
passphrase and key byte slices; Go does not provide a general memory-erasure
guarantee.

Keep an encrypted copy of the private key directory and an independently held
passphrase backup outside Git. Move `root.key.pem` offline after initialization.
This helper does not prove custody, backup recovery, rotation, revocation, or
an official trust root.

Check one restored encrypted key against an independently pinned public root
before using it. This reads the passphrase once from a terminal with echo
disabled and writes no key, signature, package, or trust-store file:

```sh
prufyx-maintainer knowledge-sign verify-key \
  --root /absolute/operator-private/prufyx-keys/root.json \
  --root-digest sha256:<independently-verified-root-digest> \
  --role targets \
  --key /absolute/restored-private/targets.key.pem
```

`verify-key` accepts one owner-owned, single-link `0600` encrypted PEM and one
of `root`, `targets`, `snapshot`, or `timestamp`. Its
`prufyx.io/local-tuf-key-verification/v1` JSON receipt reports only
that the decrypted public key matches the selected role in the supplied root.
It does not assess role threshold readiness or root expiry, prove custody or
backup health, activate trust, authorize an update, sign a payload, or contact
a network. A cryptographic key-role match against an expired root is therefore
not current trust and cannot permit an update. The helper makes a best effort to
overwrite temporary passphrase and decrypted-key byte slices; Go does not offer
a general memory-erasure guarantee.

Sign one publisher-prepared role with the matching role key. All paths are
absolute. The root digest and payload digest come from an independently checked
publisher request; the signer derives the payload again from the exact unsigned
role and rejects a mismatch before writing a new signature envelope.

```sh
prufyx-maintainer knowledge-sign sign-role \
  --root /absolute/operator-private/prufyx-keys/root.json \
  --root-digest sha256:<root> --role targets \
  --unsigned /absolute/publisher/targets-step/targets.unsigned.json \
  --payload-digest sha256:<payload> \
  --key /absolute/operator-private/prufyx-keys/targets.key.pem \
  --output /absolute/publisher/targets-signatures.json
```

The key must be a single-link, owner-owned regular `0600` file. The envelope output must be a new absolute name below a physical, owner-owned `0700` directory outside a Git checkout. Plaintext PEM,
extra PEM data, a wrong role key, wrong passphrase, modified unsigned metadata,
wrong root digest, or an unauthorized role key are rejected. The signer calls
the publisher role finalizer before producing the envelope, so root policy,
role authorization, threshold, and exact payload binding are checked locally.

Outputs are new `0600` files. A failed write leaves any newly created path for
explicit operator cleanup; the helper never deletes an output path after a
failure. A valid signature envelope is still not a published package or a
configured update source.

## Root-transition contribution

`sign-root-transition` is separate from `sign-role`; `sign-role` continues to
reject the root role. The command requires the exact current root and exact
self-signed successor template with their pinned digests, plus the prepared
unsigned successor, request and canonical payload digest. It reads an encrypted
root key and the passphrase only through the existing terminal-only path. The
returned envelope is one contribution, never threshold readiness, authorization,
or a finalized transition.

```sh
prufyx-maintainer knowledge-sign sign-root-transition \
  --trusted-root /absolute/current-root.json --trusted-root-digest sha256:<current> \
  --successor-template /absolute/proposed-root.json --successor-template-digest sha256:<template> \
  --unsigned /absolute/publisher/root-transition-step/root.unsigned.json \
  --request /absolute/publisher/root-transition-step/root.request.json \
  --payload-digest sha256:<payload> --authority trusted \
  --key /absolute/operator-private/root.key.pem \
  --output /absolute/publisher/root-old-signature.json
```
