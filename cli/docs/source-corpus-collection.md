# Private source-corpus collections

`source-corpus verify-collection` is a maintainer-only, offline verifier for a
bounded collection of already retained public-source shards. It reads only
manifests and content-addressed objects named by a local collection index. It
does not fetch URLs, authenticate upstream ownership or tags, evaluate rules,
prove runtime behavior, sign or publish data, or create a client package.

Run it from `cli/` with a private collection root and an index path relative to
that root:

```sh
cd cli
umask 077
go run ./cmd/prufyx-maintainer source-corpus verify-collection \
  --root /private/prufyx/source-corpus \
  --index collection-index.json > /private/prufyx/collection-receipt.json
chmod 0600 /private/prufyx/collection-receipt.json
```

The verifier requires the root and every referenced directory to be owned by
the current user with mode `0700`, and every referenced index, manifest, and
object file to be a single-link regular file owned by the current user with
mode `0600`. It checks those properties on the descriptors used for reading,
opens descendants without following symlinks, and reads no unreferenced tree.
Keep the index itself inside the selected root. The command emits one compact
canonical JSON receipt to standard output and never writes a receipt path.
Errors are deliberately generic and do not echo local paths or source text.

## Collection index

The closed index has exactly `schema`, `revision`, `authority`, and `shards`.
The schema is `prufyx.io/private-source-corpus-collection/v1`; the authority is
`LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF`; and `shards` is a
lexically sorted list of one to 64 entries. Each entry has exactly
`manifestPath` and `objectRoot`, canonical ASCII relative POSIX paths of at
most 512 bytes and 16 segments. Paths cannot contain `..`, `.`, empty or
repeated separators, backslashes, absolute prefixes, links, or special files.

Each selected manifest is checked by the existing single-shard verifier. Its
limits remain 256 KiB, 64 records, 4 MiB per object, 16 MiB of unique bytes,
eight ordered spans, and one million source lines. Across the collection the
limits are 64 shards, 4096 records, 4096 unique objects, 64 MiB of deduplicated
object bytes, and a 1 MiB output receipt. Duplicate record IDs, duplicate
project/source/span identities, conflicting project repositories, or
conflicting source metadata are rejected. The same content-addressed object
may be referenced by multiple shards and counts once.

The receipt binds the canonical index digest, each shard's manifest digest,
the canonical per-shard receipt digest (the SHA-256 of that shard receipt
without its trailing output LF), selected paths, the recomputed
record/project/object counts, deduplicated byte length, and sorted object
digests. It contains no normalized source records or
retained source bytes. The receipt is a local integrity summary, not evidence
that the declared version, repository, release, license, or source URL is
correct.

## Synthetic two-shard walkthrough

The repository contains a deliberately non-authoritative two-shard fixture in
`examples/source-corpus-collection/`. To use it, copy it into a new private
root and tighten the modes; the checked-in example uses ordinary source-tree
modes so it can be reviewed and shipped:

```sh
cd cli
umask 077
root=$(mktemp -d /tmp/prufyx-collection.XXXXXX)
root=$(cd "$root" && pwd -P)
cp -R examples/source-corpus-collection/. "$root"/
find "$root" -type d -exec chmod 0700 {} +
find "$root" -type f -exec chmod 0600 {} +
go run ./cmd/prufyx-maintainer source-corpus verify-collection \
  --root "$root" --index collection-index.json
rm -rf "$root"
```

The two manifests deliberately use different synthetic project/source
identities while sharing one retained object, demonstrating collection-level
byte deduplication. This fixture is not an upstream source, compatibility
rule, or release claim.

For each shard, the single-shard `source-corpus` verifier contract remains
authoritative, including exact LF-split span hashing without a trailing
separator. The collection layer composes those verified receipts and adds only
bounded cross-shard identity and count checks.
