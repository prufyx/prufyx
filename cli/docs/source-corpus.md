# Retained public-source corpus

This is an offline verifier for a private evidence corpus of public upstream
source bytes. It retains exact bytes for repeatable review across projects. It
is not a changelog downloader, a client knowledge package, a source of
compatibility authority, or a training dataset.

The `source-corpus` maintainer command is implemented in Go. It never fetches a
URL, starts a subprocess, invokes a model, evaluates a customer change, signs
data, or publishes a rule or package.

```sh
cd cli
go run ./cmd/prufyx-maintainer source-corpus verify \
  --manifest examples/corpus/synthetic-corpus.json \
  --object-root examples/corpus/objects
```

The synthetic example is deliberately non-authoritative. Production retained
objects belong in a separately access-controlled evidence corpus, never in a
client archive, TUF target, or this repository's shipped rule data.

## Closed v1 manifest

A `prufyx.io/public-source-corpus/v1` manifest has exactly `schema`,
`revision`, `authority`, and `records`. Its authority is fixed to
`DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF`.

Every record has exactly:

- `id`;
- `project`: a public project slug and its catalogue-facing canonical GitHub
  repository URL;
- `source`: the public source repository URL, finite source kind, exact release
  version or `reference_only`, a 40-character commit, exact GitHub
  `blob/<commit>/<path>` URL, SHA-256, byte length, and ordered line-span
  digests;
- `capture`: UTC capture time and an exact `sha256/<digest>` relative object
  name; and
- `declarations`: optional packet digest and rule IDs.

The project repository and source repository are intentionally separate. A
project may cite an official document in another repository. The verifier only
checks the declared source URL against the declared source repository; it does
not prove ownership, upstream identity, release tags, or provenance.

Objects are regular no-follow files under `OBJECT_ROOT/sha256/<digest>`. The verifier opens the supplied manifest and every object-root path component descriptor-by-descriptor from filesystem root, rejecting symlink ancestors and final symlinks. Relative paths are interpreted from the physical current working directory; callers under a platform alias such as `/var` must pass the corresponding physical path. The
verifier limits a manifest to 256 KiB, 64 records, 4 MiB per object, 16 MiB of
unique retained bytes, eight non-overlapping spans per record, and one million LF-split source lines per object. It rejects
links, FIFOs, changing files, duplicate record IDs, exact duplicate
project/source/span references, malformed JSON, unsafe URLs, mismatched
hashes/lengths, and span digests that do not match the retained bytes. A span digest is the
SHA-256 of the exact selected LF-split lines joined with LF, without a separator
after the last selected line. It preserves tabs and carriage returns; verification
does not decode, normalize, or require UTF-8 source bytes. A final LF creates a final empty line component; a source without a final LF does not. A shared public blob
may be referenced by more than one project or rule; its metadata
must stay consistent and it counts once against the aggregate byte limit.

`reference_only` means the document is declared context rather than a claimed
release endpoint. It does not prove a tag binding or source ownership.

## Receipt and workflow

`verify` prints canonical `prufyx.io/public-source-corpus-receipt/v1` JSON to
standard output only. The caller may retain that output under its own evidence
policy; the verifier does not create or overwrite receipt paths. The receipt
binds the canonical manifest and each verified local object but is limited to
`VERIFIED_RETAINED_BYTES`.

Packet digests, rule IDs, project identity, source metadata, capture times, and
license context are declarations. A successful receipt does not admit a
catalogue identity, prove CNCF membership, authenticate a contributor,
independently verify an upstream fetch or tag-to-commit binding, establish
license terms, add source/rule/configuration/test coverage, reproduce runtime
behavior, authorize signing, or publish a knowledge package.

The next workflow step is a separate independent primary-source review that
checks the immutable endpoint and retained bytes, then a bounded rule/vector or
source-only decision as appropriate. Technical acceptance and any future
signed-data publication remain separate actions.
