# Community source gate

`community-shipping-policy-v2.json` is the human-maintained authority for the
Community source package. The Go `release-gate` command derives a
content-addressed manifest from that policy and the selected source tree.
Historical manifests are records; they do not authorize files in a new package.

The v2 policy admits the reviewed vendored dependency profile and binds module
versions, `go.sum`, vendor paths, modes, lengths, SHA-256 digests, required
notice copies, binary vendor resources, public documentation, examples, legal
notices, release tooling, local collection tools, offline tests, fixtures, and
their in-module closure. The older v1 policy remains available for its narrower
contract. Generate captures the current selected first-party bytes. The exact
vendored closure, shipping policy, and captured module inputs must match their
reviewed bindings; the gate also checks declared vendored license and notice
identities. Verify and Stage reject selected bytes or modes that differ from the
retained manifest. Private-key blocks are rejected. The final captured policy,
vendor manifest, and module metadata are rebound, closing changes between
validation and staging.
The gate opens files without following symlinks and requires regular,
single-link files within its size bounds.

The selected production entrypoint is `./cmd/prufyx-community`. The source
closure includes architecture-specific Go files and embedded contracts. Direct
tests, tagged parity tests, test data, and module metadata are selected by the
policy; every selected production package must have direct test coverage. The
v2 policy permits Linux `amd64` and `arm64` release targets and Darwin `arm64`
source-build coverage for the supported development host. A source-build tuple
does not create a binary-release claim. Go archive identities are policy data
that the release environment verifies before a declared build.

Build and gate commands use vendored modules with module download and checksum
services disabled. From the repository root, use Go 1.26.8 and write the
manifest outside the checkout:

```sh
set -eu
umask 077
export GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off
(cd cli && go run ./cmd/prufyx-maintainer release-gate generate \
    --source-root .. \
    --policy release/community-shipping-policy-v2.json \
    --go "$(command -v go)" \
    --output /tmp/prufyx-source-manifest.json)
```

Supply the absolute path to the verified Go 1.26.8 executable with `--go` when
`command -v go` does not resolve to that toolchain. The output path must be
new and outside the source root. The command does not download modules or
execute user-supplied project code.

Verify a retained manifest and stage an exact source tree with new output
paths:

```sh
set -eu
export GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off
(cd cli && go run ./cmd/prufyx-maintainer release-gate verify \
    --source-root .. --policy release/community-shipping-policy-v2.json \
    --go "$(command -v go)" --manifest /tmp/prufyx-source-manifest.json)
(cd cli && go run ./cmd/prufyx-maintainer release-gate stage \
    --source-root .. --policy release/community-shipping-policy-v2.json \
    --go "$(command -v go)" --manifest /tmp/prufyx-source-manifest.json \
    --output /tmp/prufyx-source-stage)
```

`stage --run-native-checks` additionally runs the declared Go vet, ordinary and
tagged tests, and Linux `buildTargets` in the staged tree. Darwin
`sourceBuildTargets` selects source closure only; it is not a native release
build. Those checks are separate from source selection. A skipped
or unavailable native check is not evidence that a package is offline or
release-ready.

## What this preview does not claim

The repository contains staging and publisher helpers as retained, fail-closed
reference code. They are not an active hosted release path for this preview.
There is no active hosted CI, public binary feed, release tag, or automatic
publication claim here. A future release owner would need a separately
reviewed environment, exact source manifest, build outputs, checksums, and
provenance before publishing anything.

The source gate itself does not create a tag, release, feed, hosted service,
or attestation. It does not grant a trust root to the knowledge database. The
source manifest proves the selected local bytes match policy; it does not prove
runtime compatibility, cluster behavior, upstream endorsement, or the absence
of every possible secret outside its bounded checks.

The full release policy and [signing provenance guide](../docs/signing-provenance.md)
are the references for any later release decision. Keep generated manifests,
staged trees, and receipts outside the source root when using the local gate,
and preserve their exact digests with the review record.
