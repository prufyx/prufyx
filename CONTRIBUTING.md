# Contributing to Prufyx

Thank you for helping improve Prufyx. Spas Atanasov is the maintainer for this
release.

## Before you start

For a bug or a small documentation fix, open a focused pull request. For a new
compatibility claim, collection field, command, or larger change, open an issue
first so its evidence and data boundary can be reviewed.

Never submit credentials, Kubernetes Secrets, production snapshots, raw
customer objects, private configuration, sensitive logs, or source material
you do not have permission to redistribute. Examples and tests must use public
synthetic fixtures and label them as non-authoritative.

Compatibility work should state:

- the exact component versions, platform, deployment mode, and relevant
  configuration predicates;
- the immutable public sources and exact spans supporting the rule;
- what was reproduced, approximated, stubbed, or omitted;
- the expected `PASS`, `ATTENTION`, `BLOCKED`, or `UNKNOWN` behavior and a
  falsifiable test;
- whether collection, permissions, retained data, network access, or mutation
  authority changes.

`UNKNOWN` is a valid result. Do not turn absent, nearby, synthetic, or stale
evidence into a safety claim.

For a public upstream identity or transition proposal, use the closed offline
[evidence-packet workflow](cli/docs/upstream-contributions.md). A validation
receipt proves packet consistency only; it does not authenticate a reviewer,
verify an upstream source, authorize a rule, or publish data.

To propose a single deterministic compatibility rule — a source-pinned claim
that upgrading one already-tracked component under a specific condition will
break — see [contributing a rule](cli/docs/contributing-rules.md). It walks
through the rule schema, the evidence-pinning discipline, and the offline
`prufyx-maintainer rule validate` command that checks a candidate before you
open a pull request. That validator never publishes anything; a maintainer
still reviews and folds every accepted rule in by hand.

If you only want to suggest a useful public project, start with the
[public project source issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml).
One exact public GitHub repository URL is enough; you do not need to maintain
the project, choose exact versions, or calculate hashes. Maintainers can use the
[local onboarding workflow](cli/docs/project-onboarding.md) to produce a bounded
source-only snapshot and proposal. That proposal remains `NOT_REVIEWED` and
`NOT_ADMITTED` until a separate review, and it never adds an executable rule by
itself. Automatic sync currently requires a matching published GitHub Release;
the guide describes the explicit pinned-source fallback for tag-only and
changelog-only repositories.

## Develop locally

Use Go 1.26.8. Go dependencies are pinned in `cli/vendor`; use the vendored,
offline dependency set for every local check. From the repository root:

```sh
cd cli
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go test ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go vet ./...
CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' go build -trimpath -o ../prufyx ./cmd/prufyx-community
```

The CLI module declares `go 1.26.8`, which makes older toolchains fail. A Go
`toolchain` directive would only select a preferred version when toolchain
switching is permitted; `GOTOOLCHAIN=local` always uses the invoked Go
executable and does not validate that executable's patch release. Before an
offline check, use the explicit local gate:

```sh
cd cli
make toolchain-check GO=/absolute/path/to/go1.26.8/bin/go
```

Staticcheck is an opt-in local analysis gate. It is not part of the ordinary
offline build, and it never downloads a tool. Provision a pinned binary outside
the checkout using Staticcheck 2026.2.1 (which supports Go 1.27 and therefore
the supported Go 1.26.8 toolchain), verify its published SHA-256 sidecar:

```sh
mkdir -p /private/tmp/prufyx-staticcheck && cd /private/tmp/prufyx-staticcheck
curl -fsSLO https://github.com/dominikh/go-tools/releases/download/2026.2.1/staticcheck_darwin_arm64.tar.gz
curl -fsSLO https://github.com/dominikh/go-tools/releases/download/2026.2.1/staticcheck_darwin_arm64.tar.gz.sha256
shasum -a 256 -c staticcheck_darwin_arm64.tar.gz.sha256
tar -xzf staticcheck_darwin_arm64.tar.gz
```

Use the matching release asset for another host. `make staticcheck` runs the
correctness-focused `SA*` checks, including `SA4006`, for ordinary and
`parityreview` package variants offline. Use `make staticcheck-full` to run
Staticcheck's complete default check set:

```sh
cd cli
make staticcheck GO=/absolute/path/to/go1.26.8/bin/go \
  STATICCHECK=/absolute/path/to/staticcheck
make staticcheck-full GO=/absolute/path/to/go1.26.8/bin/go \
  STATICCHECK=/absolute/path/to/staticcheck
```


Run relevant race tests on a native supported host with a C toolchain using
`CGO_ENABLED=1 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go test -race ./...`.
Published binaries use `CGO_ENABLED=0`.
Collector tests use synthetic local input and the native Go implementation; they
do not require a cluster or separate Python or jq runtimes. Follow the exact
staged-source instructions in
[the source gate](cli/release/COMMUNITY-SOURCE-GATE.md).

Keep changes focused. Add a regression test when behavior changes, and include
the exact commands and outcomes in the pull request description. Changes to
collection fields need a compatibility-predicate justification and disclosure
review.

## Licenses and the Contributor License Agreement

Prufyx source code is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE). Reviewed knowledge data
(rules, evidence records, review records, attestations) is licensed under
[CC BY-SA 4.0](DATA-LICENSE.md).

Before a pull request can be reviewed, every author must sign the
[Prufyx Contributor License Agreement](CLA.md). You keep the copyright in your
work; the agreement lets the maintainer distribute it under the project's
licenses, including future licensing of the project. The CLA check comments on
your first pull request; reply with the sentence it asks for. You sign once.

Every commit must be authored by an email address linked to your GitHub
account, so the check can match it to your signature.

## Branches and merges

Every change, including the maintainer's, goes on a topic branch and reaches
`main` through a pull request merged with a merge commit. Fast-forward, squash
and rebase merges, direct pushes to `main`, force pushes and branch deletion are
refused by the repository ruleset for everyone. A pull request merges only when
the `CI` and `Merge policy` checks pass on a branch that is up to date with
`main`.

## Review

The maintainer may ask for narrower scope, clearer evidence, a data-boundary
review, or a reproducible test. A contribution is merged only after its tests,
license, provenance, security, and product-truth checks pass.
