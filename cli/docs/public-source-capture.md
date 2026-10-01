# Private public-source capture

`public-source-capture capture` is a maintainer-only intake command for retained
public source bytes. It takes a closed request file, fetches only its fixed
immutable GitHub blob paths, and creates private evidence for a later offline
corpus verification and independent source review. It is not a product CLI
command, knowledge updater, TUF target, crawler, rule evaluator, source
approval, or training workflow.

The checked-in [synthetic request](../examples/capture/synthetic-capture-request.json)
is a placeholder/schema illustration only. Executing capture with it still
attempts its derived public `raw.githubusercontent.com` request, usually ending
in a `404`; it is not an offline schema check. Never use a customer
configuration, credential, token, local installation path, or private source
in a request.

## Request and capture

The request schema is `prufyx.io/private-public-source-capture-request/v1`.
It has exactly `schema`, `revision`, `authority`, and `requests`; authority is
fixed to `DECLARED_PUBLIC_SOURCE_REQUESTS_NOT_RULE_OR_RUNTIME_PROOF`. A request
has a unique ID, declared project identity, declared source repository,
source kind/version, a canonical `github.com/.../blob/<40-commit>/<path>` URL,
its declared full SHA-256, ordered raw-LF span digests, and optional packet/rule
references. Project and source repositories may differ. Those identity,
version, packet, and rule fields remain declarations.

Prepare a private regular request file and private output parent. Both must be
owned by the invoking account, have no group/other permissions, and have no
symlink, FIFO, hard-link, or symlink ancestor. Relative paths are interpreted
from the physical working directory.

```sh
cd cli
chmod 600 PRIVATE-request.json
mkdir -m 700 PRIVATE-corpus-parent
go run ./cmd/prufyx-maintainer public-source-capture capture \
  --request PRIVATE-request.json --output-parent PRIVATE-corpus-parent
```

The transport is serial and always requests the derived
`https://raw.githubusercontent.com/<owner>/<repo>/<40-commit>/<path>` endpoint
with system TLS, fixed `Accept`, `Accept-Encoding: identity`, and User-Agent
headers. It has no proxy, cookies, auth, redirects, retries, GitHub API,
discovery, endpoint override, custom CA, model, shell, external binary, or
customer-data path. The fixed Go transport uses context-bound DNS, TLS, and
read deadlines and cannot execute caller code or commands. It bounds each
source, including DNS and slow body reads, to 30 seconds and enforces a
120-second aggregate network-capture budget. Preflight and local private-file
creation, writes, and `fsync` are outside that network budget.

At most 64 logical requests, 4 MiB per source, and 16 MiB of unique matching
bytes are admitted. Shared references to the same immutable URL make one
network request. Different immutable URLs are independently fetched even when
their declared hash is equal. A matching object's digest deduplicates only the
retained file and aggregate byte count.

The tool keeps all matching bytes in bounded memory until every request,
digest, and span succeeds. It then creates a new exclusive private child named
from the request digest, writes `objects/sha256`,
`CANDIDATE-CORPUS-MANIFEST.json`, and finally `CAPTURE-RECEIPT.json`. Existing
outputs are rejected and never changed. If an input, response, span, deadline,
or write fails, no completed corpus exists; the command returns 2 with a
canonical attempt receipt that omits response bodies, local paths, exception
text, redirect destinations, and invalid submitted text. A failure receipt has
`cleanup: "INCOMPLETE"` only if a locally created partial directory could not
be fully removed; it has no completion marker and must never be consumed.

A successful candidate is intentionally not authoritative. Verify it locally
with the [`source-corpus` verifier](source-corpus.md), then perform the
separate immutable-source review, scoped rule/vector decision if appropriate,
technical acceptance, and separate future signing/publication decision. Capture
does not establish upstream ownership, tag binding, licence, CNCF membership,
compatibility, runtime behavior, coverage, approval, signing, publication, or
training authorization.
