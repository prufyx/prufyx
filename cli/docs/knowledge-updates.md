# Explicit knowledge downloads

This unreleased Community source capability downloads a complete signed package
from an operator-selected HTTPS URL, retains it locally, and imports it through
the existing TUF verifier. Checks and historical replay continue to run offline.
There is no configured Prufyx feed, official trust root, startup refresh, account,
telemetry, or upload API. The Community source preview is public. Official
metadata packages and a Prufyx trust root are not yet published.

## Download and verify

Obtain the initial public TUF root and verify its digest through your own trusted
process, independently of the package endpoint. HTTPS authenticates a transport
endpoint; it cannot choose the package's trust anchor.

Before importing a retained package, inspect it offline without creating or
reading a knowledge store:

```sh
prufyx db verify ./packages/first.tar --profile cncf \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest> \
  --expected-package-digest sha256:<expected-package-digest> \
  --expected-revision 1 --expected-bundle-digest sha256:<expected-target-digest> \
  --format json
```

`db verify` always requires a root and digest obtained through an independent
trusted process. Calculating the digest of a root received with the untrusted
package does not make that root trusted. Verification authenticates the package,
checks current TUF expiry and fixed semantic admission, and reports exact
identities. It uses no store and therefore does not check a retained rollback
floor, replay against previous imports, current selection or import eligibility.
Import re-verifies the package and can still reject it if trust or time has
advanced. Verification is not a configuration or upgrade result.

Use an existing private `0700` directory for retained packages, separate from the
store. `--package-out` must be a new filename and is created with mode `0600`.
The illustrative URL below is a placeholder, not a Prufyx service.

```sh
umask 077
mkdir -m 700 packages
prufyx db update --profile cncf \
  --source https://metadata.example.org/knowledge.tar \
  --package-out ./packages/first.tar --db-root ./cncf-store \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest> \
  --format json
prufyx db status --profile cncf --db-root ./cncf-store --format json
prufyx check cncf --project kyverno --input ./kyverno-input.json \
  --knowledge-db ./cncf-store --format json
```

For the CNCF publisher path, a local canonical release plan can replace manual
transcription of the URL, package digest, revision, target digest, capability,
and verified TUF role identities:

```sh
prufyx db update --release-plan ./cncf-1.release-plan.json \
  --package-out ./packages/cncf-1.tar --db-root ./cncf-store \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest> \
  --format json
```

`prufyx.io/knowledge-release-plan/v1` is an unsigned, closed canonical JSON
routing and assertion file. It supports only profile `cncf`, the fixed
`knowledge/constraints.v1.json` target, and one unrotated publisher root. Its
authority value is `UNSIGNED_ROUTING_AND_ASSERTIONS_NOT_TRUST`. The plan has no
root bytes, credentials, local configuration, issuer, or signature and cannot
authorize bootstrap. An empty store still requires the independently obtained
root path and digest shown above. An initialized store uses its retained trust;
omit bootstrap flags on later updates. Rotated root histories continue through
the existing manual import/update path.

Plan mode is mutually exclusive with `--source`, `--profile`,
`--expected-revision`, and `--expected-bundle-digest`. The plan is read locally
before an output is reserved or a fetch begins. Its package digest is checked
before the store is opened. Its root history, role identities and expiries are
compared with material actually authenticated by TUF, and its target purpose and
capability are compared after semantic admission. A later assertion mismatch can
advance authenticated trust, but cannot select the mismatched revision; the
failure receipt reports trust and selection separately.

Provide a private minimized input as described in the [CNCF guide](CNCF-SOURCE-PREVIEW.md).
Select the updated store explicitly with `--knowledge-db`. Updating a store
does not change the embedded rules or the default selection used without that flag.
Use `prufyx db status --profile cncf --db-root ./cncf-store` to inspect the
selected store; the status command does not import packages or change the
selection, but it advances the existing local clock floor after a successful
clock check. The status fields distinguish authenticated TUF metadata freshness
from source-review freshness. A selected pack with a future earliest source
expiry is `not_expired`; a past earliest expiry is `some_or_all_expired` because
the receipt summary cannot establish that every rule is expired. `not_expired`
does not establish that the source is currently reviewed or usable. `READY` means the
selected store passed its local integrity checks and does not make every rule
usable or every claim known.

For the next update, use a new package filename and omit the bootstrap flags.
Keep the same profile and store so that trust history and rollback protection
remain effective. Optional `--expected-revision` and `--expected-bundle-digest`
assert the semantic revision and target digest; they are checked locally.
The default profile is `cert-manager`; it requires a separate store and a
package containing its fixed target. A URL must return a complete canonical
package directly; release URLs that redirect are rejected. Closed targets use
USTAR except for the CloudEvents profile's deterministic GNU LongLink target.

There is one bounded GET, with no retries, redirects, cookies, authorization,
environment proxy, or compression. Only absolute HTTPS URLs without credentials,
queries, fragments, whitespace, or percent escapes are admitted, up to 4096 bytes.
TLS uses the
system trust configuration. Transfer has a 30-second total deadline and a 4 MiB
body limit. Nothing runs automatically when a check, replay, help or version
command starts. For an offline environment, transfer the package separately and
use `db import`.

## Privacy and failure behavior

The downloader accepts only the explicit URL and cancellation context. It
receives no configuration, component/version selections, input hashes, local
paths, report, cluster credentials, or installation identifier. The request
method, path and fixed headers are independent of evaluated inputs. The host
still sees ordinary connection information, including IP address and timing.
Choose a public-data package URL; text you put into that URL is sent to its host.

Update JSON records whether a network operation was attempted, whether transfer
completed, the downloaded package's SHA-256 and the separate import receipt or
rejection. It does not include the URL, local paths, raw remote errors or bodies.
A download is not a compatibility result. `synthetic_test_only` and
operator-provisioned trust remain visible in imported knowledge and reports.

Transport failure does not invoke the importer or modify the store. Normal
transfer/write failure removes the incomplete output; interruption can leave an
untrusted partial file. If cleanup fails, `partialCleanupRequired` explicitly
requests local inspection. A changed or replaced retained file causes an
integrity failure; any completed import receipt still reports actual selection
changes. The importer pins the fetched archive digest and verifies the same
in-memory bytes throughout its transaction. Existing files are never overwritten. A fully retained
package remains available even when import rejects it. Preserve that exact file
and use **`db import`** for recovery, with the original assertions and bootstrap
arguments when the rejection requires them. Fetching a mutable URL again cannot
guarantee the same bytes.

Verified metadata can advance durable trust before semantic admission rejects a
target. The rejection reports this separately from selection changes. Follow
the [shared recovery contract](knowledge-database.md); do not edit store files
or reset rollback floors. A failed update does not authorize a stale selected
revision for current checks. Source review expiry remains independent of freshly
signed TUF metadata. New fact types and engine behavior still require a binary
release. For a newly reviewed exact pair, a data-only rule over existing canonical
facts can use the current binary when those facts are declared manually. Optional
`prepare cncf` adapters support only documented pairs, so extending raw-input
preparation can require a CLI update even without a new fact type.

Manual imports retain the existing v1 pending and trust-receipt bytes. A plan
import opts into v2 records that bind a digest of its verified assertions. If a
valid selection was originally imported manually, a plan for the same exact
revision re-verifies it and creates an assertion-bound v2 receipt; it does not
claim the old receipt checked the plan. Recovery requires the same plan
assertions. Older binaries fail closed on these opt-in v2 records, so finish or
recover a plan transaction with a plan-capable binary before rolling back, or
restore a prior local store backup.

`expectedVerificationAssertionsDigest` is the SHA-256 of the compact JSON
encoding returned by the typed plan's `VerificationAssertions`; package,
revision, and target digests remain separate pending-record fields. This digest
is a recovery consistency identity and does not authenticate the plan.

## Prepare a signed package

The offline maintainer workflow is implemented, but no official Prufyx root or
feed is configured. From the `cli` directory, export the complete compatible
CNCF replacement target:

```sh
go run ./cmd/prufyx-maintainer export-knowledge \
  --profile cncf --revision 1 --output /absolute/constraints.v1.json
```

Then follow the [publisher preparation and finalization
workflow](knowledge-publisher.md). It emits exact sequential targets, snapshot,
and timestamp payloads, accepts signature envelopes, and verifies the complete
package through the existing consumer verifier. The [offline signer
workflow](knowledge-signer.md) can initialize four encrypted role keys and sign
those exact payloads for a single operator; key custody, root bootstrap,
hosting, and publication remain separate operator gates. The [export
contract](knowledge-export.md) and `db capabilities --profile cncf` describe
the target shape accepted by the matching binary.

The older `package-knowledge` helper can still assemble an
operator-prepared tree of signed metadata and content-addressed target bytes
into the bounded canonical archive. It does not sign, validate signatures,
change review dates, or establish that source rules are correct.

The existing [contributor workflow](upstream-contributions.md#workflow-and-authority)
names maintainer Spas Atanasov (`@airstand`) for maintainer acceptance and
publication review. Production key custody, root distribution,
reviewed rule publication and hosted feed operation remain separate release gates.
Existing examples use ephemeral
test keys and synthetic review dates solely to exercise the protocol; they are
not evidence of a production feed or a comprehensive release-note corpus.
