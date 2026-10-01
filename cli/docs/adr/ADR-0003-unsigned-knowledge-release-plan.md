# ADR-0003: Treat release plans as unsigned routing and assertions

Status: Accepted

## Context

Community adopters can explicitly download and import a signed CNCF knowledge
package, but manually copying its URL, package digest, revision, target digest,
and role identities is error-prone. No official Prufyx feed, signing root,
bootstrap channel, key custody, or hosting authority has been selected.

The current importer also has stable canonical v1 pending and trust-receipt
records. Adding assertions to those records in place would change their bytes
and let old receipts appear to prove checks they never performed.

## Decision

Add the closed canonical `prufyx.io/knowledge-release-plan/v1` file for explicit
local CNCF updates. It binds one exact HTTPS URL and package digest plus target,
capability, one-root history, and verified TUF role identities. Its declared
authority is `UNSIGNED_ROUTING_AND_ASSERTIONS_NOT_TRUST`. It contains no root
bytes, credentials, local paths, issuer, or signature and cannot bootstrap a
client.

Publisher code creates a plan only from the package and verification receipt
returned by the same successful in-memory finalization. It never treats an
arbitrary saved receipt as proof. Output is ordered: create and synchronize the
package, then create and synchronize the plan. Success requires both durable
files. Failure while creating the second file retains the package and preserves
pre-existing files; the pair is not crash-atomic.

The client parses a local plan before reserving an output or fetching. Its
package digest is checked before any store change. Expected root history and
role values are compared with material produced by TUF verification. Expected
target purpose and capability are compared with semantic admission. A mismatch
cannot select a revision, although the receipt can truthfully report that valid
authenticated metadata advanced trust before a later assertion failed.

Manual imports continue to write byte-identical v1 pending and trust receipts.
Plan imports opt into v2 records with a required digest of the verification
assertions' compact JSON encoding. Package, revision, and target identities stay
separate in the pending transaction. A matching valid v1 selection is reverified and gets a new v2 receipt
rather than being invalidated or falsely described as assertion-verified.
Recovery and idempotent reuse require the exact v2 assertion digest. Manual
requests may reuse either valid receipt without gaining a new assertion claim.

Plan v1 supports the current single-root CNCF publisher. The initial root bound
by publisher verification is not client bootstrap authority. Root rotation uses
the existing manual update/import workflow.

## Consequences

The plan removes transcription risk without creating an automatic feed or trust
channel. Source-only proposals remain unreviewed and unadmitted, and an imported
rule's evaluation result does not authorize publication.

Older binaries fail closed after a plan import creates v2 records. Operators
must finish or recover that transaction with a plan-capable binary, or restore a
prior store backup before rolling back. Manual v1 stores remain compatible.
