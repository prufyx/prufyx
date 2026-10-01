# Offline cert-manager knowledge database

This guide describes the default `cert-manager` profile. Generic CNCF rules use
the separate [CNCF knowledge profile](cncf-knowledge-database.md) and must have
their own store directory. `db import` and `db status` default to cert-manager;
pass `--profile cncf` explicitly for the generic store.

The knowledge database is an unreleased, explicit opt-in path for evaluating the same bounded cert-manager predicate with operator-provisioned signed data. The default `prufyx check cert-manager-values` behavior remains the embedded alpha release behavior. Prometheus mode continues to use its embedded reviewed knowledge.

`prufyx db verify` can authenticate and semantically inspect a local package
against an explicit bootstrap root without using a store. `prufyx db import`
performs its own verification and selects data into a store; later imports use
stored root history and rollback floors. Both commands are offline. A
self-computed SHA-256 is not trust: the initial root digest must pin the exact
operator-provisioned public root obtained through an independent trusted
process. This slice does not ship an official Prufyx root or official
downloadable database.

The separate [`db update`](knowledge-updates.md) command can explicitly download
a complete package from an operator-selected HTTPS source before the same local
verification. It retains the original package for offline import and recovery.

The selected bundle is complete for its declared capability. A complete bundle may contain zero rules, which yields `UNKNOWN`. If an external selection is requested and is missing, stale, withdrawn, malformed, or fails integrity checks, the command never falls back to embedded cert-manager knowledge and never mixes rules across revisions.

Current checks use the actual local UTC clock for TUF metadata and rule-evidence freshness. There is no public option to backdate a current check. Historical replay requires the exact prior revision, bundle digest, trust-receipt digest, values digest, and original report. Its wrapper states that current non-revocation was not checked; the contained original current report must reproduce byte for byte.

If `db status` reports `RECOVERY_REQUIRED`, retry the exact original signed
package with the same expected revision, bundle digest, and bootstrap assertions
used by the interrupted import. The journal binds that package identity. Losing
the package cannot be repaired by resetting or substituting trust state; restore
the exact package from the operator's own retained copy before continuing.

The first engine capability can select, subset, or withdraw only these compiled paths:

- `prometheus.servicemonitor.path`
- `prometheus.servicemonitor.targetPort`
- `prometheus.podmonitor.path`

A database update cannot add a fourth inspected path without a new engine release. The values reader keeps only the input digest, whether the relevant shapes resolved, and matching curated path names. It does not retain raw keys outside the compiled set, values, filenames, or local paths. Reports bind the exact bundle, rule, trust receipt, evaluation time, evidence freshness, and binary build identity.

For a complete local demonstration, run `prufyx community-preview example knowledge-cert-manager` (the retained [`examples/community/knowledge/run.sh`](../examples/community/knowledge/run.sh) is a compatibility shim). The example uses visibly synthetic knowledge and ephemeral keys; it is not a production signer or compatibility authority.

The commands below show the explicit interface. Values files and the database directory must satisfy the private local-file modes described by the CLI. Digests and revisions come from the fixture manifest or an independently reviewed operator package; they are assertions, not substitutes for TUF verification.

```sh
prufyx db verify ./synthetic-revision-1.tar \
  --bootstrap-root ./synthetic-root.json \
  --bootstrap-root-digest "$ROOT_SHA256" \
  --expected-package-digest "$REVISION_1_PACKAGE_SHA256" \
  --expected-revision 1 \
  --expected-bundle-digest "$REVISION_1_BUNDLE_SHA256" \
  --format json

prufyx db import ./synthetic-revision-1.tar \
  --db-root "$DB_ROOT" \
  --bootstrap-root ./synthetic-root.json \
  --bootstrap-root-digest "$ROOT_SHA256" \
  --expected-revision 1 \
  --expected-bundle-digest "$REVISION_1_BUNDLE_SHA256" \
  --format json > ./import-1.json

prufyx db status --db-root "$DB_ROOT" --format json

prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 \
  --values "$VALUES_FILE" --values-digest "$VALUES_SHA256" \
  --knowledge-db "$DB_ROOT" \
  --knowledge-revision 1 \
  --knowledge-bundle-digest "$REVISION_1_BUNDLE_SHA256" \
  --knowledge-trust-receipt-digest "$REVISION_1_TRUST_RECEIPT_SHA256" \
  --format json > ./revision-1-report.json

prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 \
  --values "$VALUES_FILE" --values-digest "$VALUES_SHA256" \
  --knowledge-db "$DB_ROOT" \
  --knowledge-revision 1 \
  --knowledge-bundle-digest "$REVISION_1_BUNDLE_SHA256" \
  --knowledge-trust-receipt-digest "$REVISION_1_TRUST_RECEIPT_SHA256" \
  --replay-receipt ./revision-1-report.json \
  --format json
```

The `VERIFIED` receipt reports exact authenticated identities and explicitly
sets `storeUsed` and `storeChanged` to false,
`rollbackAgainstStoreChecked` to false, and `importEligibility` to
`NOT_EVALUATED`. Verification does not detect replay against a retained store,
advance a clock floor, promise a later import, or evaluate user configuration.

The supported package profile is deliberately narrow:

- An import is an uncompressed canonical archive, at most 4 MiB, with at most 16 regular files, at most 1 MiB per file, and at most 2 MiB total member data. Members are sorted by name and have mode 0644, uid/gid 0, empty owner names, and Unix epoch timestamps. Closed targets use USTAR; the CloudEvents profile's longer fixed target basename uses the deterministic GNU LongLink form emitted by the shipped assembler and Go writer. Directories, links, devices, PAX records, duplicate paths, and trailing bytes are rejected.
- The archive contains `metadata/timestamp.json`, versioned `metadata/N.snapshot.json` and `metadata/N.targets.json`, and exactly one consistent-snapshot target fixed by the selected package profile. Consecutive `metadata/N.root.json` members are admitted only for TUF root rotation. Targets for other profiles and all other paths are rejected.
- The root has exactly the four TUF top-level roles, uses Ed25519 keys and lowercase 64-hex key IDs, enables consistent snapshots, and satisfies each declared threshold. Delegated targets and target custom metadata are not supported. Timestamp and snapshot each describe exactly the next required role; targets describes exactly the selected profile's fixed knowledge target.
- For `cert-manager`, that target is strict canonical JSON under the `prufyx.io/community-knowledge-bundle/v1` schema. `rules` must be an explicit array. An empty array is complete zero coverage and evaluates to `UNKNOWN`; missing, null, partial, case-aliased, duplicate, over-bounded, or unknown fields are integrity failures. The `cncf`, `spiffe-x509-svid`, `cloudevents-structured-json`, and `tikv-gcp-v2-wif-backup` profiles enforce their own closed target schemas and semantics.
- Revisions are canonical positive decimal ordinals up to 2147483647. In the cert-manager profile, each rule binds its capability, exact chart identities, a sorted subset of the three compiled paths, replacement facts, immutable source declarations, and independently expiring evidence. TUF metadata freshness and profile evidence freshness are evaluated separately.

The archive and JSON limits above apply to each import. This slice has no
automatic garbage collection or configured total database-size cap; operators
must account for retained metadata and revisions when managing local storage.

The explicit `db update` path downloads and verifies a selected package before
import. Production publishing and signing, an official feed, and official trust-root
distribution remain separate responsibilities. The synthetic generator creates
freshness times solely to exercise the local protocol.

The scoped exits are 0 for `PASS`, 10 for profile-scoped `BLOCKED` or `FAIL` as
appropriate, 11 for `UNKNOWN`, 2 for invalid invocation or input admission, and 3
for integrity failure. `prufyx db status` uses 11 for no selection, expired metadata,
or trust advanced beyond the selected admission, and 3 for selected-state integrity
failure in both JSON and human formats.
