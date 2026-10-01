# Optional signed CNCF knowledge

This unreleased source capability selects generic CNCF constraints from a
separate, explicitly named local knowledge store. For a newly reviewed exact
version pair, the same binary can evaluate a new signed rule revision over
existing canonical facts when those facts are declared manually. Optional
`prepare cncf` adapters support only their documented pairs; extending raw-input
preparation can require a CLI update even when fact types and engine behavior
are unchanged. New collection capabilities, fact types or engine behavior still
require a binary update.

This first alpha does not migrate stores between incompatible engine
capabilities. A changed compiled registry, policy or engine contract can make an
existing store ineligible, including for new imports. Adding a compiled fact
changes the registry and external-capability digests: a matching signed package
must be rebuilt for that binary. Preserve the prior store and its matching
binary for historical replay. For a different capability, use a separate empty
store, an independently verified bootstrap root and a signed package declaring
the new capability. Do not copy trust or rollback state between stores.
Rule-only updates within one unchanged capability use the existing store.

Run the [synthetic local example](../examples/cncf/knowledge/README.md) to see
package-only verification, empty-to-active coverage and exact historical replay
with one unchanged binary.
The example uses ephemeral keys and is not a production signer or trust root.

The embedded catalogue and rules remain the default. External selection is
complete: an empty revision means no coverage; missing, invalid or stale external
data never falls back to embedded rules. `catalog cncf` continues to describe
the embedded catalogue, not the selected external store.

The store accepts operator-provisioned TUF roots and packages. There is currently
no official Prufyx root, public feed or automatic startup update. Explicit
[`db update`](knowledge-updates.md) can download and retain a complete package
from an operator-selected HTTPS URL before the same local verification.
TUF verifies origin under the selected root, metadata expiry, target digests and
rollback protection. A signature does not establish that source assertions are
correct, maintainer-reviewed, or reproduced in a runtime environment.

## Import and inspect

Use a separate private store directory for this profile. An existing
cert-manager store cannot be reused or migrated by changing the command flag.
The fixed generic target is `knowledge/constraints.v1.json`; packages cannot mix
profiles or include unused target files.

```sh
prufyx db verify revision-1.tar --profile cncf \
  --bootstrap-root root.json --bootstrap-root-digest sha256:<verified-root-digest> \
  --expected-package-digest sha256:<verified-package-digest> \
  --expected-revision 1 --expected-bundle-digest sha256:<verified-target-digest> \
  --format json
prufyx db import revision-1.tar --profile cncf --db-root ./cncf-store \
  --bootstrap-root root.json --bootstrap-root-digest sha256:<verified-root-digest> \
  --expected-revision 1 --expected-bundle-digest sha256:<verified-target-digest> \
  --format json
prufyx db status --profile cncf --db-root ./cncf-store --format json
```

For a quick local status summary, see the [adopter status guide](knowledge-status-adopter.md).

Obtain and verify the initial root identity through your own trusted process;
the package cannot choose its own trust anchor. On later imports omit the
bootstrap flags and retain the same store. Profile identity, descriptor-relative
file admission, private directories and locks protect local selection state.
Do not edit store files manually to reset rollback or clock floors.
The profile marker is public namespace metadata, not a trust anchor or a unique
store identity. Copying that marker alone grants no trust or selected revision.
Rollback protection assumes the retained store has not been replaced with an
older filesystem backup.

The optional `db verify` step above reads no store and changes no trust,
selection, rollback or clock state. Its `VERIFIED` receipt reports
`rollbackAgainstStoreChecked: false` and `importEligibility: NOT_EVALUATED`.
It is a package pre-inspection against the explicit root, not a promise that a
current store will accept the package.

The existing [knowledge database guide](knowledge-database.md) describes the
shared offline TUF package and failure/recovery rules. Verified TUF metadata can
advance trust even if the semantic target is rejected. The failure output states
whether trust advanced and whether exact-package recovery is required. A failed
import does not authorize using a stale earlier selection as current data.

## Check local declarations

Input remains the minimized operator declaration documented in the
[CNCF input guide](CNCF-SOURCE-PREVIEW.md). Keep it as a regular `0600` file,
without symlinks or hardlinks. The optional local Kyverno preparation workflow
can produce that input; the store never receives its original workload bytes.

```sh
umask 077
prufyx check cncf --project kyverno --input kyverno-input.json \
  --knowledge-db ./cncf-store --format json > report.json
chmod 600 report.json
```

Omit `--now` for external selection. A current check uses the verifier's actual
UTC clock so that a supplied earlier time cannot bypass metadata or source
expiry. The pure engine receives its whole-second UTC value. The report binds
the exact input, selected target, semantic revision, trust receipt, compiled
engine, registry, policy and build identity. It labels operator-provisioned trust
and `synthetic_test_only` data explicitly. Source references remain declarations;
whole-upgrade compatibility remains `UNKNOWN`.

Exit `0` means every selected nonempty source claim passed; `10` means at least
one was blocked; `11` means unresolved or missing coverage. Invalid local input
returns `2`; integrity and trust failures return `3`. A source rule with expired,
withdrawn or unreviewed evidence remains `UNKNOWN` even when its containing TUF
metadata is valid. Fresh transport signatures do not renew source review.
CNCF rules must declare a positive review interval of at most 90 days. This
policy bound does not verify that the declared review actually occurred.

## Replay an earlier selection

Retain the exact original input and canonical report locally. Historical replay
requires all recorded knowledge identities and the input digest:

```sh
prufyx check cncf --project kyverno --input kyverno-input.json \
  --input-digest sha256:<original-input-digest> \
  --knowledge-db ./cncf-store --knowledge-revision <original-revision> \
  --knowledge-bundle-digest sha256:<original-target-digest> \
  --knowledge-trust-receipt-digest sha256:<original-trust-receipt-digest> \
  --replay-report report.json --format json
```

The original report supplies its exact evaluation time; omit `--now`. Replay
returns an explicitly historical wrapper containing the byte-identical original
report. It does not replace current selection, establish current freshness or
prove non-revocation. The recorded build identity must still match.

## Data boundary

Import reads a local public metadata package. Checking reads private minimized
input locally. The knowledge store retains public TUF metadata, signed targets,
trust receipts, selection state and rollback/clock floors. It does not retain
input declarations, original configurations, commands, environment values,
workload names or input file paths. Neither operation contacts Prufyx, a model,
an upstream source URL or a cluster. Hashes bind bytes; they are not anonymity
proofs. Review a report before choosing to share it.

The generic envelope uses `prufyx.io/operator-cncf-knowledge/v1alpha1`, a positive
decimal revision, `operator_provided` or `synthetic_test_only` purpose, the exact
compiled capability digest, and a complete source-rule pack. It cannot define
new registries, operators, collection fields or authority labels. The parser
rejects duplicates, aliases, unknown fields, oversized or malformed data and
incompatible identities. The legacy boolean fact description uses
`enumTokens: null`; null input values or other null envelope fields are rejected.
