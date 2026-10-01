# Inspect a local knowledge store

Use status after an explicit local import or update:

```sh
prufyx db status --profile cncf --db-root ./cncf-store --format human
prufyx db status --profile cncf --db-root ./cncf-store --format json
```

The command is offline and does not import a package, select a revision, or
refresh a feed. It does retain the existing monotonic clock-floor protection;
a successful status check may advance that local floor. Use a separate private
store for each profile.

Read the fields this way:

- `trustFreshness` describes authenticated TUF role metadata. The legacy
  `freshness` field remains the same TUF-oriented value for compatibility.
- `sourceEvidenceFreshness` describes the selected receipt's source-review
  summary. `not_expired` means its earliest recorded expiry is still ahead;
  `some_or_all_expired` means at least one covered rule may be stale and the
  summary cannot tell whether the rest are also expired. `not_expired` does not
  establish that the source is currently reviewed or usable.
- `sourceEvidenceExpiresAt` is the earliest receipt expiry when available. It
  is not a source refresh timestamp and does not renew review evidence.
- `currentEligible` and `READY` describe the selected store's local integrity
  and current metadata checks. They do not mean every rule is usable or that a
  whole upgrade is safe.

Typical states are `NO_SELECTION`, `RECOVERY_REQUIRED`, `READY`, `EXPIRED`,
`TRUST_ADVANCED`, and `INTEGRITY_FAILURE`. Follow `nextAction`; preserve the old store and matching
binary when capability or trust state is incompatible. A fresh signed package
cannot turn an unreviewed or expired source assertion into reviewed evidence.

The status report contains metadata identities and bounded freshness values. It
does not retain or print checked configuration, workload names, commands,
credentials, cluster state, or input file paths. Hashes bind bytes; they are not
anonymity proof. The command does not contact Prufyx, a model, an upstream
source, or a cluster.
