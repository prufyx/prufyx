# CNCF knowledge target export

A maintainer can export the embedded public knowledge as an unsigned index and
one bounded target per project:

```sh
go run ./cmd/prufyx-maintainer export-knowledge \
  --profile cncf-projects --revision 1 --output ./targets
```

The profile defaults to `cncf-projects`. The output must be a new directory; it
contains `knowledge/cncf/index.v1.json` and the project targets named by that
index, including community targets when present. Supply `--previous-index FILE`
to retain unchanged projects' revisions. No previous index means a fresh index
layout for this unsigned export; signed releases separately require an explicit
`--first-release` or `--previous-index` decision.

Pass this directory to `knowledge-publish --targets-dir`; see
[the publisher workflow](knowledge-publisher.md). Export neither signs nor
publishes anything and has no access to local stores, customer input, roots or
signing keys.

Single-target export with `--profile cncf` is retired and rejects before
creating output. Existing single-target packages and stores remain readable by
the client under their original bounds, signatures, capabilities and expiry.
The layouts require separate stores; an older single-only binary cannot read
the project layout.

Each project target and the index retain their existing 1 MiB cap. Package,
member-count and rule-document bounds are unchanged. Export does not establish
source review or distribution authority. Independently trusted roots,
authorized signatures and verified packages remain necessary for client import.

If creating or syncing the new directory fails, export leaves any partial
output for explicit inspection or cleanup; it never overwrites an existing
path.
