# CNCF knowledge target export

A maintainer can prepare the embedded public CNCF rules as one unsigned source
target for an independently managed distribution workflow:

```sh
go run ./cmd/prufyx-maintainer export-knowledge \
  --profile cncf --revision 1 --output ./constraints.v1.json
```

With `--profile cncf-projects` the same command writes the per-project layout
into a new directory instead (`knowledge/cncf/index.v1.json` and one target per
project; `--previous-index FILE` keeps unchanged projects at their previous
revision), the input of `knowledge-publish --targets-dir`; see
[knowledge-publisher.md](knowledge-publisher.md).

For `--profile cncf` the output is only the canonical `knowledge/constraints.v1.json` target with
purpose `operator_provided`. It contains the complete embedded reviewed rule
pack with the supplied positive revision. It does not export a local database,
selection, trust root, customer input, or signing key. The command does not
fetch or publish anything.

Inspect the exact compiled construction contract before building a package:

```sh
prufyx db capabilities --profile cncf --format json
```

This reads neither a knowledge store nor the network. It reports the required
target path, capability digest, schemas, and parser bounds. It does not make
the target trusted, fetch knowledge from the official feed
(`prufyx db update`) or your own package, or enable automatic refresh.
An independently managed root, signatures, and verified package remain
necessary before the existing explicit `db import` or `db update` paths can
select it.

The output path must not already exist. If creating or syncing the new file
fails, the command leaves that path in place for explicit operator inspection
or cleanup; it never deletes a path after a failed write.
