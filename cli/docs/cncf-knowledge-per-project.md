# Per-project CNCF knowledge targets

The signed CNCF knowledge database can be published as one TUF target per
project plus a small index target, instead of one target that holds every
rule. Each target has its own 1 MiB cap, so the database can grow past the
size of a single target. This layout uses the `cncf-projects` profile. The
single-target `cncf` profile is unchanged and keeps working with existing
stores; the two layouts never share a store.

There is still no official Prufyx root or feed. Packages in this layout are
verified against an operator-provisioned root exactly like the single-target
layout; see [Optional signed CNCF knowledge](cncf-knowledge-database.md) and
[Explicit knowledge downloads](knowledge-updates.md).

## Target layout

| TUF target path | Content |
| --- | --- |
| `knowledge/cncf/index.v1.json` | The index: schema `prufyx.io/cncf-knowledge-index/v1`, its own revision, purpose, the compiled engine capability digest, and one entry per project. |
| `knowledge/cncf/projects/<project>.v1.json` | One complete `prufyx.io/operator-cncf-knowledge/v1alpha1` envelope that holds only that project's rules. |

Each index entry names the project, its target path, its own revision, the
exact target length and SHA-256 digest, the rule digest and the earliest
evidence expiry of that project's rules. The index is compact canonical JSON
with projects in ascending order; unknown fields, duplicates, projects outside
the compiled CNCF catalogue and targets over 1 MiB are rejected. An index lists
between 1 and 256 projects.

In a package archive the members are content-addressed like every other
profile: `targets/knowledge/cncf/<sha256>.index.v1.json` and
`targets/knowledge/cncf/projects/<sha256>.<project>.v1.json`, next to the
`metadata/` files. A complete package is at most 8 MiB, and its targets
together at most 7 MiB.

## What is verified

On `db verify`, `db import` and `db update` with `--profile cncf-projects`,
Prufyx verifies the TUF metadata under the store's root and then requires all
of the following before anything is selected:

- the signed targets role contains the index and only project targets, each at
  most 1 MiB;
- the set of project targets in the index equals the set of project targets in
  the signed targets role, so a target that is listed but not signed, or signed
  but not listed, is rejected;
- each project target's length and digest in the index equal its signed length
  and hash, and the downloaded bytes match both;
- each project target is a valid envelope whose revision, rule digest and
  evidence expiry equal its index entry and whose rules all belong to that
  project;
- the package contains no unused member.

Rollback protection applies to the index and to every project separately. The
index revision cannot decrease. A project's revision cannot decrease, and an
equal revision must keep the exact same target digest. A project that a later
index drops keeps its floor, so it cannot come back at an older revision.

Any failure rejects the whole package: no project is selected from a package
that fails one check. As with every profile, newer signed metadata can advance
trust state even when a target is rejected. The previous selection then stays
available for exact historical replay, and `db status` reports
`TRUST_ADVANCED` until a valid package is imported. The rejection output states
whether trust advanced and whether the selection changed.

## Import and check

Use a new private store directory for this profile:

```sh
prufyx db verify per-project.tar --profile cncf-projects \
  --bootstrap-root root.json --bootstrap-root-digest sha256:<verified-root-digest> \
  --format json
prufyx db import per-project.tar --profile cncf-projects --db-root ./cncf-projects-store \
  --bootstrap-root root.json --bootstrap-root-digest sha256:<verified-root-digest>
prufyx db status --profile cncf-projects --db-root ./cncf-projects-store
```

`db verify` lists every project target with its revision, length and digest.
`db import` and `db update` report the number of project targets imported.
`db update --profile cncf-projects --source URL` works as for other profiles;
`--release-plan` still describes only the single-target layout.

`check cncf` and `check batch` take the same `--knowledge-db` flag for both
layouts and detect the layout from the store. For a per-project store they
read and verify the index and only the projects being checked; other project
targets are not read. A project that the selected index does not list is
evaluated with no rules and stays `UNKNOWN`; embedded rules are never used as a
fallback. The report's `knowledge` section identifies the selected index
(`targetPath`, `revision`, `bundleDigest`, `trustReceiptDigest`) and adds a
`projectTarget` object with the evaluated project's target path, revision and
digest, or `"status": "absent_from_index"`; for an absent project the report's
pack digest identifies a synthesized empty envelope that was never published.

`prufyx scan --knowledge-db` reads the same stores the same way, opening the
index and the target of every targeted project. A targeted project the index
does not list is reported with the gap `PROJECT_NOT_IN_KNOWLEDGE`; see
[`prufyx scan`](scan.md#knowledge-database).
A damaged stored project target blocks only checks of that project, while
`db status` reports the store failure. Historical replay uses the index
identities from the report:

```sh
prufyx check cncf --project kyverno --input kyverno-input.json \
  --input-digest sha256:<original-input-digest> \
  --knowledge-db ./cncf-projects-store --knowledge-revision <index-revision> \
  --knowledge-bundle-digest sha256:<index-digest> \
  --knowledge-trust-receipt-digest sha256:<trust-receipt-digest> \
  --replay-report report.json --format json
```

## Moving from the single-target layout

The layouts are separate on purpose; nothing is migrated in place.

- **Current binary, existing single-target store.** `--profile cncf` stores
  keep working for import, status and checks. Checks open them unchanged.
- **Current binary, wrong layout.** Importing a per-project package with
  `--profile cncf`, a single-target package with `--profile cncf-projects`, or
  using a store of the other layout is rejected before the store changes, with
  exit code `2` and a message that names the profile to use. `db update`
  reports reason `KNOWLEDGE_LAYOUT_MISMATCH`, keeps the downloaded package, and
  leaves the selection unchanged.
- **Older binaries.** A binary without the `cncf-projects` profile rejects a
  per-project package: `db import` and `db verify` exit `3` with "knowledge
  package import failed" or "knowledge package verification failed"; `db
  update` exits `3` with reason `KNOWLEDGE_PACKAGE_IMPORT_REJECTED`, keeps the
  downloaded package, and does not open the store. The existing store, its selection and
  its rollback floors are unchanged, and checks keep using the last imported
  revision. Such a binary also rejects `--profile cncf-projects` as an unknown
  profile.

To move, create a new private store directory, import the first per-project
package into it with an independently verified bootstrap root, and point
`--knowledge-db` at the new store. Keep the old store and a binary that can
read it if you need to replay reports made from it.

## Building targets and the size check

From the `cli` directory, maintainers build the targets from the embedded
rule pack:

```sh
go run ./cmd/prufyx-maintainer knowledge-targets build \
  --revision 7 --output-dir /absolute/new-dir
go run ./cmd/prufyx-maintainer knowledge-targets build \
  --revision 8 --previous-index /absolute/new-dir/knowledge/cncf/index.v1.json \
  --output-dir /absolute/next-dir
```

The output directory must not exist. Files are written under
`knowledge/cncf/` with their TUF target paths. The build is deterministic: the
same pack and revisions give the same bytes. Without `--previous-index`, the
index and every project get `--revision`. With it, a project whose target
bytes would not change keeps its previous revision and digest, and only the
changed projects and the index move to the new revision, which must be
greater than the previous index revision. Building does not sign anything.
The [publisher workflow](knowledge-publisher.md) and `package-knowledge`
still prepare only the single-target layout; signing per-project targets is
not part of this source preview yet. A pack that carries line attestations
or upgrade-path policies cannot be split into per-project targets yet:
`knowledge-targets build` refuses it rather than dropping those sections.

The size check fails when any target reaches 80% of the 1 MiB per-target cap
(838861 bytes or more), or when the summed size of all targets reaches 80% of
the 7 MiB member total of one package (5872026 bytes or more):

```sh
go run ./cmd/prufyx-maintainer knowledge-targets check-size
go run ./cmd/prufyx-maintainer knowledge-targets check-size --dir /absolute/new-dir
```

Without `--dir` it builds the targets from the embedded pack in memory and
also checks the single-target layout, which is still the only layout the
publisher can produce; that check fails at the same 80% alarm and is removed
when the single-target profile is retired. With `--dir` it measures every
`.json` file under `knowledge/cncf/` in a build output, without parsing, so an
oversize file is still reported. It prints the largest targets, the package
total and, for each target at or over the alarm, the target path, its size, the
percentage and the cap; it then exits `1`. Exit `0` means every target and the
total are below the alarm; exit `2` means the command or input was rejected.
CI runs the check on pushes to `main` and on pull requests that target `main`.
