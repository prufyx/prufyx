# Onboarding bundles

A pull request here proposes **hints** for onboarding one public project into
Prufyx. A bundle is never knowledge, a rule, or a claim of correctness. The
maintainers re-derive everything from their own copy of the upstream source,
byte-compare every citation, and drop whatever does not match. A bundle that
passes validation is only well-formed.

Before you start, check whether the project already has a bundle: list
`contrib/onboard-bundles/` in this repository (a directory per slug). An
existing bundle, or an already onboarded project, is refused in review. Only a
maintainer of the project who holds an invite can submit a bundle; see
[For project maintainers](../../docs/maintainers.md).

If you only want to suggest a project, use the
[issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml)
instead; a pull request is for people who can also supply the bundle files.

## Layout

One bundle per project, in `contrib/onboard-bundles/<slug>/`. The slug is the
project slug in `project.json` and matches `^[a-z0-9][a-z0-9-]{0,62}$`. A
bundle for a project that is already onboarded, or already has a bundle, is
refused in review.

| File | Required | Holds |
| --- | --- | --- |
| `project.json` | yes | repository, slug, licence file with commit and sha256, SPDX guess, tag prefix, newest release lines with their commits |
| `target-draft.json` | yes | a candidate `crd-version-target/v1` (paths, excluded paths with reasons, evidence of copies) |
| `scan-notes.json` | yes | files outside the listed paths that define or name CRD kinds |
| `relnotes-sources.json` | yes | release-note files and the release pairs that hold them |
| `receipt.json` | yes | tool commit, per-file digests, `bundleSha256`, review state `NOT_REVIEWED` |
| `leads.json` | no | release-note changes as byte-exact quotes at a pinned commit |
| `extract-run/{manifest,candidates,attestations}.json` | no | output of a local `extract run` |

The schema is [`schema.json`](../../cli/internal/maintainer/onboardbundle/schema.json);
a complete fictional example is in
[`testdata/valid`](../../cli/internal/maintainer/onboardbundle/testdata/valid).

There is no command yet that writes these files for you: `onboard-bundle`
only has `validate`. Today you write `project.json`, `scan-notes.json` and
`relnotes-sources.json` by hand, following the schema and the example. The
`receipt.json` digests (per-file digests and `bundleSha256`) cannot sensibly be
computed by hand and no command writes them yet, so a new bundle cannot be
finished from the public tools alone; this is a known gap. The `validate`
output prints the computed `bundleSha256` when it differs. Until the builder
exists, send the repository and a public maintainer link through the invite
route and the maintainers prepare the bundle files with you. The only
documented producer of `target-draft.json` is
[`target-draft record`](../../cli/docs/target-draft-record.md), which needs a
local checkout of the project and expected-target values that a first-time
maintainer does not have; that is part of the same gap.

Never in a bundle: rules, tables, batches, approvals, signatures, scripts,
archives, credentials, private paths or host names. Only JSON files.

## Where each field comes from

Nothing in the table below needs to be guessed except the items marked
"maintainer". `snapshot` means the output of `prufyx-maintainer project sync`
and `project proposal --snapshot SNAPSHOT`
(see [project onboarding](../../cli/docs/project-onboarding.md)).

| File and field | Value comes from |
| --- | --- |
| `project.json` `repo`, `slug`, `tagPrefix` | the request: `--repository`, `--slug`, `--tag-prefix`; the slug must equal the directory name |
| `project.json` `licence.path`, `licence.commit` | proposal: licence file path and the commit it was read at |
| `project.json` `licence.sha256` | proposal `license.fileDigest` (the hex digest after `sha256:`) |
| `project.json` `licence.spdxGuess` | maintainer: your reading of the licence text; a guess, not a determination |
| `project.json` `cncfStatusClaim` | maintainer: what the project says about its own CNCF status; a claim, not checked |
| `project.json` `releaseLines[].tag`, `.commit` | proposal: release tag and its resolved commit |
| `project.json` `releaseLines[].line` | maintainer: the minor line of that tag, for example `0.20` for `v0.20.6` |
| `target-draft.json` `target.*` (paths, excludes, `minFrom`, `tagPrefixes`) | maintainer: read the checkout. A hand-written draft is only a hint: it is re-derived by the maintainers and never creates coverage by itself; the validator checks structure only |
| `target-draft.json` `copiesEvidence`, `exclude[].evidence` | maintainer: what you compared, in words |
| `scan-notes.json` `entries[].path`, `class`, `note` | maintainer: files outside the listed paths that define or name CRD kinds; `class` is one of the classes below |
| `scan-notes.json` `entries[].evidence[].tag`, `.commit` | proposal: tag and commit the file was read at |
| `scan-notes.json` `entries[].evidence[].sha256` | maintainer: digest of that file at that commit (`git show COMMIT:PATH \| sha256sum`) |
| `relnotes-sources.json` `rows[].path`, `form` | maintainer: the release-note file in the checkout; `form` as in the schema |
| `relnotes-sources.json` `pairs[].fromTag`, `.toTag`, `.commit` | proposal: adjacent release tags and the commit of `toTag` |
| `relnotes-sources.json` `pairs[].fileSha256` | maintainer: digest of the file at that commit |
| `relnotes-sources.json` `pairs[].startLine`, `.endLine` | maintainer: line range of the section for that release pair; a hint, the validator cannot check it |
| `receipt.json` (all fields) | derived by the import: do not write it |

### Scan-notes classes

`class` in `scan-notes.json` must be one of these (checked against the schema
by a test):

| Class | Use for |
| --- | --- |
| `copy` | a byte-equal copy of a listed CRD file |
| `templated-copy` | a template (for example a Helm chart) that repeats listed CRDs |
| `extra` | a CRD-defining file that is not in the listed paths |
| `reference` | a file that only names a CRD kind (docs, examples, RBAC) |
| `unread` | a file you did not read; say so in `note` |
| `external` | a CRD defined in another repository |
| `go-defined` | a CRD generated from Go types with no YAML in the repository |
| `other` | none of the above; explain in `note` |

## Release window and changelog files

`project init --release-limit N` keeps the N newest GitHub releases by publish
date, among releases that match `--tag-prefix` (if given). Backports count:
a patch release of an older line published recently can push the newest line's
patches out of the window (a pilot with `--release-limit 5` got
v0.19.12, v0.19.13, v0.20.4, v0.20.5, v0.20.6). To get the lines you want,
raise `--release-limit` (up to 10), narrow the window with `--tag-prefix`, or
name the tags yourself with the exact-tag form (`--exact-tag`, see
[project onboarding](../../cli/docs/project-onboarding.md)). Selecting the
newest tags per release line would often be a better default; that is not
implemented, and the selection described here is unchanged.

`--changelog-paths` takes comma-separated paths, at most eight. The list
replaces the defaults (`CHANGELOG.md`, `CHANGES.md`, `CHANGES`, `RELEASES.md`,
`docs/CHANGELOG.md`) for every release in the request, so a project with one
changelog file per minor line must list every file it needs, for example
`--changelog-paths CHANGELOG/CHANGELOG-0.19.md,CHANGELOG/CHANGELOG-0.20.md`.

## Limits

- at most 256 KiB per file and at most 12 files;
- strict UTF-8 JSON, no duplicate keys, nesting at most 24 levels;
- no symbolic links and no directories other than `extract-run/`.

## Check before you open the pull request

From a checkout of this repository:

```sh
cd cli
go run ./cmd/prufyx-maintainer onboard-bundle validate --dir-is-slug ../contrib/onboard-bundles/<slug>
```

The first `go run` compiles the tool and can take a while with no
progress output on a cold cache or a busy machine; later runs are fast.

The check is offline: it reads the bundle directory and nothing else, and it
executes nothing from the bundle. Exit code 0 means well-formed, 1 means
findings (listed one per line), 2 means a usage or read error. CI runs the same
command, built from the base branch, on every changed bundle directory.

## Licence and CLA

Every author signs the [Contributor License Agreement](../../CLA.md) on the
first pull request. Bundle data is licensed under
[CC BY-SA 4.0](../../DATA-LICENSE.md). Submit only material you may
redistribute: file names, digests, commits and short upstream quotes of a
project whose licence allows it. Source-available licences (BUSL, ELv2, SSPL)
and proprietary projects are not accepted.

How the validator enforces this: `project.json` declares the licence file
(`path`, `commit`, `sha256`) and an identifier `spdxGuess`. The identifier must
be exactly one of the schema's allowlist (Apache-2.0, MIT, BSD-2-Clause,
BSD-3-Clause, MPL-2.0, ISC, GPL-2.0, GPL-3.0, LGPL-3.0, AGPL-3.0). Any other
value is a finding: BUSL, ELv2, SSPL, proprietary, unlicensed, unknown,
compound expressions, case or spacing variants, a non-string value, and a
missing field. The check cannot read the licence file's contents (it stays
offline and sees only the digest), so `spdxGuess` is a declaration;
maintainers compare it with the upstream file in review.

## Steps

1. Pick the slug and create `contrib/onboard-bundles/<slug>/` with the files
   above.
2. Run the offline check from "Check before you open the pull request".
3. Open the pull request against `main` and sign the CLA when asked.
4. CI re-runs the check with the validator from the base branch.

Steps 1-4 are manual today (no command writes the bundle). Implemented today: the offline check, the maintainers' manual review, and the
automatic import of merged bundles. Who may submit, how to get an invite and
the exact merge path are described only in
[Intake is for invited maintainers only](../../docs/maintainers.md#intake-is-for-invited-maintainers-only);
that page is the single source. In short: a submission from an account without
an invite is refused and not imported. After a Prufyx maintainer merges the
bundle pull request, the import runs by itself; this does not mean that
self-onboarding is complete end to end, and a merge is not a compatibility
claim.

Planned, not live: automatic status comments for every stage (received,
validated, imported, classified in scope or blocked with a reason or out of
scope, for example no CRDs, draft target proposed, in a batch pull request,
merged, pairs decided n of m). Until then maintainers answer by hand.
No time frame is promised.

Never collected: secrets, credentials, cluster data. Nothing is published
without maintainer review and the Prufyx maintainers' signature on the knowledge bundle.

## What happens next

A maintainer reviews the diff. A merged bundle may let the project into the
mirror scope of the build pipeline; it does not add a rule, a target, or a
published claim by itself. Those stay behind the normal review and approval.
