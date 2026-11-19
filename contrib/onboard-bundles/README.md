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

Every schema field of the six bundle files is listed once (a test checks this
against [`schema.json`](../../cli/internal/maintainer/onboardbundle/schema.json)).
`proposal` means the output of `prufyx-maintainer project proposal --snapshot
SNAPSHOT` after `project sync` (see
[project onboarding](../../cli/docs/project-onboarding.md)); `request` means
the options you gave `project init`.

| File and field | Value comes from |
| --- | --- |
| `project.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `project.json` `kind` | fixed text `project` |
| `project.json` `repo` | request: `--repository`, written as `github.com/OWNER/NAME` |
| `project.json` `slug` | request: `--slug`; must equal the directory name |
| `project.json` `licence` | object holding the four fields below |
| `project.json` `licence.path` | proposal: licence file path |
| `project.json` `licence.commit` | proposal: commit the licence file was read at |
| `project.json` `licence.sha256` | proposal `license.fileDigest` (hex after `sha256:`) |
| `project.json` `licence.spdxGuess` | maintainer: your reading of the licence text; a guess, not a determination |
| `project.json` `tagPrefix` | request: `--tag-prefix` |
| `project.json` `releaseLines` | list, one entry per release line in the window |
| `project.json` `releaseLines[].line` | maintainer: minor line of the tag, for example `0.20` for `v0.20.6` |
| `project.json` `releaseLines[].tag` | proposal: release tag |
| `project.json` `releaseLines[].commit` | proposal: resolved commit of that tag |
| `project.json` `cncfStatusClaim` | maintainer: what the project says about its CNCF status; a claim, not checked |
| `target-draft.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `target-draft.json` `kind` | fixed text `target-draft` |
| `target-draft.json` `status` | maintainer: `filled` when you wrote the target (see schema for the other values) |
| `target-draft.json` `target` | object, a candidate `crd-version-target/v1`; only a hint: maintainers re-derive it and it never creates coverage by itself; the validator checks structure only |
| `target-draft.json` `target.project` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.name` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.repo` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.component` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.factProject` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.tagPrefixes` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.minFrom` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.attest` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.paths` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.paths[].path` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.paths[].directory` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.paths[].match` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.paths[].guard` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude[].path` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude[].repo` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude[].reason` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude[].evidence` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `target.exclude[].copies` | maintainer: read from the checkout (hint, see `target`) |
| `target-draft.json` `copiesEvidence` | maintainer: what you compared at which tags, in words |
| `target-draft.json` `copiesEvidence[].path` | maintainer: what you compared at which tags, in words |
| `target-draft.json` `copiesEvidence[].comparedWith` | maintainer: what you compared at which tags, in words |
| `target-draft.json` `copiesEvidence[].tags` | maintainer: what you compared at which tags, in words |
| `target-draft.json` `copiesEvidence[].note` | maintainer: what you compared at which tags, in words |
| `scan-notes.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `scan-notes.json` `kind` | fixed text `scan-notes` |
| `scan-notes.json` `entries` | list, one entry per file |
| `scan-notes.json` `entries[].path` | maintainer: file outside the listed paths that defines or names CRD kinds |
| `scan-notes.json` `entries[].class` | maintainer: one of the classes below |
| `scan-notes.json` `entries[].note` | maintainer: one sentence |
| `scan-notes.json` `entries[].evidence` | list, one entry per tag the file was read at |
| `scan-notes.json` `entries[].evidence[].tag` | proposal: release tag |
| `scan-notes.json` `entries[].evidence[].commit` | proposal: commit of that tag |
| `scan-notes.json` `entries[].evidence[].sha256` | maintainer: digest of the file at that commit (`git show COMMIT:PATH | sha256sum`) |
| `relnotes-sources.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `relnotes-sources.json` `kind` | fixed text `relnotes-sources` |
| `relnotes-sources.json` `rows` | list, one row per release-note file |
| `relnotes-sources.json` `rows[].path` | maintainer: release-note file in the checkout |
| `relnotes-sources.json` `rows[].form` | maintainer: kind of file, values in the schema |
| `relnotes-sources.json` `rows[].postTag` | maintainer: `true` when the file is read after the tag, values in the schema |
| `relnotes-sources.json` `rows[].pairs` | list, one entry per adjacent release pair |
| `relnotes-sources.json` `rows[].pairs[].fromTag` | proposal: older release tag |
| `relnotes-sources.json` `rows[].pairs[].toTag` | proposal: newer release tag |
| `relnotes-sources.json` `rows[].pairs[].present` | maintainer: whether the file exists at that commit |
| `relnotes-sources.json` `rows[].pairs[].commit` | proposal: commit of `toTag` |
| `relnotes-sources.json` `rows[].pairs[].fileSha256` | maintainer: digest of the file at that commit |
| `relnotes-sources.json` `rows[].pairs[].startLine` | maintainer: first line of the section; a hint, the validator cannot check it |
| `relnotes-sources.json` `rows[].pairs[].endLine` | maintainer: last line of the section; a hint, the validator cannot check it |
| `leads.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `leads.json` `kind` | fixed text `leads` |
| `leads.json` `leads` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].type` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].component` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].artefact` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].replacement` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].changedIn` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].refusal` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].pair` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].pair.fromTag` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].pair.toTag` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].path` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].commit` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].fileSha256` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].quote` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].quote.startLine` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].quote.endLine` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].quote.text` | optional file; see `testdata/valid` and the schema for the shape |
| `leads.json` `leads[].certainty` | optional file; see `testdata/valid` and the schema for the shape |
| `receipt.json` `schema` | fixed text `prufyx.io/onboard-bundle/v1`; copy from `testdata/valid` |
| `receipt.json` `kind` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `kit` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `tool` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `tool.prufyxCommit` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `bundleSha256` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `files` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `files[].name` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `files[].sha256` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `review` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `review.state` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `review.admissionState` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `agentLabel` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `generatedAt` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks.targetCheckOffline` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks.extractRun` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks.dropped` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks.dropped[].file` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |
| `receipt.json` `checks.dropped[].reason` | required file, written by `prufyx-maintainer onboard-bundle seal` (PR #750, open); until it merges, prepared via the invite route. Never by hand |

### Scan-notes classes

`class` in `scan-notes.json` (`entries[].class`) must be one of these (checked against the schema
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

## Projects without CRDs

Projects without CRDs are in scope. For such a project the evidence comes from
the Helm chart, in chart families: the install API surface, the declared
platform version range, and the values schema. These families are being built;
the coverage table in the project README will show them as "none yet" (PR #756)
until they produce data. A project with no cluster API surface at all gets a
permanent gap with its reason.

`onboard-bundle build --no-crds` (PR #753, open) changes one field: the
`target-draft.json` `status` becomes `no-crds`. Use it only when the project
ships no CRDs, and declare it explicitly. Building without the flag for a
no-CRD project gives the same bundle apart from that field, so the flag is the
only place the choice is recorded.

## Release window and changelog files

`project init` selects the N newest releases by version (drafts, prereleases
and non-version tags are skipped; it reads up to a fixed page cap and stops
with `RELEASE_LIST_CAP_REACHED` if it cannot find N). This needs the change in
PR #757; before it, the window was the first page of GitHub's release list,
where backports could displace the newest line. `--release-limit` is N (up
to 10) and `--tag-prefix` restricts the tags considered. A repository that
publishes chart-release tags next to app tags (for example
`descheduler-helm-chart-x.y.z` next to `v0.x.y`) needs `--tag-prefix` for the
app tags (for example `v`), or explicit tags (`--exact-tag` at `project init`,
`--tags` where a command takes it). To name the tags
yourself, use the exact-tag form (`--exact-tag`, see
[project onboarding](../../cli/docs/project-onboarding.md)).

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
validated, imported, classified in scope, blocked with a reason, or a permanent
gap with its reason (no cluster API surface), draft target proposed, in a batch pull request,
merged, pairs decided n of m). Until then maintainers answer by hand.
No time frame is promised.

Never collected: secrets, credentials, cluster data. Nothing is published
without maintainer review and the Prufyx maintainers' signature on the knowledge bundle.

## What happens next

A maintainer reviews the diff. A merged bundle may let the project into the
mirror scope of the build pipeline; it does not add a rule, a target, or a
published claim by itself. Those stay behind the normal review and approval.
