# Onboarding bundles

A pull request here proposes **hints** for onboarding one public project into
Prufyx. A bundle is never knowledge, a rule, or a claim of correctness. The
maintainers re-derive everything from their own copy of the upstream source,
byte-compare every citation, and drop whatever does not match. A bundle that
passes validation is only well-formed.

If you only want to suggest a project, use the
[issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml)
instead; a pull request is for people who can also supply the bundle files.

## Layout

One bundle per project, in `contrib/onboard-bundles/<slug>/`. The slug is the
project slug in `project.json` and matches `^[a-z0-9][a-z0-9-]{0,62}$`. A
project that already has a bundle or is already onboarded is refused.

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

Never in a bundle: rules, tables, batches, approvals, signatures, scripts,
archives, credentials, private paths or host names. Only JSON files.

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

## What happens next

A maintainer reviews the diff. A merged bundle may let the project into the
mirror scope of the build pipeline; it does not add a rule, a target, or a
published claim by itself. Those stay behind the normal review and approval.
