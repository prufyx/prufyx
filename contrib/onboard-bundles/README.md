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

Never in a bundle: rules, tables, batches, approvals, signatures, scripts,
archives, credentials, private paths or host names. Only JSON files.

## Limits

- at most 256 KiB per file and at most 12 files;
- strict UTF-8 JSON, no duplicate keys, nesting at most 24 levels;
- no symbolic links and no directories other than `extract-run/`.

## Building the bundle from a snapshot

`build` writes the required files and the receipt from a snapshot made with the
private `project init`, `project sync` and `project verify` commands. It reads
only that snapshot directory: no network, no clock, no environment.

```sh
cd cli
go build -ldflags "-X github.com/prufyx/prufyx/cli/internal/buildidentity.SourceRevision=$(git rev-parse HEAD)" -o prufyx-maintainer ./cmd/prufyx-maintainer
./prufyx-maintainer onboard-bundle build \
  --snapshot <private>/snapshot-<sha256> --slug <slug> --spdx Apache-2.0 \
  --post-tag CHANGELOG.md --out ../contrib/onboard-bundles/<slug>
```

Two optional inputs add more, both still offline:

```sh
./prufyx-maintainer onboard-bundle build ... \
  --checkout <local clone> --scan-path CHANGELOG.md:copy:"one note" \
  --target-input target-hint.json
```

- `--checkout DIR` with one or more `--scan-path PATH:CLASS[:NOTE]` (at most 20)
  fills `scan-notes.json` evidence: for each built tag, the sha256 of the blob.
  It is **limited to blobs the verified snapshot already holds** (the changelog
  files and the licence). A path the snapshot holds no blob for is refused, as
  is an absolute path, a dot segment or a glob. The clone is read as git
  objects at the snapshot's commit ids only, never its working tree, config or
  replace refs, and is never fetched. The tag must resolve to the snapshot
  commit and the blob must hash to the snapshot's digest. The note is at most
  300 characters from a restricted charset.
- `--target-input FILE` is **your hint for the target skeleton**: strict JSON
  (at most 256 KiB) with only `name`, `component`, `factProject`, `paths`,
  `exclude` and `copiesEvidence`, each field capped and restricted to a
  charset. It never makes a filled target: `status` stays `skeleton` and the
  file cannot set a status, an origin, the project or the repository.
  It cannot be combined with `--no-crds`.

The **offline target check** runs only when `--target-input` is given and only
on the declared target and the snapshot's own data: the built tags, the tag
prefix and lowest line, and the changelog and licence files the snapshot holds.
It fails on no paths, a duplicate path, a path that is a snapshot changelog or
licence file, a path overlapping an exclusion in the same repository, and
copies evidence that names an undeclared path or a tag that is not built. The
result is written to `receipt.json` as `checks.targetCheckOffline` (`pass` or
`fail`; `not-run` without `--target-input`) and the reasons are printed. A
failed check still writes the bundle, for inspection, but `build` exits 1: fix
the reasons, then run `build` again; a bundle with a failed check is not ready
to submit. `pass`
means the declaration is self-consistent with the snapshot. It does not mean a
path exists upstream, that the target is right, or that anything is verified
against upstream, and it is not coverage. A later edit followed by `seal`
resets the result to `not-run`.

Where each field comes from:

| Field | Source |
| --- | --- |
| repository, release lines (tag, commit), licence path, commit and sha256, changelog commits, file digests and line spans | the snapshot (derived, nothing guessed) |
| `generatedAt` | the snapshot's observation time, so the same snapshot and flags give byte-identical files |
| `spdxGuess`, `cncfStatusClaim`, `postTag`, `tagPrefix` (only when it cannot be derived), `minFrom` override, `no-crds` status | **declared by you** with `--spdx`, `--cncf` (default `none`, never looked up), `--post-tag` or `--no-post-tag` per changelog path, `--tag-prefix`, `--min-from`, `--no-crds`; optional `chart.path` and `chart.version` with `--chart-path` and `--chart-version` |
| `tool.prufyxCommit` | the commit embedded in the binary at build time (the `-ldflags` line above); a binary built without it writes `0000...0000`, meaning unverified |

What the result does and does not say:

- The snapshot is **self-consistent with its own digests**; it is not verified
  against upstream. The import is planned to re-check tags, licence and changelog spans against upstream; today these declared values are checked only for format and by the human merge review.
- `target-draft.json` is always a **skeleton**: empty unless you pass
  `--target-input`, and even then its `status` stays `skeleton`. `build` never
  writes a filled target; coverage comes only from the pipeline.
  `scan-notes.json` has no entries unless you pass `--checkout` with
  `--scan-path`.
- `build` never writes an origin, a review result or anything the import
  derives. The receipt is the integrity record described below.
- It refuses a snapshot that fails verification, has extra or missing content,
  has no licence file, a tag you name that is not in the snapshot, a missing or
  unknown declared value (the message names the flag), a field over its limit
  (the same limits as `seal`), or an `--out` that already exists. On a refusal
  nothing is written. A filled target is not supported here.
- A snapshot with more than six release lines needs `--tags`.

### Projects without CRDs

A project that ships no CustomResourceDefinitions is declared with
`--no-crds`. If its evidence is a Helm chart, you can point to it so the
pipeline's chart resolver knows where to look:

```
prufyx-maintainer onboard-bundle build ... --no-crds \
  --chart-path charts/<name> --chart-version <chart version>
```

- Both flags go together (a version without a path, or a path without a
  version, is refused). Both are **declared by you**: nothing is derived or
  guessed, and the version is not compared with anything.
- Limits: path at most 253 characters, letters, digits and `. _ / + -`, a plain
  repo-relative path (no absolute path, dot segment or glob); version at most
  128 characters, starting with a letter or digit, then letters, digits and
  `. _ + -`.
- The path must be a file the snapshot already holds (a path you gave to
  `project init --changelog-paths`; the snapshot keeps the first path found per
  tag), or a directory that contains one, at a built tag. A path the snapshot
  holds nothing under is refused: the chart is never accepted on its own. For a
  chart whose changelog lives in the chart directory, list that changelog file
  and declare the directory.
- It is written to `project.json` as `chart: {path, version}`. The field is
  optional; bundles without it stay valid. It is a hint only: it never sets a
  verdict, coverage or a filled target, and it is not in the receipt.
- Check the factory side before relying on it: the intake validator uses a
  pinned copy of the bundle schema and refuses `chart` until that copy is
  updated.

In your pull request text, list the values you declared (the table row above)
and every field of your `--target-input` and `--scan-path` notes.

## The receipt

```sh
cd cli
go run ./cmd/prufyx-maintainer onboard-bundle seal \
  --tool-commit <40-hex commit of your checkout> --generated-at 2026-11-19T10:00:00Z \
  ../contrib/onboard-bundles/<slug>
```

`seal` writes only `receipt.json`, using the same digest function as
`validate`. The directory must be named after the slug in `project.json`. It
never reads the clock or the network, and it never writes an origin, a review
result or anything the import derives itself. If you edit a file later, run it
again: a receipt that no longer matches is replaced only with `--force-reseal`,
and the changes are printed. `--tool-commit` is your own declaration and is not
verified.

The receipt is an integrity record of the file bytes and nothing more. It does
not bind the repository, an invite, a snapshot or the tool version, it is not
provenance, and anyone can re-seal edited content. Nothing trusts it for a
decision. The import is planned to re-check tags, licence and changelog spans against upstream; today these declared values are checked only for format and by the human merge review.

`seal` also refuses a bundle with any other finding, a string over 2000
characters, a character outside printable ASCII (leads quotes excepted), or
more than 512 KiB in all. In your pull request text, list the fields you
declared yourself (paths, exclusions, names, notes, quotes); that list is read in
review.

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
   above, except `receipt.json`: run `onboard-bundle build` (see "Building the
   bundle from a snapshot") or write them yourself.
2. Write the receipt with the command, never by hand (`build` already did; run
   `seal` after any later edit, see "The receipt").
3. Run the offline check from "Check before you open the pull request".
4. Open the pull request against `main` and sign the CLA when asked.
5. CI re-runs the check with the validator from the base branch.

Implemented today: steps 1-5 (`onboard-bundle build` writes the files of step 1 from a verified snapshot; target paths, exclusions and scan notes stay yours to write), the maintainers' manual review, and the
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
