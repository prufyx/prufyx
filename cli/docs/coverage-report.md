# Coverage report

`prufyx-maintainer coverage report` measures how much of each project's recent
upgrade surface the knowledge pack decides. It is a reporting tool for
maintainers. It reads a rule pack and a snapshot of upstream release lines,
classifies pairs of consecutive release lines and prints counts. It evaluates no
rule, produces no verdict and changes nothing a check reports.

## What is measured

For each project the report takes a window of the last N release lines
(default 6, so 5 consecutive pairs `L(i)` to `L(i+1)`). A release line is a
`major.minor` pair with at least one final release. Each pair gets exactly one
status, the strongest that applies:

| Status | Meaning |
|---|---|
| A (attested) | A current line attestation for `L(i+1)` exists, `L(i)` is the line directly before it, and every rule the attestation lists is valid and line-wide for the pair. An empty list counts: it states that the pack holds no rule for the line. |
| B (bounded) | A valid rule's range covers the whole of `L(i)` on the from side and the whole of `L(i+1)` on the to side, or a valid crossing rule has its removal release inside `L(i+1)` and its crossing region covers the whole of `L(i)`. The answer for such a pair is BLOCKED or UNKNOWN, never PASS. |
| S (spot) | Only a rule for an exact pair of versions, with `from` in `L(i)` and `to` in `L(i+1)`. It decides those versions only. |
| G (gap) | None of the above. |

A rule or attestation is valid when its state is active and the evaluation time
lies in `[reviewedAt, validUntil)`. Verdict-neutral rules (notices and leads)
never count. The matching uses the engine's own helpers (`CoversLine`,
`CrossingBounds`, the line attestation families), not separate logic.

Derived numbers:

- `VC` of a project is `(A + B) / pairs`; `VCA` is `A / pairs`. S is shown and
  never counted.
- C1: projects with at least one valid rule or attestation. C3: `VC >= 0.6`.
  C5: `VCA = 1`.
- A and B are also reported per fact family (rules outside every attestable
  family appear as `other`).

A status "A" means the pack decides the pair within the attested family's scope.
It is not a statement that an upgrade is safe. The families are those of
[line-attestations.md](line-attestations.md): `kubernetes.removed_served_gvk`
for Kubernetes and `crd.custom_resource_versions` for each project of the
custom-resource table. An attestation of the custom-resource family also names
the releases it read; the report counts the pair, while `scan` decides only a
hop between two of those releases.

Projects whose release lines are not the `major.minor` of the engine version
(today `cloud-custodian`, whose releases `0.9.N` form line `9.N`) are measured
on exact pairs only: their ranges, crossings and attestations are never read as
line-wide.

## Inputs

The pack is the embedded pack, or a file given with `--pack`. The versions come
from an offline lines snapshot, `--lines`. The command has no network access.

```
prufyx-maintainer coverage report --lines lines.json --now 2026-10-08T12:00:00Z \
  [--pack rules.json] [--window 6|ALL] [--declared declared.json] [--complete] \
  [--json-out report.json] [--md-out report.md]
```

`--now` and `--lines` are required: the report never reads the clock. Without
`--json-out` and `--md-out` the JSON goes to standard output. The same inputs
give the same bytes; the report records the SHA-256 digests of the pack and of
the lines file.

### Lines snapshot

```json
{
  "schema": "prufyx.io/coverage-lines/v1",
  "capturedOn": "2026-10-08",
  "projects": {
    "example": { "priority": true, "lines": ["1.28", "1.29", "1.30"] }
  }
}
```

Lines are `major.minor`, ascending and unique. `priority`, `component` and
`releases` are optional (`component` lets a project without rules still own line
attestations). Unknown members are rejected. A project with rules but no entry
is listed under `projectsWithoutLines`; its pairs are unknown and are never
counted as covered.
A community-catalog project that has a valid rule but no valid line
attestation is neither counted in `packProjectsCovered` nor listed under
`projectsWithoutLines`.

`releases` maps a line to the final releases of that line, ascending
(`"releases": {"1.28": ["1.28.0", "1.28.1"]}`). Every key must be a listed
line and every version a final release of that line. The ALL window compares
it with the releases a release-scoped attestation names (see below); a line
without an entry cannot be compared. The member is additive to schema
`prufyx.io/coverage-lines/v1`: a binary that predates it rejects a file that
holds it, so an old tool never reads such a snapshot silently.

### Building the snapshot from tags

Capturing tags is a separate step so that the command itself stays offline. An
operator lists the tags of each project, for example:

```
git ls-remote --tags https://example.org/org/project.git > tags/project.tags
```

then converts them:

```
prufyx-maintainer coverage lines-from-tags --tags-dir tags --out lines.json \
  --priority project-a,project-b --captured-on 2026-10-08
```

Each `<project>.tags` file holds one tag per line or `git ls-remote` output.
Only final release tags make a line: `v1.2.3` or `1.2.3`. Pre-releases, snapshots
and unknown spellings are ignored, so an unrecognised tag scheme yields fewer
lines, never invented ones. The same tags fill `releases` (`v1.2.3` is release
`1.2.3`); a project with its own tag scheme (`linkerd`, `cloud-custodian`) gets
none. A reviewed table covers `linkerd`
(`stable-2.X.Y`, `version-2.X.Y`) and `cloud-custodian` (`0.9.N[.M]` to line
`9.N`).

## Output

The JSON report holds the schema, evaluation time, window, pack and lines
digests, fleet and priority totals (projects, pairs, A, B, S, G, C1, C3, C5,
`vcPairs`, `vcMean`, `sPairs`), per-family counts, one row per project with its
window and pairs, the projects without lines, and the projects with an entry
expiring within 14 days. The Markdown file is a summary of the same facts.

`rulesInWindow` counts valid rules whose from and to versions both lie in the
window.

## The ALL window and the complete predicate

`--window ALL` measures every release line from the project's `minFrom` (the
first line its extractors read) instead of the last N lines. `--window N`
(N from 2 to 64) and the default of 6 are unchanged: their output is
byte-identical to what earlier versions of the tool wrote, and none of the
members below appears in it. In the ALL window the report carries
`"windowAll": true` instead of `window`, at most 1024 lines per project, and
the extra members below. The window of a project starts at the lowest
`minFrom` of the families it is registered in (`kubernetes.removed_served_gvk`
from line 1.19, `crd.custom_resource_versions` from the `minFrom` of its target
file); a project registered in none uses all its lines and can never be
complete.

Per project, and per family under `familyCounts`:

| Member | Meaning |
|---|---|
| `linesTotal` | Lines of the window. |
| `decided` | Pairs `L(i)` to `L(i+1)` decided by a qualifying attestation. |
| `declaredUnknown` | Pairs with no attestation and a valid declaration (below). |
| `undeclared` | `linesTotal - 1 - decided - declaredUnknown`: pairs nobody has stated anything about. |
| `complete` | True only when every clause below holds. |
| `invalidDeclarations` | Declarations of the project that name a family it is not registered in, a chart-line family, or lines that are not consecutive in the snapshot. |
| `incompleteReasons` | Why `complete` is false, from a closed list (`snapshot-stale`, `snapshot-undated`, `snapshot-future`, `snapshot-truncated`, `snapshot-hole`, `no-registered-family`, `chart-lines-unmapped`, `too-few-lines`, `invalid-declaration`, `undeclared-pairs`, `count-mismatch`). `count-mismatch` is an assertion of the counting itself and is not expected to appear; a gap shows as `undeclared-pairs`. |

At project level a pair is `decided` only when every family the project is
registered in decides it, and `declaredUnknown` when each family that does not
decide it declares it unknown. The `families` list gets the same four counts as
sums over the CNCF projects. `complete` is per project and never part of the
fleet or priority totals; community-catalog projects are reported apart as
before.

### The predicate

`complete` is true for a project only when all of the following hold. It is
computed from the pack and the inputs named on the command line, never from
any other state.

1. Lines. The project is in the lines snapshot; the snapshot has a
   `capturedOn` date that is not in the future and at most 14 days before
   `--now` (counted from midnight of that date); the first line is not later
   than the `minFrom` of any family the project is registered in; the window
   of each family starts exactly at its `minFrom` line (a missing `minFrom`
   line is a hole); inside one major version consecutive lines differ by
   exactly one minor, and a new major follows the previous major and starts at
   `X.0` (anything else is a missing line). Whether the snapshot lists every upstream line is the
   snapshot's claim: the report states the snapshot's date and digest under
   `linesSnapshot` and in the Markdown, and `complete` is relative to it.
2. Pairs. For every family the project is registered in, each pair has an
   attestation for `L(i+1)` whose previous line is `L(i)`, every rule it lists is
   valid and line-wide for the pair (an empty list is allowed), and, for a
   release-scoped family, the attestation's `releases.from` and `releases.to` are
   exactly the snapshot's `releases` of the two lines (the attestation's own list
   is never trusted; a snapshot without `releases` for either line decides
   nothing). Otherwise the pair must carry a valid declaration. A pair into a new
   major version has no previous line, so it needs a declaration.
3. Citations. The attestation and every listed rule cite at least one source
   with a 40-hex commit and a path in it.
4. Evidence. The attestation and every listed rule have basis `mechanical`, name
   the extractor id, version and code digest that this build of the tool ships,
   and are valid for more than 14 days beyond `--now` (a record valid for exactly
   14 days does not count). A `reviewed` record never satisfies this clause.
5. Counts. `undeclared = 0` and `decided + declaredUnknown = linesTotal - 1`,
   with at least two lines, in every family and for the project.

The extractor identity is computed at run time from the sources compiled into
the tool, so an attestation derived by another version of the extractor does
not count until it is derived again.

`helm.values_schema` is registered for the projects that have a chart target,
but its pairs are pairs of chart lines, which the snapshot does not hold, and
no attestation exists for it. Its pairs are always `undeclared` (declarations
for it are ignored and counted as invalid): a project with a chart target is
never complete (`chart-lines-unmapped`). Chart lines are not mapped onto the
project's lines.

What `complete` claims: for every pair of consecutive lines of the snapshot in
the window, the pack holds a current, mechanically derived statement of the
rules of the registered families (or a reviewed declaration that the pair cannot
be decided). What it does not claim: that an upgrade is safe, that facts outside
the families are covered, or that the snapshot lists every upstream release.

### Declared unknown

A pair that cannot be decided can be declared unknown with a reason from a
closed list. The declarations are a reviewed file embedded in the tool
(`data/declared-unknown.json` in the package; it declares nothing yet), or the
file given with `--declared`. They are not part of the rule pack. The report
records the digest and the number of records used under `declared`.

```json
{
  "schema": "prufyx.io/coverage-declared-unknown/v1",
  "declarations": [
    {
      "project": "example", "family": "crd.custom_resource_versions",
      "from": "1.2", "to": "1.3", "reason": "blocked:go-defined-crds",
      "note": "short reviewed explanation",
      "declaredAt": "2026-10-01T00:00:00Z", "validUntil": "2026-12-15T00:00:00Z"
    }
  ]
}
```

Reasons: `blocked:go-defined-crds`, `blocked:templated-only`,
`blocked:other-repository`, `frozen:tag-deleted`, `conflict:shared-group`,
`scan:not-clean`. The decoder is strict: unknown members are rejected, records
are sorted by project, family and `from`, a project, family and `from` appear
once, `note` is at most 512 bytes and `validUntil` is after `declaredAt` by at
most 90 days. A bad file refuses the whole report. A declaration counts only
while it is current and valid for more than 14 days beyond `--now`; an
expired one is ignored. `to` must be the next snapshot line after `from`, and
the family must be one the project is registered in; a declaration that is not
is ignored and counted in `invalidDeclarations`, which makes the project
incomplete. A declaration never replaces an attestation: it only fills a pair
that has none.

### `--complete`

`--complete` implies the ALL window and prints the projects whose `complete` is
true, one slug per line, sorted. When there are none the output is empty and the
exit code is 0. It cannot be combined with `--window N`, `--json-out` or
`--md-out` (usage error, exit code 2); `--declared` needs `--window ALL` or
`--complete`.
