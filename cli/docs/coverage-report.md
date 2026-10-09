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
  [--pack rules.json] [--window 6] [--json-out report.json] [--md-out report.md]
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

Lines are `major.minor`, ascending and unique. `priority` and `component` are
optional (`component` lets a project without rules still own line
attestations). Unknown members are rejected. A project with rules but no entry
is listed under `projectsWithoutLines`; its pairs are unknown and are never
counted as covered.

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
lines, never invented ones. A reviewed table covers `linkerd`
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
