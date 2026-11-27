# Hop status for multi-version jumps

Status: implemented, locally verified (unit tests). Not yet wired to a command
or to the signed pack; the jump composer reads it as a Go package.

`internal/hopstatus` resolves, for a jump from one release line to another, the
status of every hop (pair of consecutive release lines) on the path. It reads
evidence the caller took from the signed pack. It uses no model, no network and
no clock, and it never decides the verdict of the jump: that composition stays
with the caller (any BLOCKED hop blocks the jump; PASS only when every hop is
PASS).

## API

```go
hops, err := hopstatus.Resolve(project, "1.24", "1.28")
```

`project` is a `hopstatus.Project`:

| Field | Meaning |
|---|---|
| `Lines` | the known release lines, ascending, unique (`major.minor`) |
| `Hops` | evidence by `hopstatus.Key(from, to)`: `Blocked []Block{RuleID, Citation}`, `Attested bool`, `Change string` (citation of a cited change list), `Stop *hopstop.Record` |
| `DerivedFrom` | the target's `derivedFrom` line or empty; it only chooses `NextAction` |

`Resolve` returns one `Hop{From, To, Status, Citation, ReasonCode, Source,
NextAction}` per consecutive line from the start to the end, ascending.

Priority per hop: a B rule with a citation gives `BLOCKED`; an admitted
attestation gives `PASS`; a cited change list gives `L`; a hop-stop record gives
`G` with its code; nothing gives `G` with reason `not-derived`. An attestation
and a hop-stop for the same hop contradict each other: `G` with reason
`evidence-conflict`.

Refusals (an error and no hops, never a PASS): a line that is not known for the
project, a start not before the end, unsorted or repeated lines, evidence for a
key that is not a hop, a B rule without rule id or citation, a hop-stop that is
invalid or belongs to another hop.

`derivedFrom` is never evidence. A hop at or above `derivedFrom` with no
attestation, no rule, no change list and no stop is `G` `not-derived`, exactly
like one below it; only the next action differs (`backfill-depth` below,
`re-derive` at or above).

## Hop-stop records

`internal/hopstop` is the record of a hop that the pipeline derived without an
attestation: project, family, from and to line, one code from a closed set,
reasons from the same set, tool commit and facts digest. No free text. The
final codes are `hop-not-previous-minor`, `declared-incomplete`,
`scan-unclean`, `rules-not-line-wide`, `definition-removed`, `tags-missing`,
`window-shortened` and `family-stop:<frozen|narrowed|parked|unsupported>`.
`release-pending` and `derive-failed` are states of a run: a record that
carries one is refused. `hopstop.Parse` and `hopstop.Admit` refuse unknown
codes, unknown or repeated members, unsorted or repeated hops and every
malformed field. The records are not yet a member of the signed pack; adding
the member changes the pack schema level and is a separate reviewed step.
