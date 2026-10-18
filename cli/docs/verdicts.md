# What the verdicts mean

One page for every answer Prufyx prints. The exit codes are the same ones as in
[exit-codes.md](exit-codes.md); if the two ever disagree, that table is the
reference.

Two rules hold everywhere:

- **`UNKNOWN` is never a pass.** It means the evidence did not decide the
  question. Prufyx does not turn a missing fact into `PASS`.
- **A pass is always about a scope.** No command certifies a whole upgrade as
  safe. `check` says so in its `aggregate:` line; `scan` says so in its
  `Scope limits:` line.

## At a glance

| You see | Command | Exit | Short meaning |
| --- | --- | --- | --- |
| `PASS FOR THE DECLARED SCOPE` | `scan` | `0` | Every hop is covered and nothing is missing. |
| scoped `PASS` | `check` | `0` (`14` with `--strict-exit`) | The rules this check evaluated for that exact pair passed. Nothing more. |
| `BLOCKED` | `scan`, `check` | `10` | A reviewed rule matched your input. Fix it before upgrading. |
| `UNKNOWN` (also `ATTENTION`, `NOT CHECKED`) | `scan`, `check` | `11` | The evidence did not decide. Not a pass. |
| `prufyx: ...` on standard error | any | `2` | The command line or an input was not accepted. |
| `prufyx: KNOWLEDGE INTEGRITY FAILURE` or another integrity error | any | `3` | The built-in knowledge, the `--knowledge-db` database or an input failed verification. |

`check batch --exit-mode detailed` also uses `12` (stale evidence) and `13`
(evaluation clock before review time); see [exit-codes.md](exit-codes.md).

When several apply, `3` and `2` stop the command; otherwise blocked (`10`),
then not checked (`11`), then pass.

## PASS FOR THE DECLARED SCOPE (`scan`, exit 0)

- **Means:** every hop of the upgrade you declared is covered by reviewed
  records, and nothing is missing.
- **Does not mean:** the upgrade is safe. `scan` reads only the manifests you
  give it; it does not look at a live cluster, custom resources, stored
  versions, admission or component configuration, or node version skew.
- **Today:** with the knowledge built into this source tree `scan` cannot reach
  this answer yet (the reviewed records it needs are not shipped; see the
  [README](../../README.md#what-scan-covers-today)).
- **Do:** treat it as one input to your own upgrade review.

Exit `0` from `scan --fail-on blocked` or `--fail-on none` is not this answer.
It can be a blocked or undecided scan; the report headline shows which.

## Scoped PASS (`check`, exit 0 or 14)

- **Means:** the reviewed rules this check evaluated for that exact version
  pair, on that input, passed. It can be one rule (one setting in one file) or
  the seven removed-API rules of one Kubernetes pair.
- **Does not mean:** the rest of the upgrade is fine. The report keeps
  `aggregate: UNKNOWN` next to it, always.
- **Do:** in CI add `--strict-exit`, so a scoped pass exits `14` and cannot be
  read as a complete pass.

## BLOCKED (exit 10)

- **Means:** your input matches a reviewed, pinned source condition that the
  target release enforces, such as a removed API or flag. The report names the
  object (`scan`: file, line, kind and name), the fix, and cites the upstream
  source it relies on.
- **Does not mean:** that fixing it makes the upgrade safe. Other things may
  still be undecided.
- **Do:** apply the fix shown after `fix:` (`scan`) or `next action:`
  (`check`), then run the same command again.

## UNKNOWN (exit 11)

- **Means:** Prufyx could not decide. Typical causes: a declaration is missing
  (see [declarations.md](declarations.md)), the version pair or a release
  boundary is outside what was reviewed, or a fact the rule needs is not in the
  input. `scan` lists every cause under `NOT CHECKED`; `check` prints each
  undecided rule with the reason code and a `next action:`.
- **Does not mean:** the upgrade is fine, and does not mean it is broken. It
  means the evidence did not decide, so the answer is "do not assume".
- **Do:** read the `next action:` or the `NOT CHECKED` entries. Add a missing
  declaration only if it is true. If the pair itself is not reviewed, check each
  minor step on its own, or check by hand.

`check` can also print `ATTENTION` (also exit `11`): a finding that is not a
block but needs a person to look at it (for example a removed cert-manager
value with `--schema-validation disabled`, which the target templates ignore).
It is not a pass.

## NOT CHECKED (`scan`)

A section of the `scan` report that lists each area the scan could not decide
and what to do about it. Any entry here makes the answer at best `UNKNOWN`
(exit `11`); with a blocker present the headline stays `BLOCKED` (exit `10`)
and the entries are still listed.

## Whole-upgrade status

- `check` prints `aggregate: UNKNOWN (whole-upgrade compatibility: UNKNOWN;
  network used: false)` after the scoped result. It is `UNKNOWN` even next to a
  scoped `PASS` or a `BLOCKED` result, because the checked rules are a part of
  the upgrade, not all of it.
- `scan` prints `Scope limits:` and the count of areas not checked.
- In JSON the same status is the `aggregate` field.

## Errors (exit 2 and 3)

- `2`: the command line, a flag value or an input file was not accepted (for
  example a file readable by other users for a `check` command, or a flag in
  the wrong place). Nothing was evaluated; fix the call and run it again.
- `3`: integrity failure of the built-in knowledge, of the database given with
  `--knowledge-db`, or of an input. Prufyx does not fall back to other
  knowledge silently. Do not use the result.
