# Exit codes

One table for every `prufyx` command that gives a verdict. Read it before you
wire a command into CI.

## The one thing to know

`prufyx scan` and `prufyx check ...` both exit `0` on a pass, but the pass is
not the same size:

- `scan` exit `0` means the declared scope is complete: every hop is covered
  and nothing is missing. This holds unless you pass `scan --fail-on blocked`
  or `--fail-on none`, which can report a non-pass verdict as exit `0` (see
  "`scan --fail-on`" below); the default, `--fail-on unknown`, keeps it.
- `check` exit `0` means **the reviewed rules this check evaluated for that
  exact pair passed** (one or a few rules, for example one setting in one
  file, or the seven removed-API rules of one Kubernetes pair). It says
  nothing about the rest of the upgrade, and the report says so
  (`scoped result: PASS` and `aggregate: UNKNOWN`).

A CI step that treats every `0` as "safe to upgrade" misreads a `check` pass.
**In CI, always add `--strict-exit` to `check`** (below): the scoped pass then
exits `14`, and every other code needs a human decision. Without the flag the
exit codes, output and replay reports are unchanged, and a `check` that exits
`0` prints one line on standard error as a reminder:
`prufyx: note: scoped PASS (exit 0): whole-upgrade compatibility is UNKNOWN; use --strict-exit in CI`.

Making `--strict-exit` the default is proposed for a later minor release; until
then the flag is opt-in.

## Table

| Exit | `scan` | `check` (default) | `check --strict-exit` |
| --- | --- | --- | --- |
| `0` | `PASS FOR THE DECLARED SCOPE`: scope complete (with `--fail-on blocked` or `none`: also an undecided or blocked scan, see below) | scoped `PASS`: the checked rules passed, nothing more | not used for a result (only help output exits `0`) |
| `14` | not used | not used | scoped `PASS`: the checked rules passed, nothing more |
| `10` | `BLOCKED` | scoped `BLOCKED` or `FAIL` | same |
| `11` | not every area checked | `UNKNOWN`, `ATTENTION`, or stale evidence in `check batch` | same |
| `12` | not used | `check batch --exit-mode detailed` only: stale evidence | same |
| `13` | not used | `check batch --exit-mode detailed` only: evaluation clock before review time | same |
| `2` | command line or input not accepted | same | same |
| `3` | knowledge or input integrity failure | same | same |

Rank when several apply: `3` and `2` stop the command; otherwise blocked
(`10`), then not checked (`11`), then pass.

## `scan --fail-on`

`prufyx scan --fail-on unknown|blocked|none` changes only the process exit
code, never the report or its verdict. `unknown` is the default and is the
table above.

| `--fail-on` | verdict `BLOCKED` | verdict `UNKNOWN` (not every area checked) |
| --- | --- | --- |
| `unknown` (default) | `10` | `11` |
| `blocked` | `10` | `0`, except `11` when manifests use an API version the target does not serve |
| `none` | `0`, except `10` when manifests use an API version the target does not serve | `0`, except `11` for the same case |

- Exit `0` with `--fail-on blocked` or `none` can be a blocked or undecided
  scan, so it is **not** a pass. Whenever the flag changes a non-zero verdict
  code, `scan` prints one line to standard error:
  `prufyx: note: verdict UNKNOWN (exit 11) reported as exit 0 by --fail-on blocked; this is not a PASS`.
  Read the headline of the report for the verdict.
- A report with a gap `API_VERSION_NOT_SERVED` (manifests use an API version
  the target no longer serves, for example `batch/v1beta1` CronJob before 1.25)
  keeps its verdict exit code under every `--fail-on` value. This is the same
  gap the GitHub Action fails on.
- Usage (`2`) and integrity (`3`) errors are never changed.

## `--strict-exit`

```sh
prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 --values values.json --strict-exit
echo $?   # 14 when the checked rules passed, 10 when one blocked, 11 when unknown
```

- Accepted by every `prufyx check` route (`batch`, `cncf`, `project`,
  `cert-manager-values`, `prometheus-mode`, `spiffe-x509-svid`,
  `cloudevents-structured-json`, `tikv-gcp-v2-wif-backup`), anywhere after
  `check`. `--strict-exit=false` is the default.
- It changes one thing: a result that would exit `0` exits `14`. Standard
  output, JSON and replay reports are byte-identical to the run without the
  flag, so a report produced with it replays without it.
- On exit `14` it prints one line to standard error:
  `prufyx: note: scoped PASS: exit 14 (--strict-exit); this is not a complete PASS, see cli/docs/exit-codes.md`.
- With the flag, `check` never exits `0` for a result. Help output
  (`prufyx check --help`) still exits `0`.
- `scan` does not take the flag: with the default `--fail-on unknown` its `0`
  already means a complete scope, and `prufyx scan --strict-exit` is refused
  with exit `2`.

In a shell step that should pass on a scoped PASS but fail on anything else:

```sh
prufyx check ... --strict-exit; rc=$?
[ "$rc" -eq 14 ] || exit "$rc"
```

Other commands (`version`, `catalog`, `prepare`, `db`, `assess`) exit `0` on
success, `2` for input not accepted and `3` for an integrity failure.
