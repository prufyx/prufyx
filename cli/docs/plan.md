# `prufyx plan`

`prufyx plan` answers "what are the hops from here to there, in what order,
and what blocks each one?". It takes the inputs and flags of
[`scan`](scan.md) and prints one **stage** per planned hop.

```sh
prufyx plan rendered/ --from kubernetes=1.29.15 --to kubernetes=1.33.0 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required
```

## How it works

`plan` runs one `scan` with the full (current, target) pair of every
component, so a rule that spans several lines (a whole-upgrade rule) is seen.
It then places the hops of the scan report in stages. It evaluates no rule of
its own: every blocker, gap and unsupported combination in a stage comes from
the scan, with the same rule id and fix.

## Stages and order

- Kubernetes stages come first, one per hop, in the order of the reviewed
  `sequential_minor` path policy (order label `required`).
- Other components follow, one stage per hop (order label `inferred`: no
  support-range data says an app must move earlier or later; label `free`
  when no Kubernetes path is planned).
- A whole-upgrade finding is shown in exactly one stage: the last stage of its
  component.
- A component whose path the scan could not plan (a gap, no reviewed path
  policy for an app) is listed under *Not planned* with the scan's gap.

## Verdicts

Per stage: `BLOCKED` (a rule blocks the hop), `UNSUPPORTED` (outside a
documented support range), `UNKNOWN`, `PASS`. The plan verdict is the worst
stage; a plan with any not-planned component is at best `UNKNOWN`.

A stage is `PASS` only when all of these hold: its hop is `COVERED` by the
scan, the scan has no gap for the component, the order is `required`, the hop
actions (CRD stored-version migrations and similar) are checked, and the node
rolls are planned. **This version checks no hop actions and plans no node
rolls, so no stage is `PASS` yet.** A `COVERED` hop shows as `UNKNOWN` with
the reasons `HOP_ACTIONS_NOT_CHECKED` (and `NODE_ROLLS_NOT_PLANNED` for
Kubernetes). `BLOCKED` is fully decided: a blocker is a blocker.

Reason codes: `ORDER_INFERRED`, `HOP_ACTIONS_NOT_CHECKED`,
`NODE_ROLLS_NOT_PLANNED`, `HOP_NOT_COVERED`, `COMPONENT_GAP`.

## `latest`

`--to C=latest` is not resolved yet: no signed release-line snapshot ships, so
Prufyx cannot know the newest release. The component is reported as
`LATEST_NOT_RESOLVED` and is not planned. Give an explicit version.

## Output and exit codes

`--format human` (default), `markdown` or `json` (schema
`prufyx.io/upgrade-plan/v1alpha1`). Exit codes: `0` PASS, `10` BLOCKED, `11`
otherwise; usage and integrity errors as `scan`. `plan` refuses `--fail-on`; the exit code is
the plan verdict. The scan-only output flags (`--show-passes`, `--verbose`,
`--only-blocked`) do not change a plan.
