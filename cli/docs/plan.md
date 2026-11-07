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
- Other components follow, one stage per hop. Their order is `inferred` when
  a Kubernetes path is planned or multiple components have planned hops:
  reviewed evidence does not establish their relative order. Verify the order
  before upgrading. With only one planned component, the order is `free`.
- A whole-upgrade finding is shown in exactly one stage: the last stage of its
  component.
- A component whose path the scan could not plan (a gap, no reviewed path
  policy for an app) is listed under *Not planned* with the scan's gap.

## Verdicts

Per stage: `BLOCKED` (a rule blocks the hop), `UNSUPPORTED` (outside a
documented support range), `UNKNOWN`, `PASS`. The plan verdict is the worst
stage; a plan with any not-planned component is at best `UNKNOWN`.

A stage is `PASS` only when all of these hold: its hop is `COVERED` by the
scan, the scan has no gap for the component, the order is `required` or `free`, the hop
actions (CRD stored-version migrations and similar) are checked, and the node
rolls are planned. **This version checks no hop actions and plans no node
rolls, so no stage is `PASS` yet.** A `COVERED` hop shows as `UNKNOWN` with
the reasons `HOP_ACTIONS_NOT_CHECKED` (and `NODE_ROLLS_NOT_PLANNED` for
Kubernetes). `BLOCKED` is fully decided: a blocker is a blocker.

Reason codes: `ORDER_INFERRED`, `HOP_ACTIONS_NOT_CHECKED`,
`NODE_ROLLS_NOT_PLANNED`, `HOP_NOT_COVERED`, `BLOCKED_BY_EARLIER_FINDING`,
`COMPONENT_GAP`, `LATEST_NOT_RESOLVED`, `PATH_NOT_PLANNED`.

## Example: a long route (1.29 to 1.36)

[`examples/old-to-latest/rendered.yaml`](../../examples/old-to-latest/rendered.yaml)
is a synthetic apply set that uses only API versions Kubernetes 1.37 serves
(copy it to an owner-only file before use). A golden test
(`TestPlanOldToLatestExample`) pins the statuses below.

```sh
prufyx plan rendered.yaml --from kubernetes=1.29.15 --to kubernetes=1.36.0 \
  --kubelet-version-min 1.33.0 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required
```

What is printed (knowledge revision `cncf-2026-09-13.8`): 7 stages, 1.29.15 to 1.30
up to 1.35 to 1.36.0; each `hop status: COVERED`, verdict `UNKNOWN`, reasons
`HOP_ACTIONS_NOT_CHECKED` and `NODE_ROLLS_NOT_PLANNED`; plan verdict `UNKNOWN`,
exit `11`. This is not a whole-upgrade `PASS`. What stays unknown: hop actions
(stored-version migrations and similar), node rolls, the live environment, and
every component other than Kubernetes.

A `COVERED` hop needs every rule of that hop decided. Two kinds of rule need
input from you:

- Kubelet version skew rules, which exist for the hops from 1.32 to 1.33
  onward. They need `--kubelet-version-min` (or `minimumKubeletVersion` in
  `prufyx.yaml`). Without it these hops are `PARTIAL` with a
  `DECLARATION_MISSING` gap. The hops 1.29.15 to 1.30, 1.30 to 1.31 and 1.31 to
  1.32 carry no such rule, so they are `COVERED` with no kubelet input.
- Served-API removal rules need the complete apply set:
  `--resource-scope-complete` and `--target-api-apply-required`, with manifests
  that are the whole set. A manifest that uses an API version removed on the
  route is reported, correctly, instead of being covered.

The declared kubelet minimum is checked only on hops that have a kubelet-skew
rule (1.33 onward). The first three hops are `COVERED` without testing the
declared kubelet, so the declaration describes the nodes after the control plane
reaches 1.33; a kubelet newer than the API server is not valid Kubernetes, and
the early hops do not test for it. Kubernetes allows a kubelet up to three minor
lines behind the API server and never newer.
No single version satisfies the 1.33 and the 1.37.0 hops together, so a run to
`newest-covered` (1.37.0) from 1.29.15 is `BLOCKED` by the skew rule on some hop
whatever one version you declare. Plan the route in legs, each with the kubelet
version the nodes will have then, for example
`--from kubernetes=1.33.5 --to kubernetes=newest-covered --kubelet-version-min 1.34.0`
(4 stages to 1.37.0, all `COVERED`, plan verdict `UNKNOWN`).

## Provider support dates (advisory)

With `--distribution eks|gke|aks|k3s` the plan places the scan's [provider facts](scan.md#provider-facts-advisory) next to the stages: each Kubernetes stage lists the facts of the line the hop leaves, and a `Provider` block after the stages shows the target line, the forced-upgrade date (UNKNOWN unless an official sentence is recorded), anything that could not be read and the standing notes. Extended support is always labelled `extended (paid)` and is never recommended as a path.

Example (synthetic dates, evaluated at `--now 2026-11-07T00:00:00Z`, EKS 1.29.15 to 1.33.0 with a record that lists 1.31 to 1.33 only):

```
Stage 1  kubernetes 1.29.15 -> 1.30  UNKNOWN  [...]
         UNKNOWN provider_version_unknown: EKS 1.29 is not in the attested lifecycle rows, so its end-of-support dates are unknown
           Next: refresh the knowledge bundle, or confirm the dates with the provider
Stage 3  kubernetes 1.31 -> 1.32  UNKNOWN  [...]
         WARN provider_support_ended: EKS says 1.31 standard support ended 2025-11-26 (announced globally); extended (paid) ends 2026-11-26, automatic per the provider; extended support is not assumed, no opt-in was declared
Provider: eks (declared), evaluated at 2026-11-07T00:00:00Z, knowledge revision ...
  Target  WARN provider_support_ended: EKS says 1.33 standard support ended 2026-07-29 ...
  Target  INFO provider_forced_upgrade: EKS says it upgrades clusters still on 1.33 on 2027-07-29 (sentence ...)
```

State: **the evaluation is present, provider data is not yet published**, so a plan today shows `UNKNOWN provider_record_absent` on every stage. Provider facts never change a stage verdict, the plan verdict or the exit code, and never make a stage `PASS`. The plan evaluates no provider rule of its own: it places what the scan reported.

## `newest-covered`

`--to kubernetes=newest-covered` sets the target to the `.0` release of the
newest release line for which the knowledge holds a current reviewed
served-API list. It is the newest line Prufyx can evaluate. It is **not** the
newest release: a newer line may exist, and the patch is not resolved. The
plan prints the chosen version in a note, and the scan input records the
target source `newest-covered`. If no line is current (the lists expired) or
the component has no such lists, the command refuses; it never guesses. It
cannot be combined with an explicit `--to` for the same component.

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

JSON stages include the scan's hop input and engine contract digests when
available. Staged findings and unsupported results include their scan hop,
source citations and any available rule digest or crossed-line evidence;
staged notices include their original scan evidence. A whole-upgrade finding's
hop identifies the whole transition; the containing stage's digest identifies
only that stage. A crossed-line finding carries the digest for its decided
step. Missing source evidence or digests are not inferred. Results that cannot
be placed in a stage are reported as gaps and do not carry this evidence.
These additive JSON fields may require updates to strict JSON consumers. The
plan does not include the input bytes and these references do not verify them.

## Declared reference states (preview)

`prufyx plan --declared-state REQUEST.json` is a separate, JSON-only mode for
linking **authored reference states** to newly evaluated scoped reports. It
supports three embedded routes: Kubernetes served-API removal over a rendered
apply set, Cilium nonempty requires fields over a declared policy set, and
cert-manager's three removed monitoring values over exact merged JSON values.
Other knowledge origins and deployment modes remain UNKNOWN. It reads private
local files only and performs no cluster, network, apply or upgrade operation.

Each stage evaluates the selected component using the **before** state's input
bytes and the exact before/after component versions. An adjacent stage must
reference the identical manifest digest left by the preceding stage. A
`declared-edit` stage records an authored edit only. For example, B0 → B1 can
declare removal of an obsolete API and B1 → B2 can check the newly supplied B1
apply set. B1 is never represented as an observed remediation or upgrade output.
App ordering, migrations, storage, provider, runtime and workload effects remain
UNKNOWN. Every stage and aggregate is UNKNOWN unless a real rule blocks it;
scoped PASS claims in child reports do not establish whole-upgrade safety.
Cert-manager cannot bind an evaluation clock or general policy in its embedded
report; those missing bindings remain explicit gaps even when its values claim
passes. Real cert-manager blockers are preserved.

The request and every input file must be regular, single-link, owner-readable
files with no group/other permission bits. All path components must avoid
symlinks. Input locators are clean relative paths below the request directory;
absolute paths, `..`, links, changed files, oversize files and digest mismatches
are rejected. Each file is read once through the bounded reader, and that same
byte slice supplies both the digest and parser. No raw input document is emitted
in the report. Supply minimized route inputs; exclude Secrets, credentials and
unrelated objects. Limits are 1 MiB per file/request, 8 MiB total source bytes,
16 artifacts, 8 components and entries per artifact, and 32 stages.

### Request encoding

This preview uses fixed typed JSON rather than a general JSON canonicalization
standard. Emit compact UTF-8 JSON with the fields in the following order,
including explicit empty strings, null completeness, and empty arrays. One
trailing newline is accepted. Unknown/duplicate fields, alternate field order
or whitespace, and omitted schema fields are rejected. Hash the compact manifest
bytes without a trailing newline; hash source files byte-for-byte, including
their whitespace. Every digest uses the `sha256:` prefix and lowercase hex.
Paths are locators outside the manifest, so moving unchanged files does not
change the state identity.

| Object | Fields in encoding order |
| --- | --- |
| Request | `schema`, `context`, `artifacts`, `stages` |
| Context | `target`, `intent`, `policyId`, `policyDigest`, `trustBases`, `evaluatedAt`, `knowledgeOrigin`, `knowledgeRevision`, `knowledgeDigest`, `certManagerKnowledgeDigest` |
| Artifact | `name`, `manifest`, `files` |
| Manifest | `schema`, `target`, `intent`, `components`, `entries` |
| Component | `name`, `version`, `mode` |
| Entry | `role`, `logicalName`, `length`, `digest`, `distribution`, `complete`, `targetApplyRequired`, `schemaValidation`, `chartDigest` |
| File | `role`, `logicalName`, `path` |
| Stage | `index`, `component`, `from`, `to`, `before`, `after`, `beforeDigest`, `afterDigest` |

Both schemas are `prufyx.io/declared-state-plan/v1alpha1`. Components are sorted
uniquely by name, entries by `(role, logicalName)`; files correspond to entries
in the same order. Names are explicit artifact references; stages have contiguous
zero-based indices. `beforeDigest` and `afterDigest` assert the hashes of those
artifacts' manifests. Missing referenced artifacts or assertions leave gaps;
present conflicting identities or endpoint labels fail integrity.

`target` and `intent` must agree between context and every manifest. Component
names/entry roles are `kubernetes`, `cilium` and `cert-manager`. The corresponding
modes are `official-rendered-apply-set`, `official-policy-set` and
`official-chart-merged-values`. A stage selects one route; `declared-edit` needs
empty `from`/`to` and issues no compatibility verdict. Unselected fields in entries
use empty strings or false. Kubernetes uses `distribution`, `complete`, and
`targetApplyRequired`. Cilium uses `complete` (null means undeclared).
Cert-manager uses `schemaValidation` (`required` or `disabled`) and the before
and after entries' official `chartDigest` assertions. See the
[cert-manager check](projects/routes.md#check-cert-manager-values) for its exact chart contract.

Select `knowledgeOrigin: "embedded"` explicitly. Use an exact second-resolution
UTC `evaluatedAt` ending in `Z`; the issued CNCF report supplies the embedded
revision, pack digest and rule-source policy identity for context assertions.
An initially empty policy/knowledge assertion is reported as a gap, allowing
inspection of the authentic child report before pinning and re-evaluating.
`trustBases` names the accepted evidence bases (for example
`reviewed,mechanical,empirical,consensus`).
An empty `trustBases` uses that documented default for scoped evaluation and
adds an explicit missing-policy gap; it never establishes a caller policy.
Cert-manager's source-contract digest is separate from the CNCF pack digest;
its report exposes that exact digest as
`inputs.knowledgeRevisionDigest`. It has no general policy/clock input.

The output retains each canonical manifest, its verified identity, stage
associations, evaluation context, separate source/prepared/engine input digests,
and newly issued sealed child report bytes with their original citations and
omissions. The in-memory seal detects mutation before serialization; it is not
a signature or proof of authenticity for serialized JSON. Deterministic replay
means re-running the actual adapters with the original bytes/context and
comparing output, never accepting a caller-supplied report or checksum as proof.
Exit codes are `10` for a preserved blocker, `11` for UNKNOWN, `2` for request
syntax, and `3` for admission, evaluation or integrity failure.
