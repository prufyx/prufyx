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
