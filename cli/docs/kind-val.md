# KIND-VAL: checking the knowledge against real API servers

Prufyx's Kubernetes knowledge is a set of claims: a release line stops
serving these API versions and still serves those; a project's release no
longer serves a custom-resource version. KIND-VAL checks such claims against
real API servers: it creates one [kind](https://kind.sigs.k8s.io/) cluster
per release line, reads what each serves, applies manifests with a server
dry run, scans the same manifests with `prufyx`, installs the upstream CRDs
of consecutive project releases, and answers every claim with one outcome.

It is a maintainer tool. Nothing here runs in the normal test suite, which
needs no network and no cluster; the tool's own tests use fakes and a
synthetic project.

## The claims contract

The input is a list of claims; the output gives one outcome per claim. Both
are JSON with a `schema` member and are decoded strictly: an unknown member
is refused, so the shape only changes with the schema name. The `v1` shapes
follow; `v2` adds verdicts, reason codes and control claims (see
[Verdicts, reasons and controls](#verdicts-reasons-and-controls)).

### Input: `prufyx.io/kind-val-claims/v1`

```json
{
  "schema": "prufyx.io/kind-val-claims/v1",
  "claims": [
    {"id": "k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served",
     "kind": "k8s-served-api",
     "subject": {"line": "1.32", "group": "flowcontrol.apiserver.k8s.io", "version": "v1beta3", "kind": "FlowSchema"},
     "expect": "not_served",
     "evidence": {"source": "k8sremovals:component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"}},
    {"id": "k8s.1.31-to-1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.removal",
     "kind": "k8s-removal",
     "subject": {"from": "1.31", "to": "1.32", "group": "flowcontrol.apiserver.k8s.io", "version": "v1beta3",
                 "kind": "FlowSchema", "ruleId": "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0"}},
    {"id": "example.v2.0.0.gadgets.example.io.v1beta1",
     "kind": "crd-version",
     "subject": {"project": "example", "repo": "github.com/example/example",
                 "release": {"tag": "v2.0.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
                 "crd": "gadgets.example.io", "group": "example.io", "version": "v1beta1", "kind": "Gadget",
                 "served": false, "storage": false}},
    {"id": "example.crd-version-removal.gadgets-example-io.1-9-0-to-2-0-0",
     "kind": "crd-removal",
     "subject": {"project": "example", "repo": "github.com/example/example",
                 "from": {"tag": "v1.9.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
                 "to":   {"tag": "v2.0.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
                 "group": "example.io", "version": "v1beta1", "kind": "Gadget",
                 "ruleId": "example.crd-version-removal.gadgets-example-io.1-9-0-to-2-0-0"}},
    {"id": "example.v2.0.0-to-v2.1.0.quiet",
     "kind": "crd-pair",
     "subject": {"project": "example", "repo": "github.com/example/example",
                 "from": {"tag": "v2.0.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
                 "to":   {"tag": "v2.1.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]}}},
    {"id": "some-rule", "kind": "addon-rule", "subject": {"project": "example", "ruleId": "example.rule"}}
  ]
}
```

| `kind` | `subject` | What is checked |
| --- | --- | --- |
| `k8s-served-api` | `line`, `group` (empty for the core group), `version`, `kind`; `expect` is `served` or `not_served` | Discovery of the cluster of `line` lists `group/version Kind`, or does not. |
| `k8s-removal` | `from`, `to` (release lines), `group`, `version`, `kind`, optional `ruleId` | The `from` cluster serves the API and the `to` cluster does not (discovery and a server dry run of a manifest agree), and `prufyx scan --from <from> --to <to>` on that manifest is `BLOCKED` (exit 10) naming `API_VERSION_NOT_SERVED`. With `ruleId`, that rule must be among the matched rules. |
| `crd-version` | `project`, `repo`, `release` (`tag`, `commit`, `files`), `crd`, `group`, `version`, `kind`, `served`, `storage` | After the release's files are installed, the cluster's definition declares the version with these flags, and a dry-run object of the version is accepted or rejected for another reason (served) or answered "no matches" (not served). |
| `crd-removal` | `project`, `repo`, `from`, `to` (releases), `group`, `version`, `kind`, optional `ruleId` | The version is served after installing `from` and not served after installing `to`. The result also records whether applying `to` over `from` in place was refused (`status.storedVersions`) and whether `to` no longer defines the CRD at all (a plain apply leaves it in the cluster). |
| `crd-pair` | `project`, `repo`, `from`, `to` (releases) | Every version served after `from` is still served after `to`; the versions that disappeared are named otherwise. |
| `crd-field` | `project`, `repo`, `from`, `to` (releases), `crd`, `group`, `version`, `kind`, `path`, `change`, optional `value` | An object that sets only `path` is accepted by the `from` schema and refused by the `to` schema for the reason `change` names, as the API server's strict field validation reports it. See [crd-field](#crd-field). |
| `addon-rule` | free (`project`, `ruleId`, `from`, `to`, ...) | Not evaluated here: outcome `undetermined`. Reserved so a ledger can carry every claim through one file. |

`evidence` is free-form JSON, passed through to the output. Releases of one
project with the same `tag` must have the same `commit` and `files` across
claims. Files are repository paths, fetched from
`https://raw.githubusercontent.com/<owner>/<name>/<commit>/<path>`; only
`kind: CustomResourceDefinition` documents are installed.

`kindval claims --lines ...` derives the `k8s-served-api` and `k8s-removal`
claims from the removal table built into the binary
(`internal/k8sremovals`): a version removed at line L is not served by L or
any later line, was served by L-1, the versions the table names as still
served at L are served there, and, when both lines are in the matrix, the
hop L-1 -> L is a removal claim. Nothing is claimed about a removed version
below L-1, since the table does not record when a version was introduced.
`--crd FILE` merges the claims of another file, for example custom-resource
claims written from the `crd.version-removal` extractor's proof.

### crd-field

A `crd-field` claim says that an object the `from` release's CRD schema
accepts is refused by the `to` release's schema, for one reason:

```json
{"id": "example.v2.0.0-to-v3.0.0.gadgets.spec.size",
 "kind": "crd-field",
 "subject": {"project": "example", "repo": "github.com/example/example",
             "from": {"tag": "v2.0.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
             "to":   {"tag": "v3.0.0", "commit": "<40 hex>", "files": ["config/crd/gadgets.yaml"]},
             "crd": "gadgets.example.io", "group": "example.io", "version": "v1", "kind": "Gadget",
             "path": "spec.size", "change": "field-type-changed", "value": "large"},
 "evidence": {}}
```

`path` is dot-separated property names (an array is crossed through its
items, which the object fills with one element: `spec.ports.name` is
`spec.ports[0].name`; a map value is named by its key: `spec.labels.team`);
it may not start with `apiVersion`, `kind` or `metadata`. The API server
spells an array element two ways: strict decoding and
`x-kubernetes-validations` rules write `spec.ports[0].name`, the schema
validation causes write `spec.ports.0.name`; a map value is
`spec.labels.team`, except in an `x-kubernetes-validations` cause, which
writes `spec.labels[team]`. Both sides of every comparison are written one
way (a bracketed index or key as a dot segment) before they are compared;
the match stays exact (no prefix or suffix, and `spec.ports.1.name` never
matches `spec.ports[0].name`). `change` is one of `field-removed`, `field-required-added`,
`field-type-changed`, `enum-value-removed`, `validation-tightened`. `value` is
the value that `from` accepts and `to` should refuse; it is required for
`field-type-changed`, `enum-value-removed` and `validation-tightened`. The
claim's id is the caller's.

The claim is decided within the run of its release pair (the same install
and cleanup as `crd-removal` and `crd-pair` claims; the pair's definitions
are deleted afterwards):

1. After `from` is installed, the definition is read back from the cluster
   (`kubectl get crd -o json`) and the path is walked in the version's
   `openAPIV3Schema`. A schema that preserves unknown fields at the root, an
   ancestor or the field, a version without a schema, a field without a type,
   or a `status` field of a version with the status subresource (status is
   dropped on create): `undetermined`, `schema-permissive`. The definition,
   the version or the path absent (a map key reached through
   `additionalProperties` counts as absent for `field-removed` and
   `field-required-added`), or, for `enum-value-removed`, a `from` enum that
   does not list the value: `path-not-in-from`.
2. A minimal object of the group, version and kind (`metadata.name:
   kindval-field`, `namespace: default` unless the scope is `Cluster`) sets
   only the path, with the intermediate objects and one-element arrays the
   schema asks for: for `field-removed` a placeholder of the field's type,
   for `field-required-added` the parent without the field, otherwise the
   claim's `value` (absent or `null`: `value-missing`). Required siblings at
   every level (and the first branch of a `oneOf`/`anyOf` that only lists
   required names) get placeholders from the `from` schema (first enum value,
   `"x"` padded to `minLength`, `1` or `minimum`, `true`, `{}`, `[]`); when a
   placeholder cannot be made: `object-not-buildable`. Placeholders do not
   follow `pattern`, `format`, a `maximum` below 1 or `nullable`; a schema
   that needs them refuses the object at `from`, and the claim is
   `from-rejected` (never refuted).
3. `kubectl create --dry-run=server --validate=strict -f -` must be accepted.
   A refusal: `from-rejected` (never refuted). No answer from the API server
   (kubectl did not run, transport failure, a client-side validation error,
   or a server that could not handle the request: `ServiceUnavailable`,
   `Timeout`, `TooManyRequests`, `InternalError` or an etcd failure that names
   no webhook): `error`, `server-no-answer`. Any other `Error from server
   (...)` is an answer.
4. `to` is applied in place over `from` and the object is sent again; then the
   pair's definitions are deleted, `to` is installed fresh, and the object is
   sent a third time. The fresh install decides: right after an in-place
   update the server may still validate against the `from` schema. The
   in-place answer is a cross-check: if it refuses where the fresh install
   accepts, or refuses differently: `other-rejection`. When the in-place
   apply itself is refused, or the in-place dry run gets no answer from the
   API server, the detail says so and the fresh install alone decides.
5. The fresh answer is matched against a closed set of messages, on the exact
   server path:

| `change` | `confirmed` when `to` refuses with | `refuted` when |
| --- | --- | --- |
| `field-removed` | the strict decoding error `unknown field "<path>"`, and `to`'s schema no longer has the path | `to` accepts the object and its schema declares the path |
| `field-required-added` | `<path>: Required value` | `to` accepts the object and its schema declares the path |
| `field-type-changed` | `<path>: Invalid value: ...` naming the type (`in body must be of type`) | `to` accepts the object and its schema declares the path |
| `enum-value-removed` | `<path>: Unsupported value` | `to` accepts the object and its schema declares the path |
| `validation-tightened` | `<path>: Invalid value` (not a type error; a `x-kubernetes-validations` rule reports this way), `Too long` or `Too many` | `to` accepts the object and its schema declares the path |

Everything else is `undetermined` with `other-rejection`, the server's message
in `detail`: a refusal for another reason, on another path (also a parent: a
removed ancestor is a wider change than claimed, claim the ancestor), a path
absent from `to`'s schema for a change other than `field-removed`, a `to`
release that no longer defines the CRD, an answer from a webhook. When `to` refuses on the path as claimed and also for
other causes on other paths, the claim is confirmed and an `INFO` finding
`<id>.also` lists the other causes. `to` accepting while its schema preserves
unknown fields at the path is `schema-permissive`, never refuted; `to`
accepting the object while the path is absent from its schema is
`other-rejection`, never refuted: for an object that sets the path, strict
field validation would have refused an undeclared field, so it did not
decide; for `field-required-added`, the field is gone, a wider change than
claimed. A refuted claim raises a
`MEDIUM` finding.

The crd run records each claim in `fields` (additive): the claim id, the
pair, the server path, the digest of the object sent, the answers at `from`,
after the in-place update and after the fresh install, whether the in-place
apply was refused, the state of `to`'s schema at the path (`present`,
`absent`, `permissive`), the matched pattern, or the skip reason or error.

Limits:

- `refuted` means "the CRD schema at `to` accepts the object", not "the
  project accepts it": validation by admission webhooks or by the project's
  controllers is out of reach of a dry run on a cluster without them.
- A field under `x-kubernetes-preserve-unknown-fields` is never decided.
- An `x-kubernetes-validations` rule is reported on the schema node that
  carries it: the claim's path must be that node. Rules that compare with the
  old object (`oldSelf`) do not run on create, and rules that need cluster
  state are not exercised.
- A field `to` gives a `default` is filled in before validation: a
  `field-required-added` claim on it is refuted.
- When `to` also drops a required sibling the object fills, the strict
  decoding error is all the server says: `other-rejection`.

### Output: `prufyx.io/kind-val-results/v1`

```json
{
  "schema": "prufyx.io/kind-val-results/v1",
  "generatedAt": "2026-10-10T07:30:00Z",
  "prufyx": {"commit": "<40 hex>", "sha256": "sha256:..."},
  "logDigest": "sha256:...",
  "lines": [{"line": "1.37", "serverVersion": "v1.37.0", "image": "kindest/node:v1.37.0@sha256:...", "served": 72}],
  "claims": [{"id": "...", "kind": "k8s-served-api", "outcome": "confirmed", "detail": "not served by v1.37.0",
              "prufyxCommit": "<40 hex>", "nodeImageDigest": "sha256:...", "logDigest": "sha256:...", "evidence": {}}],
  "diffs": [{"from": "1.36", "to": "1.37", "removed": [], "added": [], "unknownRemovals": []}],
  "findings": [{"severity": "HIGH", "id": "...", "message": "..."}],
  "totals": {"claims": 0, "confirmed": 0, "refuted": 0, "undetermined": 0, "error": 0, "high": 0, "medium": 0, "info": 0}
}
```

Outcomes: `confirmed` (the API server agrees), `refuted` (it disagrees),
`undetermined` (no cluster or run covers the claim, or the kind is not
evaluated), `error` (the run for the claim failed: a fetch, an apply, or a
scan that gave no report, or a kubectl call that did not reach the API server: missing binary, connection refused, timeout, TLS or kubeconfig failure, which is never read as "served"). Only `confirmed` counts as agreement.
`nodeImageDigest` is the digest of the node image of the cluster the claim
was decided on (the `to` line of a removal, the CRD line for CRD claims);
`prufyxCommit` comes from `evaluate --prufyx-commit` (a development build
reports its revision as unbound); `logDigest` is the digest of the run log
at evaluation time.

Findings come from refuted claims and from the served-API difference
between consecutive lines (an API that disappears with no claim about it).
`HIGH`: a claim whose failure would let a false pass through (the scan
passes a removed API, a release still serves a version a claim removes, a
release dropped a version the claims keep). `MEDIUM`: a block or removal
claim the server contradicts, a scan that stays `UNKNOWN` on a removed API,
a removed beta or stable API no claim names, a definition whose versions or
flags differ from the claim, a custom resource whose whole definition the
later release no longer ships with no claim about it (a plain apply keeps
the old definition, so its objects stay accepted until it is deleted). `INFO`: an alpha API that disappeared, a scan
that gave no report, a refused in-place CRD update, a definition a release
no longer defines.

## Verdicts, reasons and controls

A claims file of schema `prufyx.io/kind-val-claims/v2` asks for results of
schema `prufyx.io/kind-val-results/v2`. A `v1` claims file gives exactly the
`v1` results described above, byte for byte; `evaluate` reads both.
`kind-val.sh` writes `v1` claims (and so `v1` results, exactly as before)
unless it is given `--v2`; `kindval claims` writes `v1` unless it is given
`--schema v2`.

### What v2 adds

The v2 claims file has two more members: `lines`, the cluster matrix of the
run, and, among `claims`, the control claims of the run (`"control": "true"`
or `"false"`, ids starting with `control.`). Both come from `kindval claims`:
a claims file merged with `--crd` may not carry them, and every subcommand
refuses a v2 file whose controls are not exactly the reviewed controls of its
lines and of the kinds of its other claims (none missing, none added, none
changed). A control is an ordinary claim of an ordinary kind; the snapshots,
verdicts and custom-resource runs decide it on the same clusters as the
claims.

Every claim result gains:

- `verdict`: `confirmed-by-execution` (outcome `confirmed`), `refuted`,
  `undetermined` or `error`. The verdict is never stronger than what the API
  server showed in this run.
- `reason`: one code of the closed list below; empty only for
  `confirmed-by-execution`. `detail` stays the human explanation.

The results gain `controls` (one entry per control: `id`, `kind`, `line`,
`expected` (`true` or `false`), `outcome`, `ok`, `reason`, `detail`; omitted
when the run has no control), `totals.verdicts` (claims by verdict) and
`totals.controls` (one entry per kind and line: `state` `ok`, `failed`,
`incomplete` or `absent`, the number of `true` and `false` controls, the `failed` control
ids). Controls are never in `claims` and never in the claim totals. The
summary gains a `Controls` section with one line per `totals.controls`
entry.

| `reason` | Outcome | Meaning |
| --- | --- | --- |
| `not-evaluated` | undetermined | The kind is not evaluated here (`addon-rule`). |
| `no-snapshot` | undetermined | No snapshot of the line (or of a line of the hop). |
| `no-run` | undetermined | No run of the release pair, or no run installed the release. |
| `no-corpus-case` | undetermined | No dry run of the API on both lines of the hop, or no scan for it. |
| `not-probed` | undetermined | The custom-resource member was not probed on both releases. |
| `release-unavailable` | undetermined | The release cannot be installed from the claim's own evidence (its files hold no definitions or cannot be read). |
| `release-not-installed` | undetermined or error | A run that should have installed the release did not reach it. |
| `server-no-answer` | error | A kubectl call got no answer from the API server. |
| `scan-no-report` | error | `prufyx scan` gave no report. |
| `install-failed` | error | A fetch, apply, wait or cleanup of a release failed. |
| `crd-missing` | refuted | The cluster holds no such definition after the install. |
| `version-not-declared` | refuted | The definition does not declare the version. |
| `disagreement` | refuted | The API server (or the scan) contradicts the claim. |
| `image-digest-mismatch` | error | The node is not proven to run the configured image digest. |
| `canary-failed` | error | A control of the kind on this line did not come out as expected. |
| `controls-absent` | undetermined | The controls file has controls for the kind, but none ran for a group the claim depends on (for a removal, also the served-API group of either line), or all that ran have the same expectation. |
| `schema-permissive` | undetermined | `crd-field`: the schema preserves unknown fields at the path (or has no schema, or no type there): nothing can be refused. |
| `path-not-in-from` | undetermined | `crd-field`: the definition, version or path is absent after installing `from`, or its enum does not list the claimed value. |
| `value-missing` | undetermined | `crd-field`: the change needs a `value` and the claim has none. |
| `object-not-buildable` | undetermined | `crd-field`: no object satisfying the `from` schema's required fields could be built. |
| `from-rejected` | undetermined | `crd-field`: the `from` schema refuses the object. |
| `other-rejection` | undetermined | `crd-field`: `to` refuses the object, but not for the claimed change on the claimed path. |

### The void rule

Controls are grouped like the claims they guard: a `k8s-served-api` claim by
its `line`, a `k8s-removal` claim by its `to` line, and the custom-resource
kinds by kind (they are decided on the one custom-resource line of the run).
A `k8s-removal` claim reads the served APIs and dry runs of both its lines,
so it depends on three groups: the removal group of its `to` line and the
served-API groups of its `from` and `to` lines (a run with removal claims
therefore always carries the served-API controls of its lines). For each
claim:

- Every control of the group came out as expected (`true`: confirmed;
  `false`: refuted): the claims are reported as without controls, plus
  `verdict` and `reason`.
- Any control of a group it depends on did not (the other outcome,
  `undetermined` or `error`): the claim becomes `outcome: error`,
  `verdict: error`, `reason: canary-failed`; `detail` names the failed
  controls and keeps the former detail after `was:`. A claim that would have
  been refuted is reported as error too: nothing from a void group is
  evidence either way, so the findings those claims raised (and, for a void
  `crd-removal` group, the missed-removal findings of the pairs) are dropped.
  One `HIGH` finding `canary-failed/<kind>/<line>` (`canary-failed/<kind>`
  for the custom-resource kinds) names each failed control with its outcome,
  reason and detail, and the findings it dropped. A control that repeats a
  claim (the documented removals are both) therefore turns a knowledge defect
  on that line into `canary-failed`: read the failed control's detail.
- The group has no control although the controls file has entries for the
  kind (a claim about a line outside the matrix, a hop between lines that are
  not one minor apart), or every control of the group came out as expected
  but all have the same expectation (`state: incomplete`): a confirmed or
  refuted claim becomes `undetermined` with `reason: controls-absent`, and its
  findings are dropped; `totals.controls` has the entry with `state: absent`
  or `incomplete`. One expectation cannot tell a working harness from one
  that gives the same answer to everything.
- The controls file has no entry for the kind (`addon-rule`): the claims are
  unchanged and `totals.controls` has `{kind, state: "absent"}`. No control is
  ever made up at run time.

Controls failing on one line void that kind's claims on that line only (and
the removal claims of the hops into and out of it); the other lines and
kinds are unaffected. Controls add no other finding and take no part in the
missed-removal check. The served-API difference between two lines is kept
only when the served-API groups of both lines are `ok`: otherwise its
`diffs` entry and its `diff.<line>.*` findings are dropped (and listed in the
`canary-failed` finding when a group failed). A v2 run without served-API or
removal claims has no served-API controls and so reports no differences.

`k8s-removal` controls are decided on the API servers only: the `from` line
serves the API (discovery and dry run) and the `to` line does not. The scan
verdict is not part of a control, so a scan or knowledge regression on a hop
refutes the affected removal claims (which still require the scan to block)
instead of voiding the hop. The scan stage itself therefore has no canary.

The hops whose removals the upstream deprecation guide does not document
(1.33, 1.34, 1.37 in the current table) have only `false` removal controls,
so their `k8s-removal` groups are `incomplete` and their removal claims stay
`undetermined` until a reviewed `true` control is added for the hop.

A control that cannot be decided is not as expected: a line without a
snapshot, or a custom-resource run limited with `kindval crd --pair` (or
missing), voids the groups whose controls it would have decided.

### The controls file

`internal/tools/kindval/controls.json` (`prufyx.io/kind-val-controls/v1`) is
embedded in the binary. Each entry is a claim of the claims contract plus
`control`, and, for the Kubernetes kinds, an optional `lines` range
(`{"from": "1.32"}`; empty bounds are open). An entry with `lines` names no
line of its own: `kindval claims` expands it for every line of the matrix in
range (a `k8s-served-api` entry gets the line, id suffixed `.<line>`; a
`k8s-removal` entry gets the hop from the line one minor below when the
matrix has it, id suffixed `.<from>-to-<to>`). An entry without `lines` is
used when the matrix has its line or both lines of its hop. Custom-resource
controls name a project of their own (`control.<project>`), so they never
share a release with the claims; they are added whenever the claims have their
kind. A line named twice in `--lines` counts once; a v2 claims file that
names a line twice is refused.

To add or change a control: open a reviewed pull request that edits
`controls.json` and cites, for every value, the upstream file at a commit
(for Kubernetes, the deprecation guide in `kubernetes/website`; for a
project, the CRD manifest at the release's commit), in the entry's
`evidence` and in the pull request. Keep at least two `true` and two `false`
controls per kind.

## Running

Needs `kind`, `kubectl` and `docker`, a built `prufyx`, and network access
to pull node images and fetch CRD manifests. One cluster exists at a time
(about 1 GB of memory per cluster); each is deleted before the next is
created, also on error.

```sh
cat > images.txt <<'EOF'
1.36 kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
1.37 kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
EOF
cli/scripts/kind-val.sh --images images.txt --out /tmp/kind-val --prufyx "$HOME/.local/bin/prufyx" \
  --prufyx-commit "$(git rev-parse HEAD)" [--crd-claims pairs.json] [--crd-line 1.37] \
  [--kind-config FILE] [--post-check 'some health command'] [--v2]
```

Pin node images by digest from the kind release notes: the script and `kindval snapshot`/`crd` refuse an image without `@sha256:<64 hex>`. The script also records the repository digests of the image the node container really runs (`docker inspect`) as `observedImageDigests`; a claim decided on a node whose observed digests do not include the configured one is an `error`. The clusters are
created from `cli/scripts/kind-val-cluster.yaml`, which serves every beta
API (`api/beta=true`): beta APIs introduced since Kubernetes 1.24 are off by
default, and a claim about a version a line serves is only checkable on a
server that serves it. The script writes `claims.json`, `runs/` (one
snapshot and verdicts file per line, one crd file for the chosen line),
`corpus/` (the manifests scanned), `results.json` and `summary.md`. Without
`--kindval` it runs a `kindval` executable placed next to the script, else
the tool with `go run` from the `cli` directory. `--post-check` runs a command after each
cluster is deleted and stops the run when it fails.

The subcommands can be run one by one against any kubeconfig:

```text
kindval claims   --lines 1.36,1.37 [--crd FILE] [--schema v2] --out claims.json
kindval snapshot --kubeconfig KC --line 1.37 --image REF --out runs/snapshot-1.37.json
kindval verdicts --kubeconfig KC --line 1.37 --dir corpus --out runs/verdicts-1.37.json \
                 --claims claims.json --prufyx BIN --from-version 1.36.4 --to-version 1.37.0
kindval crd      --kubeconfig KC --line 1.37 --image REF --claims claims.json --out runs/crd-1.37.json [--pair ID]
kindval evaluate --claims claims.json --runs runs --out results.json --summary summary.md \
                 --prufyx BIN --prufyx-commit SHA --log run.log
```

The corpus of `verdicts` is one minimal manifest per removal the table
knows (and per `k8s-removal` claim), plus controls every line serves; each
is submitted with `kubectl create --dry-run=server` and, when `--prufyx` is
given, scanned for the hop into this line. `evaluate` pairs each line's
scan with the previous line's dry run, so the previous line needs a
verdicts file too. The CRD check installs the earlier release's
definitions, probes every declared version, applies the later release over
them (recording a refusal or the definitions it no longer defines), then
installs the later release from scratch and probes it, and deletes the
pair's definitions.

A `crd-version` claim whose release no pair of the claims covers (a batch
may hold the version claims of a release without its pair claim) is not
left undetermined: after the pairs, `kindval crd` installs that release on
its own, from the repository, commit and files the claim cites, probes it,
and deletes its definitions before the next release (one cluster, one
release at a time). The result is recorded in the optional `releases` member
of the crd run; the run schema is unchanged. The claim is then decided as it
is for a pair's release. It stays `undetermined`, with the reason in
`detail`, only when the cited files were fetched but hold no definitions or
cannot be read; a failed fetch (network, HTTP status), install or cleanup is
`error`, never confirmed. With
`--pair ID` only that pair is run.

## Limits

- A dry-run create probes whether the API exists; a `rejected` outcome
  (validation, admission, a conversion webhook that is not installed) still
  counts as served.
- The CRD check installs definitions only, never the project's controllers,
  and creates no objects (dry runs only), so a stored-version migration is
  exercised only through the in-place update attempt.
- The scan's exit depends on the rules built into the given `prufyx`: a
  removal the table knows but no published rule decides is reported as
  `UNKNOWN` with the `API_VERSION_NOT_SERVED` gap, which the harness counts
  as refuted (`MEDIUM`), never as a pass.
