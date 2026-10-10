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
is refused, so the shape only changes with the schema name.

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
    {"id": "some-rule", "kind": "glm-addon-rule", "subject": {"project": "example", "ruleId": "example.rule"}}
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
| `glm-addon-rule` | free (`project`, `ruleId`, `from`, `to`, ...) | Not evaluated here: outcome `undetermined`. Reserved so a ledger can carry every claim through one file. |

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
scan that gave no report). Only `confirmed` counts as agreement.
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
flags differ from the claim. `INFO`: an alpha API that disappeared, a scan
that gave no report, a refused in-place CRD update, a definition a release
no longer defines.

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
  [--kind-config FILE] [--post-check 'some health command']
```

Pin node images by digest from the kind release notes. The clusters are
created from `cli/scripts/kind-val-cluster.yaml`, which serves every beta
API (`api/beta=true`): beta APIs introduced since Kubernetes 1.24 are off by
default, and a claim about a version a line serves is only checkable on a
server that serves it. The script writes `claims.json`, `runs/` (one
snapshot and verdicts file per line, one crd file for the chosen line),
`corpus/` (the manifests scanned), `results.json` and `summary.md`. Without
`--kindval` it runs the tool with `go run` from the `cli` directory; pass a
built binary to run elsewhere. `--post-check` runs a command after each
cluster is deleted and stops the run when it fails.

The subcommands can be run one by one against any kubeconfig:

```text
kindval claims   --lines 1.36,1.37 [--crd FILE] --out claims.json
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
