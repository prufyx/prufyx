# KIND-VAL: checking the knowledge against real API servers

Prufyx's Kubernetes knowledge is a set of claims: a release line stops
serving these API versions, still serves those, and a project's release no
longer serves a custom-resource version. KIND-VAL checks such claims against
real API servers: it creates one [kind](https://kind.sigs.k8s.io/) cluster
per release line, reads what each serves, applies manifests with a server
dry run, scans the same manifests with `prufyx`, installs upstream CRDs of
two consecutive project releases, and reports every claim as confirmed,
refuted or unevaluated.

It is a maintainer tool. Nothing here runs in the normal test suite, which
needs no network and no cluster; the tool's own tests use fakes.

## What is checked

1. **Served APIs.** For every release line, the served `group/version Kind`
   pairs are read from discovery (`/api`, `/apis`, each group version). The
   removal table built into the binary (`internal/k8sremovals`) gives the
   claims: a version removed at line L is not served by L or any later line,
   was served by L-1, and the versions the table names as still served at L
   are served there. Consecutive lines are also compared: an API that one
   line serves and the next does not, with no entry in the table, is a
   finding (`MEDIUM`, or `INFO` for an alpha version).
2. **Verdicts.** A corpus of small manifests, one per removal the table knows
   (plus controls every line serves), is submitted to each cluster with
   `kubectl create --dry-run=server` and scanned with
   `prufyx scan --from kubernetes=<previous line> --to kubernetes=<this line>`.
   When the previous line accepts a manifest and this line answers "no such
   API", the scan must be `BLOCKED` (exit 10) naming `API_VERSION_NOT_SERVED`;
   a `PASS` there is a `HIGH` finding, an `UNKNOWN` without the gap is
   `MEDIUM`, an `UNKNOWN` that names the gap is `INFO` (no published rule
   decides the hop). An API neither line serves must not pass (`HIGH`
   otherwise). An API this line still serves must not be blocked (`MEDIUM`).
3. **Custom resources.** For each supplied pair of consecutive releases of a
   project, the CRD manifests of both releases are fetched from GitHub,
   pinned by commit. The earlier release's definitions are installed and
   every declared version is probed with a dry-run create; the later
   release's definitions are then applied over them (as an upgrade would),
   and, when the API server refuses that, installed from scratch. A version
   the claims say was removed must be served before and not after (`HIGH`
   when the later release still serves it); a version the claims keep must
   still be served (`HIGH` otherwise); each definition's declared versions
   with their served and storage flags must match the claims (`MEDIUM`
   otherwise). A refused in-place update (a dropped version still in
   `status.storedVersions`) is recorded as `INFO`.

## Files

Every file is JSON with a `schema` member.

| Schema | Written by | Content |
| --- | --- | --- |
| `prufyx.io/kind-val-claims/v1` | `kindval claims` | `kubernetes`: one claim per line and API (`line`, `api`, `expect` = `served` or `not_served`, `source`); `customResources`: pairs (`project`, `repo`, `from`/`to` with `tag`, `commit`, `files` and `crds` with `versions[].served/storage`). |
| `prufyx.io/kind-val-snapshot/v1` | `kindval snapshot` | The served pairs of one cluster, `serverVersion`, `image`. |
| `prufyx.io/kind-val-verdicts/v1` | `kindval verdicts` | Per corpus case: the server outcome (`accepted`, `not_served`, `rejected`) and the scan's exit, verdict, gaps and matched rules. |
| `prufyx.io/kind-val-crd-run/v1` | `kindval crd` | Per pair: files fetched (with digests), definitions read back, object probes, in-place update outcome. |
| `prufyx.io/kind-val-results/v1` | `kindval evaluate` | `claims[]` with `status` `confirmed`/`refuted`/`unevaluated`, `verdicts[]`, `diffs[]`, `findings[]` (`HIGH`/`MEDIUM`/`INFO`), `totals`. |

The claims file is the interface for other producers: a tool that drafts
rules can write its claims in this shape (Kubernetes claims by line and API,
custom-resource pairs by release) and get back one status per claim.
`kindval claims --crd FILE` merges the `customResources` of such a file
with the Kubernetes claims of the embedded table. The tool's test data uses
a synthetic project; no upstream project is named in the repository.

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
  [--crd-claims pairs.json] [--crd-line 1.37] [--post-check 'some health command']
```

Pin node images by digest from the kind release notes. The script writes
`claims.json`, `runs/` (one snapshot and verdicts file per line, one crd
file for the chosen line), `corpus/` (the manifests scanned),
`results.json` and `summary.md`. Without `--kindval` it runs the tool with
`go run` from the `cli` directory; pass a built binary to run elsewhere.
`--post-check` runs a command after each cluster is deleted and stops the
run when it fails (a check that the host is still healthy).

The subcommands can be run one by one against any kubeconfig:

```text
kindval claims   --lines 1.36,1.37 [--crd FILE] --out claims.json
kindval snapshot --kubeconfig KC --line 1.37 --image REF --out runs/snapshot-1.37.json
kindval verdicts --kubeconfig KC --line 1.37 --dir corpus --out runs/verdicts-1.37.json \
                 --prufyx BIN --from-version 1.36.4 --to-version 1.37.0
kindval crd      --kubeconfig KC --line 1.37 --claims claims.json --out runs/crd-1.37.json [--pair ID]
kindval evaluate --claims claims.json --runs runs --out results.json --summary summary.md
```

`evaluate` pairs each line's verdicts with the previous line's server
outcomes, so the previous line must have a verdicts file too (its scan part
is not needed). A claim for a line without a snapshot, a pair without a
run, or a scan that produced no report is `unevaluated`, never confirmed.

## Limits

- kind runs a default API server: alpha APIs and non-default feature gates
  are off, so a beta API that a gate guards can be absent on a line that
  would serve it with the gate on. The claims derived from the table do not
  assert that a removed version was served below its previous line.
- A dry-run create probes whether the API exists; a `rejected` outcome
  (validation, admission, a conversion webhook that is not installed) still
  counts as served.
- The CRD check installs definitions only, never the project's controllers,
  and creates no objects (dry runs only), so stored-version migration is
  exercised only through the in-place update attempt.
