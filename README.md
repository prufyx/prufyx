# Prufyx

**Deterministic upgrade checks for Kubernetes and CNCF projects.**

Prufyx checks a planned upgrade against upstream evidence and returns
`PASS`, `BLOCKED`, or `UNKNOWN`. Every rule cites the exact upstream commit,
file, and line range it relies on, and says how it was established.

<!-- basis-counts:begin -->
Of the 303 active rules shipped today, 260 with basis `reviewed`, 43 with basis `mechanical`. A `reviewed` rule was established by a person who read the cited upstream evidence. A `mechanical` rule was derived from upstream source by an extractor program that is re-run and checked before the rule is accepted; no person reviewed it rule by rule. The 167 release-line attestations and served-API lists are separate records: 167 with basis `mechanical`.
<!-- basis-counts:end -->

Each rule states which way it was established, and
you can limit a `scan` to the ways you trust (by default `scan` uses every
basis except `lead`; `--require-basis reviewed` keeps only rules a person
reviewed). Prufyx evaluates locally and offline, uploads nothing, and a
deterministic engine computes every verdict: no model runs on your machine. When the
evidence does not decide the question, the answer is `UNKNOWN`, not a guess.

> **Status: public beta (pre-release).** The [`v0.1.0-beta.0` release](https://github.com/prufyx/prufyx/releases/tag/v0.1.0-beta.0)
> is available for testing. The binary carries embedded, time-limited knowledge,
> and `prufyx db update`
> refreshes it from the official signed feed. Results are scoped findings, not a
> guarantee that a whole upgrade is safe.

## Quickstart

Requires Go 1.26 (release builds use 1.26.10; see CONTRIBUTING.md).

**1. Build.**

```sh
git clone https://github.com/prufyx/prufyx.git
cd prufyx/cli
mkdir -p "$HOME/.local/bin"
go build -buildvcs=false -o "$HOME/.local/bin/prufyx" ./cmd/prufyx-community
export PATH="$HOME/.local/bin:$PATH"
```

**2. Scan your rendered manifests.** `scan` is the command to start with: it
reads manifests, says first whether the upgrade is blocked, and for every
problem names the file, line, object and fix. This example creates a small
manifest file with a CronJob that Kubernetes 1.25 no longer serves. With your
own chart, render it first (`helm template my-release ./chart > rendered.yaml`;
`kustomize build` works too) and keep the file owner-only.

```sh
mkdir -p /tmp/prufyx-demo && cd /tmp/prufyx-demo
cat > rendered.yaml <<'YAML'
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-report
  namespace: default
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: report
              image: example/report:1.0
          restartPolicy: OnFailure
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: report-settings
  namespace: default
data:
  mode: nightly
YAML
chmod 600 rendered.yaml
prufyx scan rendered.yaml --from kubernetes=1.24.0 --to kubernetes=1.25.0
```

Real output (exit `11`; the last line of the report, which carries a
timestamp and digests, is left out here):

```
UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (4 other areas were not checked)

kubernetes 1.24.0 -> 1.25.0: 1 hop (path policy sequential_minor)

NOT CHECKED (5)
  kubernetes   1 manifest(s) use API versions not in the Kubernetes 1.25 served list, stable (GA) versions only - check those API versions against the Kubernetes 1.25 API reference by hand
  kubernetes   1 manifest(s) use API versions Kubernetes 1.25 does not serve, removed on a line this upgrade enters - no reviewed rule decided them; migrate them to a served API version before upgrading, and the gaps for the step that enters the line say why
  kubernetes   it is not declared that these manifests are applied to the target kubernetes API - if they are, add targetApplyRequired: true to prufyx.yaml or pass --target-api-apply-required
  kubernetes   the kubernetes distribution is not declared - for upstream builds, add distribution: official_upstream to prufyx.yaml or pass --distribution official_upstream
  kubernetes   the kubernetes manifests are not declared to be the complete set you apply - if they are, add resourceScopeComplete: true to prufyx.yaml or pass --resource-scope-complete

Read 2 documents over 1 hop; 1 of 1 component has rules (partially evaluated).
Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.
Evidence: every finding cites pinned upstream source (--verbose). No network used.
```

The first line is the answer: `UNKNOWN` is not a pass. The five entries under
`NOT CHECKED` say what is missing. Three of them are facts only you can state
(see [declarations](cli/docs/declarations.md)).

**3. Declare what is true, run again.** If `rendered.yaml` is every manifest you
apply, it is applied to the target API, and the cluster runs upstream
Kubernetes, say so:

```sh
prufyx scan rendered.yaml --from kubernetes=1.24.0 --to kubernetes=1.25.0 \
  --distribution official_upstream \
  --resource-scope-complete \
  --target-api-apply-required
```

Real output (exit `10`):

```
BLOCKED: 1 problem must be fixed; 1 area was not checked

kubernetes 1.24.0 -> 1.25.0: 1 hop (path policy sequential_minor)
  1.24.0 -> 1.25.0   Kubernetes 1.25 stops serving CronJob through batch/v1beta1
                     rendered.yaml:1  CronJob default/nightly-report
                     fix: Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

NOT CHECKED (1)
  kubernetes   1 manifest(s) use API versions not in the Kubernetes 1.25 served list, stable (GA) versions only - check those API versions against the Kubernetes 1.25 API reference by hand

Read 2 documents over 1 hop; 1 of 1 component has rules (partially evaluated). 6 checks passed (--show-passes).
Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.
Evidence: every finding cites pinned upstream source (--verbose). No network used.
```

`BLOCKED` names the problem, where it is, and the fix. Fix it, run the same
command again. The `NOT CHECKED` entry that remains is not a failure of the
command: the reviewed list of the API versions Kubernetes 1.25 serves holds
stable (GA) versions only, so a manifest that uses an API version outside it is
listed as not checked rather than passed. Put the
declarations in a `prufyx.yaml` to stop typing them (see
[scan-config.md](cli/docs/scan-config.md)).

**Several hops or several components?** `prufyx plan` takes the same inputs and flags as `scan` and prints the whole route as ordered stages, one per hop, with each stage's blockers, gaps and the reason it is not `PASS`. Today no stage is `PASS`: hop actions and node rolls are not checked yet. See [plan.md](cli/docs/plan.md).

From the repository root, try a synthetic multi-component example. The [sample manifests](examples/multi-hop/rendered.yaml) are scan fixtures, not deployable resources. Copy them to an owner-only file and run:

```sh
demo_dir=$(mktemp -d)
cp examples/multi-hop/rendered.yaml "$demo_dir/rendered.yaml"
chmod 600 "$demo_dir/rendered.yaml"
prufyx plan "$demo_dir/rendered.yaml" \
  --from kubernetes=1.24.17 --to kubernetes=1.26.0 \
  --from cilium=1.19.0 --to cilium=1.20.0 \
  --from crossplane=1.20.0 --to crossplane=2.0.0 \
  --distribution official_upstream --resource-scope-complete \
  --target-api-apply-required --format json
```

The declarations describe this synthetic apply set, not your environment. In a
local development run evaluated at `2026-11-03T00:00:00Z` with embedded
knowledge revision `cncf-2026-09-13.8`, the plan returned `BLOCKED` (exit `10`): three stages were `BLOCKED` and one
was `UNKNOWN`. It showed two required Kubernetes hops and inferred the Cilium
and Crossplane order; verify that order before upgrading. The three findings
cite upstream sources, and each of the four stages includes hop input and
engine contract digests. Those evidence fields require a build containing the
staged evidence changes. This example does not check a live environment, hop
actions or node rolls. Results can change with the binary and knowledge used.

**From an old release to a much newer one.** The [old-to-latest example](examples/old-to-latest/rendered.yaml) is a synthetic apply set that uses only API versions Kubernetes 1.37 still serves. It shows what `plan` prints for a long route. Copy it to an owner-only file first, as above:

```sh
prufyx plan "$demo_dir/rendered.yaml" \
  --from kubernetes=1.29.15 --to kubernetes=1.36.0 \
  --kubelet-version-min 1.33.0 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required
```

With embedded knowledge revision `cncf-2026-09-13.8`, the plan prints seven stages, 1.29.15 to 1.30 through 1.35 to 1.36.0. Every stage shows `hop status: COVERED` and verdict `UNKNOWN`, with the reasons `HOP_ACTIONS_NOT_CHECKED` and `NODE_ROLLS_NOT_PLANNED`. The plan verdict is `UNKNOWN` (exit `11`). It is not a whole-upgrade `PASS`: CRD stored-version migrations and similar hop actions are not checked, and node rolls are not planned. `--resource-scope-complete` and `--target-api-apply-required` declare that the manifests are the complete apply set. `--kubelet-version-min` declares, it does not observe, the lowest kubelet version; declare only what is true.

Two limits show up in the same example. Without `--kubelet-version-min`, the three hops through 1.32 are still `COVERED`, because no kubelet skew rule applies to them, and the hops from 1.32 to 1.33 onward are `PARTIAL` with a `DECLARATION_MISSING` gap. The declared kubelet minimum is checked only on hops that have a kubelet-skew rule (1.33 onward); the first three hops are `COVERED` without testing it, so the declaration describes the nodes after the control plane reaches 1.33 (a kubelet newer than the API server is not valid Kubernetes, and the early hops do not test for it). And a single kubelet declaration is one fixed version: Kubernetes allows a kubelet up to three minor lines older than the API server, never newer, so no one version fits every hop from 1.29 to 1.37. With `--to kubernetes=newest-covered` and `--kubelet-version-min 1.33.0` the plan resolves 1.37.0 but is `BLOCKED` (exit `10`) at 1.37.0, as the kubelet is then four lines behind. Plan a second leg for the end of the route, for example `--from kubernetes=1.33.5 --to kubernetes=newest-covered --kubelet-version-min 1.34.0`: four stages to 1.37.0, all `COVERED`, still `UNKNOWN`. The kubelet versions in the two legs describe different points of the upgrade; roll the nodes between them yourself.

**Never add a declaration flag that is not true.** Prufyx does not default any
of them, because a false one turns `UNKNOWN` into an answer the evidence does
not support.

### What the exit code means

| Exit | Meaning |
| --- | --- |
| `0` | `scan`: `PASS FOR THE DECLARED SCOPE`. `check`: the checked rules passed, nothing more. |
| `10` | `BLOCKED`: a rule matched your input. |
| `11` | `UNKNOWN`: the evidence did not decide. Not a pass. |
| `2` / `3` | Input not accepted / integrity failure. |

`check` exit `0` is a scoped pass: add `--strict-exit` in CI, so it exits `14`.
Full meanings: [verdicts](cli/docs/verdicts.md) and [exit codes](cli/docs/exit-codes.md).
In CI, `scan` gates on its exit code. `--fail-on blocked` makes an `UNKNOWN`
scan exit `0` (except when manifests use an API version the target does not
serve); that `0` is not a pass, so use it knowingly.

### More examples

All of these run as written after step 2 (same directory).

Scan from standard input, for example straight from a render step (replace
`cat rendered.yaml` with `helm template my-release ./chart`):

```sh
cat rendered.yaml | prufyx scan - \
  --from kubernetes=1.24.0 --to kubernetes=1.25.0 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required
```

A markdown report for a pull request comment or ticket (`--format` also takes
`json`, `sarif` and `csv`):

```sh
prufyx scan rendered.yaml --from kubernetes=1.24.0 --to kubernetes=1.25.0 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required \
  --format markdown > report.md
```

A project config with `check`. `scan` reads Kubernetes manifests; for another
project's configuration use `check`. Example: cert-manager Helm values (a
config file, owner-only):

```sh
echo '{"prometheus":{"servicemonitor":{"path":"/custom"}}}' > values.json
chmod 600 values.json
prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 --values values.json
```

The first lines of the real output (exit `10`; the rest lists the pinned
sources):

```
cert-manager removed monitor values: BLOCKED
claim: CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT
reason: the exact proposed values contain a curated key rejected by the target chart schema
matched curated paths: prometheus.servicemonitor.path
values digest: sha256:6fbf9de30d9b79c9e77974bf5c4dd0cb46355ff556e4226a0957cfb4664c683f
```

`prufyx catalog checks --project NAME` lists the checks and the exact command
and input each one reads; the [community checks reference](cli/docs/community-checks.md)
documents every input.

Triage a live cluster with `assess`. This one reads a cluster (read-only,
through kubectl), so it is not part of the copy-paste sequence above. **Put all
flags before the context name**: anything after it is taken as another context.

```sh
prufyx assess --kubeconfig "$HOME/.kube/config" --acknowledge-kubeconfig-exec-risk \
  --format json my-context
```

Without `--scope-input`, `assess` does not give a verdict (exit `0` is not a pass). It lists which checks apply to what it found
and what each still needs from you. See [one-command flow](cli/docs/one-command-flow.md).

The longer [quickstart guide](cli/docs/quickstart.md) walks through `check`
on the same manifest, with the upstream source citation of each finding.

Run `prufyx` for a short command overview and `prufyx <command> help` for one
command's details. Help text is coloured only on a terminal; `NO_COLOR` or
`PRUFYX_COLOR=never` turns it off and `PRUFYX_COLOR=always` forces it on (see
the quickstart guide). Reports are never coloured.

## What the verdicts mean

- `BLOCKED`: your input matches a rule condition the target release
  enforces. The output names the fix. Exit `10`.
- `UNKNOWN`: the evidence does not decide. Never read it as a pass. Exit `11`.
- `PASS`: the checked rules passed for that scope. It is not a whole-upgrade
  certificate. `scan` exit `0` means the declared scope is complete; `check`
  exit `0` means only the checked rules passed (use `--strict-exit` in CI, exit
  `14`).

The page [what the verdicts mean](cli/docs/verdicts.md) gives, for each answer,
what it means, what it does not mean and what to do. The single exit-code table
is [exit codes](cli/docs/exit-codes.md). What each declaration flag asserts is in
[declarations](cli/docs/declarations.md).

A rule applies to the exact cited version pair, or to a version range only
where the cited evidence states that range. Outside it, the result is
`UNKNOWN`.

## Beta

A public beta pre-release (`v0.1.0-beta.0`) is being prepared. Read the
[beta tester guide](cli/docs/beta-tester-guide.md) for install and
verification, the main commands and how to report a wrong answer, and the
[release notes](cli/docs/release-notes-v0.1.0-beta.0.md) for what a build
contains and its known limits. The coverage figures live in the generated block
below, not in the guide. A beta result is a scoped finding, never a whole-upgrade
certificate.

## What is covered

The [generated support inventory](cli/docs/community-support-inventory.md)
is the authoritative list of checks. A check covers exact cited versions;
the numbers below separate how many rules exist from how much of the recent
upgrade surface they decide.

Catalogued is not the same as decided.

<!-- crd-catalogue:begin -->
A project is catalogued when it has a reviewed custom-resource target (87 projects: 46 of the CNCF landscape catalog, 41 of the community catalog). It is decided only for the upgrades that a rule or line attestation covers for the whole release-line pair (A or B in the table below). Of the 41 community-catalog projects, 15 hold a published rule or current line attestation for the CRD version family and 26 hold none.
<!-- crd-catalogue:end -->

In beta.0, a community-catalog project without data in the embedded knowledge
is not scannable: `scan`, `plan` and `check cncf --custom-resources` refuse it
with exit `2` instead of answering. The generated sentence above counts the
community projects that hold CRD knowledge.

## Coverage

<!-- coverage:begin -->
Generated on 2026-11-10 by `scripts/readme-coverage.sh` (do not edit this block by hand). Release lines captured 2026-10-31, evaluated on 2026-11-07. 9 projects were appended to the snapshot with their own capture dates; the block is evaluated on 2026-11-10 (the later of the snapshot's evaluation date and every capture date).

| Executable rules | Count |
| --- | --- |
| CNCF source rules, active | 252 across 53 projects (1 withdrawn, not used) |
| Rules for further, non-CNCF projects | 51 across 10 projects |
| Projects with at least one executable check (a rule, a named check or a profile; says nothing about which upgrades it decides) | 67 |
| Projects with a rule or attestation that decides at least one of their last five minor upgrades (A, B or S below) | 45 of 79 |
| Projects catalogued with retained public sources | 58 (11 of them source-only, no check) |
| Projects with reviewed CRD targets (a reviewed `crd.custom_resource_versions` target) | 87 |
| Projects with a published CRD rule or line attestation | 29 |

Version-coverage depth, measured over the last five minor upgrades of each of the 79 projects with a release-line snapshot (395 upgrades between consecutive release lines):

| Status | Upgrades | Share |
| --- | --- | --- |
| Decided for the whole release-line pair (A attested, B bounded) | 51 | 12.9% |
| Rule for one exact version pair only (S) | 40 | 10.1% |
| Gap, no valid rule (G) | 304 | 76.9% |

Kubernetes: 63 valid rules, but 19 fall in its window 1.32 to 1.37; 0 of 5 upgrades in that window are gaps.

Decided means a valid rule or attestation covers every version of both release lines. It never means a whole-upgrade PASS. Only 8 of the 51 decided upgrades are decided by a rule, or by an attestation that lists rules, so the answer for them can be BLOCKED or UNKNOWN. The other 43 are decided only by line attestations that list no rule (43 by `crd.custom_resource_versions`): for them an attestation can only give a family-scoped PASS (`scan` prints "PASS within <family> only"), never BLOCKED. An exact-pair rule decides only the versions it names. The metric is defined in the [coverage report guide](cli/docs/coverage-report.md); it is not a statement that any upgrade is safe.

Metric v2, Decided Pair Coverage, shown beside the v1 table above (v1 measures one fact family, so its share is not comparable). It covers the last two upgrades (last three release lines) of 30 Tier 1 and 0 Tier 2 projects: 60 upgrades, split into 420 cells, one per fact family that applies to the project. Tier 1 is the priority portfolio; no reviewed tier definition exists yet. Tier 2 has no reviewed list yet.

| Measure | Value |
| --- | --- |
| DPC-declared: weighted share of cells with a line attestation | 2% |
| DPC-reachable: the same, counting only cells whose fact the shipped client can read from manifests | 2% |
| Cells attested | 9 of 420 (9 of them reachable, 0 declared only) |
| Cells bounded by a rule range only, not counted | 0 |
| Cells open, not counted | 411 |
| Upgrades with every cell attested | 0 of 60 |

| Fact family | Cells | Attested | Reachable | Producer in the shipped client (for at least one project) |
| --- | --- | --- | --- | --- |
| `crd.versions` | 60 | 7 | 7 | manifest |
| `crd.schema` | 60 | 0 | 0 | none |
| `helm.values` | 60 | 0 | 0 | none |
| `cli.flags` | 60 | 0 | 0 | none |
| `config.keys` | 60 | 0 | 0 | none |
| `k8s.api` | 60 | 2 | 2 | manifest |
| `k8s.min` | 60 | 0 | 0 | none |

Declared means a reviewed line attestation exists in the knowledge. Reachable also needs the shipped client to produce that fact from manifests; an attested cell without a producer is declared only and is not in the reachable share. A bounded or open cell is not coverage, and a family with no measurement yet counts as open, never as not applicable (0 project-family-upgrade cells exempted by reviewed exemptions). Weights: Tier 1 three times Tier 2, the newest upgrade twice the one before. Neither share says that any upgrade is safe.
<!-- coverage:end -->

Update the block with `scripts/readme-coverage.sh` (`--check` fails when it is
stale). The method and the full per-project table are in the
[coverage report guide](cli/docs/coverage-report.md).

In plain terms: the rules are exact transitions, mostly for older
releases. Only a minority of upgrades between two release lines are decided as a
whole (see the table above).
Kubernetes API removals exist for upgrades to 1.22, 1.25-1.27, 1.29,
1.32-1.34 and 1.37, plus the in-tree dockershim removal in 1.24.
Each served-API removal rule covers every patch release of the previous line
going to every patch release of the line that stops serving the API, so a
manifest at the removed version answers `BLOCKED` for any such pair (for
example 1.31.14 to 1.32.11), not only at the `.0` releases.

Further projects with executable checks: Apache Airflow, Argo Workflows, Ceph,
Fluent Bit, Grafana, Grafana Loki, Kibana, MariaDB, MariaDB Operator and
OpenSearch (community projects), and named checks and profiles for cert-manager, Prometheus, SPIFFE
X.509-SVID, CloudEvents and TiKV.

CNCF projects with rules include Argo CD, Cilium, containerd, Contour, CoreDNS,
Cortex, CRI-O (its one rule is withdrawn), Crossplane, Envoy, etcd, Falco, Flux, Harbor, Helm, Istio,
Jaeger, Karmada, KEDA, Knative, KubeEdge, KubeVirt, Kyverno, Linkerd, Longhorn,
MetalLB, OPA, OpenTelemetry, Prometheus, Rook, SPIRE, Strimzi, Tekton, Thanos,
Velero and others.

Every rule in the CNCF and community-project packs is time-limited.

<!-- validity-window:begin -->
The 303 active rules shipped today stop being valid, rule by rule, between 2026-12-07 and 2027-02-04 unless their review is renewed; after its date a build without newer knowledge answers `UNKNOWN` for that rule. 199 of the 303 stop being valid on or before 2026-12-12, in the 6 days starting on the earliest.
<!-- validity-window:end -->

The named cert-manager and Prometheus checks are pinned to
fixed versions and do not expire.

Run `prufyx catalog checks --project PROJECT` (for example `kubernetes`) to
list a project's embedded rules and the exact command and input each one reads. The [community checks reference](cli/docs/community-checks.md)
documents every input contract.

## What `scan` covers today

`prufyx scan` reads your rendered Kubernetes manifests and a target version and
reports which API versions in them a Kubernetes release on the way to the
target stops serving. It covers Kubernetes only; other projects are reported as
not covered, with the `prufyx check cncf` command that does cover them. It does
not look at a live cluster, stored versions, admission or component
configuration, or node version skew. Custom resources are evaluated only for
the projects whose reviewed custom-resource version knowledge covers the
upgrade (see [custom resources](cli/docs/custom-resources.md)); a custom
resource of any other group is not evaluated.

`scan` answers `PASS FOR THE DECLARED SCOPE` (exit `0`) only when every hop of
the upgrade is decided by reviewed records: reviews that a release line has no
other removed APIs, the reviewed Kubernetes upgrade-path policy that plans a
jump across minor lines hop by hop, and a reviewed list of the API versions
each target release serves. Anything the knowledge does not cover ends in
`BLOCKED` (exit `10`) or "not every area checked" (exit `11`). See the
[`scan` guide](cli/docs/scan.md). To run it in a workflow, see the
[GitHub Action](cli/docs/github-action.md).

## Kubernetes distributions

Prufyx recognises the version strings of several Kubernetes distributions and
maps them to an upstream Kubernetes version (see
[distribution versions](cli/docs/kubernetes-distribution-versions.md)). A
distribution can also carry a reviewed record with provider lifecycle facts
(support end dates, extended support, forced upgrades); `scan` and `plan` read
those lifecycle facts as advisory findings that can add a warning and never
remove a finding or authorize a pass (see
[provider facts](cli/docs/scan.md#provider-facts-advisory)). The checking
machinery is merged, but no provider fact extractor is compiled in and no
provider fact has been published to the knowledge feed. Today no distribution
below has a published lifecycle fact.

<!-- distribution-lifecycle:begin -->
| Distribution | Version string recognised | Lifecycle facts | State |
| --- | --- | --- | --- |
| EKS | yes (`v1.N.P-eks-<hex>`) | none published | reference/planned: no published facts yet |
| GKE | yes (`1.N.P-gke.<build>`) | none published | reference/planned: no published facts yet |
| AKS | yes, with a declared distribution | none published | reference/planned: no published facts yet |
| k3s | yes (`v1.N.P+k3s<n>`) | none published | reference/planned: no published facts yet |
| kind | no distribution record | none published | reference/planned: no published facts yet |
| Upstream | yes (`official_upstream`, takes no record) | not a provider | reference/planned: no published facts yet |
<!-- distribution-lifecycle:end -->

Reading the table: "recognised" means the version string is parsed; it does not
mean the distribution behaves like upstream Kubernetes. A distribution without
a current reviewed record is a gap, never a pass. kind is a local test
environment, not a lifecycle-tracked distribution; a result from kind or any
other local cluster says nothing about the fidelity of a managed or production
cluster. These rows are catalogue entries, not tested coverage: no row is
listed as supported for production use.

## Recent changes

The [changelog](CHANGELOG.md) is the full list. Merged and user-visible, by
status:

**Implemented in the source tree**

- **Coverage report** (maintainer command): measures how much of each
  project's last five minor upgrades the rules decide. See
  [coverage report](cli/docs/coverage-report.md).
- **Release-boundary rules:** a rule whose range pins a removal or change
  boundary no longer lets a hop that crosses that boundary pass; the result is
  `UNKNOWN` (`RULE_RELEASE_BOUNDARY_NOT_REVIEWED`), and `catalog checks` lists
  the `boundary-unreviewed` and `crossing` match modes.
- **Image-based detection for `assess`** (reads a cluster, opt-in): a reviewed
  registry maps container images to projects and reads a version only from a
  tag that follows the declared scheme. Unlisted, digest-only, `latest` and
  mirrored images give no version, so the component is indeterminate rather
  than a mismatch.
- **Knowledge store:** `check cncf` and `scan` use a verified database that
  `prufyx db update` installed, and refuse an invalid or expired one;
  `--knowledge=embedded` forces the built-in knowledge.
- **`check --strict-exit`:** a scoped `PASS` exits `14` instead of `0`. See
  [exit codes](cli/docs/exit-codes.md).
- **`scan` output is escaped:** terminal escape sequences, line breaks and
  bidirectional controls from the input or knowledge are shown as visible
  escapes, so a name or path cannot forge a report line.
- **Per-kind migration hints** with cited upstream passages for derived
  Kubernetes API-removal rules.
- **Helm subcharts:** `scan` answers `UNKNOWN` instead of `BLOCKED` for a
  removed API in a subchart that may not be rendered.
- **Hardening:** filesystem writes by maintainer tools and the collector do
  not follow symlinks; the GitHub Action passes its token only to the
  attestation check and requires an archive checksum to skip attestation;
  tagged release builds are reproducible and carry their build identity. See
  [releasing](cli/docs/releasing.md).

**Planned:** a published release with prebuilt binaries and automated GitOps
release gates. Neither exists today. The official signed knowledge feed is
published; `prufyx db update` fetches it.

## Privacy and offline operation

- `check` and `scan` read local files you select. They do not contact a
  cluster, registry, or upstream project, and they do not execute supplied
  content. `prufyx assess` is the only command that reads a cluster: read-only,
  through kubectl, and only with an explicit kubeconfig, context and
  `--acknowledge-kubeconfig-exec-risk`.
- The `check` commands accept only private input files (owner-only, for
  example mode `0600`) and refuse anything group- or world-accessible. `scan`
  refuses files other users can write; by default it accepts files other users
  can read and prints a note, and `--input-permissions strict` applies the
  owner-only rule to `scan` as well.
- Reports omit raw values, paths, credentials, and configuration content.
- Knowledge can be refreshed explicitly with `prufyx db update` from a signed
  package you choose; nothing updates automatically. With no arguments it targets the
  official feed, verified against the root pinned in the build.

### Two ways to get knowledge

- **Offline (default).** The binary carries its knowledge, versioned with the
  release. `check`, `scan` and `plan` need no network and no setup. Embedded
  rules are time-limited; an expired rule answers `UNKNOWN`.
- **Online, only when you run it.** `prufyx db update` fetches the signed
  knowledge database from the official feed and installs it in
  `~/.local/share/prufyx/knowledge/cncf-projects` (`$XDG_DATA_HOME` if
  absolute); downloaded packages are kept in `.../knowledge/packages/`. It
  verifies a TUF chain that starts at the root pinned in the binary
  (`sha256:11eff27032c4a3db126d030ae860e881e8e0dd1e7c37fcc4f10ef5fde70a326a`),
  changes nothing for a package older than the installed one (exit `12`) or
  too new for this build (exit `15`),
  refuses a package with the same revision and a different digest, and sends no
  configuration, path or report. Nothing runs at startup.
- **Back to embedded.** `--knowledge=embedded` on `check cncf` or `scan`, or
  remove the store directory above.
- **Air-gapped.** Carry a package over and check it with
  `prufyx db verify FILE --profile cncf-projects --bootstrap-root root.json
  --bootstrap-root-digest sha256:<digest you verified yourself>`, then
  `prufyx db import FILE --db-root <store> --profile cncf-projects` (same root
  flags on a first import). Or use an HTTPS mirror you operate:
  `prufyx db update --profile cncf-projects --source https://<mirror>/cncf-projects.tar`,
  still verified against the pinned root.
- An invalid or expired store makes `check` and `scan` stop with exit `3`; they
  do not fall back to embedded silently. Repair it with `db update`, or use
  `--knowledge=embedded`.

Details: [knowledge updates](cli/docs/knowledge-updates.md).

## Support Prufyx

Prufyx is built in the open by an independent maintainer. Every check is tied to a
cited upstream source, and the tool runs locally with no account and no model in
the verdict path. Keeping that knowledge current across the projects listed in the coverage table
above takes real compute.

**What we need now: one build-and-research workstation.**

| Component | Target | What it unlocks |
|---|---|---|
| CPU | 32+ cores | Run the full test suite and knowledge re-verification in parallel instead of in one queue |
| Memory | 128 GB+ | Mirror and re-check upstream sources for many projects at once |
| Storage | 2 TB NVMe | Pinned upstream source mirrors and reproducible builds |

If you or your company would like to fund or provide hardware, please get in touch
by email at [hello@prufyx.com](mailto:hello@prufyx.com) or on
[LinkedIn](https://www.linkedin.com/in/spasatanasov/). Hardware sponsors are
acknowledged here and on [prufyx.com](https://prufyx.com) with their permission.
We will publish what any support paid for. Sponsorship does not buy influence over
verdicts: every rule still needs cited upstream evidence and review.

## Contributing

The most useful contribution is a reviewed upgrade fact: a public project, an
exact version pair, the setting or API that changed, and the upstream source
that proves it.

- Suggest a project with the
  [project source issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml).
  The repository URL is enough to begin.
- Maintain a project? See [For project maintainers](docs/maintainers.md).
- Prepare evidence locally with the
  [project onboarding guide](cli/docs/project-onboarding.md) and the
  [upstream contribution guide](cli/docs/upstream-contributions.md).
- Propose a rule with the [rule contribution guide](cli/docs/contributing-rules.md).

Every contribution is reviewed by a maintainer before it becomes a rule. Never include customer
configuration, cluster snapshots, or credentials. See
[CONTRIBUTING.md](CONTRIBUTING.md) for build and test requirements.
Contributors sign the [Contributor License Agreement](CLA.md) once; the CLA
check guides you on your first pull request.

## License

- **Source code:** [GNU Affero General Public License v3.0 only](LICENSE)
  (`AGPL-3.0-only`).
- **Reviewed knowledge data** (rules, evidence, attestations):
  [CC BY-SA 4.0](DATA-LICENSE.md).
- **Third-party material** keeps its own license; see
  [THIRD-PARTY.md](THIRD-PARTY.md).

Prufyx is maintained by [Spas Atanasov](https://github.com/airstand).
Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Limits

A finding covers only the named rule, version pair, and input it was given. It
does not prove migration completion, runtime compatibility, availability, data
safety, or security. Review the upstream documentation and test the complete
deployment before upgrading.
