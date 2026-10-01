# Prufyx

Prufyx is a local, offline review tool for narrowly scoped configuration and
upgrade facts. It reads a caller selected file, compares it with a signed or
embedded source contract, and returns `PASS`, `BLOCKED`, or `UNKNOWN`. A result
is a bounded finding; it is not whole upgrade, cluster, runtime, or data safety
validation.

This is the official Prufyx repository at [github.com/prufyx/prufyx](https://github.com/prufyx/prufyx).
Build the executable from source with the vendored Go modules. There is no
official prebuilt binary, release feed, or automatic knowledge refresh for
this preview.

## Quickstart

New to Prufyx? [`cli/docs/quickstart.md`](cli/docs/quickstart.md) takes you
from a clean clone to a real **BLOCKED** verdict with a source citation, in
under five minutes, using a Kubernetes API-removal check. It also explains
what `PASS`/`BLOCKED`/`UNKNOWN` mean, why input files must be `chmod 600`,
and how to wire the exit code into CI.

Have a public GitHub project with useful release notes or changelogs? Start with
the [local project onboarding guide](cli/docs/project-onboarding.md)
or [suggest the repository](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml).
The repository URL is enough to begin; source onboarding does not add a support
claim or executable check. Default sync requires a matching published GitHub
Release. Repositories without Releases can instead use the guide's explicit,
bounded Git-tag selection; it does not discover or infer tags.

## Another worked example: a MetalLB migration fact

The example below uses the caller's proposed native Kubernetes JSON. It does
not contact Kubernetes, a registry, or MetalLB.

This quickstart requires Go 1.26.8. It creates a temporary binary and private
0600 inputs outside the checkout.

```sh
set -eu
umask 077
PREVIEW_DIR="$(mktemp -d)"
trap 'rm -rf "$PREVIEW_DIR"' EXIT
test "$(go env GOVERSION)" = go1.26.8
(cd cli && \
  GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o "$PREVIEW_DIR/prufyx-community" ./cmd/prufyx-community)
cat > "$PREVIEW_DIR/metallb-legacy.json" <<'JSON'
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}
JSON
chmod 600 "$PREVIEW_DIR/metallb-legacy.json"
legacy_result=0
"$PREVIEW_DIR/prufyx-community" check cncf --project metallb --native-resource "$PREVIEW_DIR/metallb-legacy.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T00:00:00Z --format human || legacy_result=$?
test "$legacy_result" -eq 10

cat > "$PREVIEW_DIR/metallb-cr.json" <<'JSON'
{"apiVersion":"metallb.io/v1beta1","kind":"IPAddressPool","metadata":{"name":"pool","namespace":"metallb-system"},"spec":{"addresses":["192.0.2.10-192.0.2.20"]}}
JSON
chmod 600 "$PREVIEW_DIR/metallb-cr.json"
"$PREVIEW_DIR/prufyx-community" check cncf --project metallb --native-resource "$PREVIEW_DIR/metallb-cr.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T00:00:00Z --format human
```

The selected legacy ConfigMap is **BLOCKED** because the reviewed 0.13.2
contract no longer consumes that 0.12 configuration shape. Convert the
operator-owned configuration with [MetalLB's migration procedure](https://metallb.io/configuration/migration_to_crds/), save the resulting
reviewed CR resource as another 0600 JSON file, and rerun the same command with
that path. The corrected input is checked only as the submitted resource;
unsupported, incomplete, or ambiguous shapes remain **UNKNOWN**. Do not read
this example as proof that a cluster was converted or that traffic is safe.

## What is covered

The current generated inventory reports **66 executable projects**, **110
selected source references**, and **58 projects with retained source records**.
The [full generated inventory](cli/docs/generated/community-support-inventory.json)
contains the exact capabilities and source bindings.
Use [`catalog checks`](cli/docs/community-checks.md#discovering-embedded-source-rule-routes)
to discover the embedded source-rule identities and exact local input routes for one project.

Explicit adopter-managed refresh continues through the existing signed TUF
import/update path. A Community CLI built from this source reports authenticated
TUF freshness separately from source-evidence expiry and exposes the fixed CNCF
target contract. The maintainer binary can export a complete compatible
replacement target, prepare each sequential signing payload, sign public role
metadata with encrypted local role keys, and verify the final package. See the
[adopter update overview](cli/docs/knowledge-updates.md), [publisher
workflow](cli/docs/knowledge-publisher.md), and [offline signer
workflow](cli/docs/knowledge-signer.md). No official Prufyx root or feed is
configured by these source tools.

The 2026-09-12 development-preview expansion currently admits **115 selected
exact project/version pairs across 23 projects**. Each row uses five selected
earlier stable releases and one exact reviewed target; it does not claim five
universal minor lines. The [latest-target coverage matrix](cli/docs/latest-upgrade-coverage-2026-09-12.md)
distinguishes native input from operator declarations and states the predicate
and `UNKNOWN` boundary for every project. Notation remains an explicit
qualification gap. Jaeger's retained `1.76.0` to `2.20.0` route is additional
to the selected-pair count, and one selected Cortex pair was already present.
Prometheus also has an additional canonical `2.55.1` to `3.14.0` depth
route over existing declared facts and a scoped native `remote_write`
HTTP/2-default check; these do not change the 23-project,
115-selected-pair matrix.
This is current source-preview development scope, not an official release or a
whole-upgrade compatibility claim.

The fifty-nine documented scenario examples are:

| Project | Scoped scenario | Local input |
| --- | --- | --- |
| Argo Workflows | 3.5.0 → 3.6.0 and five exact origins → 4.1.3 check the server `--basehref` to `--base-href` rename | native exact-image Kubernetes Deployment JSON with complete selected argv |
| Argo CD | 2.14.0 → 3.0.0 preserves declared v2 visibility; five exact origins → 3.5.2 check one selected Helm OCI repository | complete, precedence-resolved private ConfigMap or pre-apply repository Secret with explicit plain-HTTP intent and route guards |
| Ceph | Quincy 17.2.7 → Reef 18.2.0 rejects a selected current FileStore OSD | private native per-OSD metadata JSON output |
| Cloud Custodian | 0.9.50 → 0.9.51 and five exact origins → 0.9.52 remove the selected IAM access-key `json-diff` policy filter | private policy JSON |
| CloudNativePG | 1.29.0 → 1.30.0 cluster reference must remain immutable | paired Kubernetes JSON objects |
| MetalLB | 0.12.1 → 0.13.2 legacy ConfigMap configuration is removed | ConfigMap or reviewed CR JSON |
| NATS | 2.10.0 → 2.11.0 and five exact origins → 2.14.6 reject ASCII spaces in supplied selected names | native JSON configuration subset |
| Contour | 1.19.0 → 1.20.0 selected `networking.x-k8s.io/v1alpha1` resources need explicit migration | Kubernetes resource JSON |
| CNI | spec 0.4.0 → 1.0.0 removes non-List configuration | plugin configuration JSON |
| Cilium | 1.16.19 → 1.17.18 rejects an invalid effective ConfigMap cluster name; 1.18.6 → 1.19.0 and 1.18.13 → 1.19.7 witness a nonempty `fromRequires`/`toRequires` selector | complete, precedence-resolved official-upstream v1 ConfigMap YAML or JSON, or one selected CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy (or flat list) with an explicit policy-set completeness declaration |
| Linkerd | 2.13.7 → 2.14.0 derives empty-selector state for a proposed MeshTLSAuthentication | proposed MeshTLSAuthentication JSON with declared distribution and schema-validation intent |
| Karmada | 1.18.3 → 1.19.0 witnesses a removed legacy `purgeMode` value on a proposed policy | proposed PropagationPolicy/ClusterPropagationPolicy JSON with declared distribution and target-policy-CRD-admission intent |
| CoreDNS | 1.6.9 → 1.7.0 and five exact origins → 1.14.7 reject the removed `federation` directive | complete Corefile with declared official distribution |
| Flux | 2.6.4 → 2.7.0 and five exact origins → 2.9.5 detect removed beta CRD API versions | native rendered resource JSON object, or one flat `v1` List, with an explicit selected-scope-complete declaration |
| Envoy | 1.38.4 → 1.39.1 blocks direct V2 xDS transport API versions at the selected ADS, LDS, or CDS paths | directly loaded JSON bootstrap selected by the caller; this route has no native PASS |
| Falco | 0.40.0 → 0.41.0 and 0.40.0 → 0.42.0 remove five deprecated 0.40 CLI spellings for the `falco` executable | caller-declared explicit effective Falco argv JSON with declared distribution |
| Prometheus | 2.55.1 → 3.14.0 checks one selected `remote_write` entry's direct `enable_http2` setting or reviewed omitted default against an explicit endpoint requirement | complete, precedence-resolved native Prometheus YAML with a unique literal entry name |
| Cortex | 1.17.2 and four exact origins → 1.21.1 remove the `querier.at-modifier-enabled` flag | native exact-image `apps/v1` Deployment, StatefulSet, or DaemonSet JSON with one explicitly named `cortex` container |
| Kuma | 2.8.0 → 2.9.0 removes two deprecated `kumactl install transparent-proxy` UID exclusion flags | caller-declared explicit effective `kumactl install transparent-proxy` argv JSON with declared distribution |
| SPIRE | 1.10.4 → 1.11.0 removes the `spire-server entry create` `-ttl` and `--ttl` options | caller-declared explicit effective `spire-server entry create` argv JSON with declared distribution |
| etcd | 3.5.17 → 3.6.0 removes eight v2/proxy options; five exact origins → 3.7.1 reject the finite documented 3.7-removed experimental flag names | caller-declared, complete, direct effective etcd argv JSON in strict `--name=value` form |
| Kyverno | 1.12.5 → 1.13.0 removes `reportsChunkSize`; five exact origins → 1.19.1 check the same target-only constraint | one caller-selected container's bare literal `reports-controller` command with declared distribution |
| Tekton Pipelines | 1.9.0 → 1.10.0 requires the new `metrics-protocol: prometheus` key once the removed OpenCensus `metrics.backend-destination` key is no longer parsed | complete effective `config-observability` v1 ConfigMap YAML or JSON with declared distribution, system namespace, and Prometheus-retention intent |
| KubeEdge | 1.18.0 → 1.19.0 replaces the legacy `keadm init --profile version=<version>` selector with `--kubeedge-version` | caller-declared explicit effective `keadm init` argv JSON with declared distribution and argv-completeness |
| Jaeger | 1.76.0 → 2.20.0 and five exact origins → 2.20.0 require an explicit `--config` selection when non-memory storage and the official distribution are both declared | caller-declared direct Jaeger v2 invocation JSON with an explicit `--config=value` argv and declared storage/distribution facts |
| Harbor | 2.7.0 → 2.8.0 and five exact origins → 2.15.2 reject the removed docker-compose installer `--with-chartmuseum` option | caller-declared, complete, literal `make/install.sh` argv JSON with a declared-effective flag |
| KEDA | 2.16.0 → 2.17.0 removes the direct External Scaler `tlsCertFile` TLS transport; a forwarded metadata field alone never establishes reliance | complete caller-selected rendered `keda.sh/v1alpha1` ScaledObject JSON with an explicit reliance declaration when `tlsCertFile` is present |
| MariaDB Operator | 26.3.0 → 26.6.0 requires `autoUpdateDataPlane` for one complete Galera resource before the operator update | complete native `k8s.mariadb.com/v1alpha1` MariaDB JSON with Galera-only and pre-update declarations |
| containerd | 1.7.28 → 2.0.0 removes two selected official bundled v1 runtime shims; upstream migration preserves the selected runtime type | complete, precedence-resolved native config.toml with an explicit handler and upstream/bundled-runtime declarations |
| Distribution | 2.8.3 → 3.0.0 removes schema 1 manifests | manifest JSON |
| Emissary-Ingress | 3.10.0 → 4.0.1 removes `diagd --metrics-endpoint` | caller-selected argv JSON |
| Fluent Bit | 3.2.0 → 4.0.0 requires an intended OpenTelemetry HTTP/2 setting to stay enabled | complete classic configuration plus current-default and preservation declarations |
| Fluentd | 1.17.1 → 1.18.0 changes treatment of one selected unquoted interpolation marker; 1.16.0 → 1.17.0 and five exact origins → 1.19.3 require a declared minimum Ruby version for the official package | paired literal JSON declaration with completeness, current-default, and preservation guards, or a declared proposed distribution and proposed Ruby version target |
| Grafana | 10.4.0 → 11.0.0 rejects explicit legacy alerting enablement | complete, precedence-resolved `grafana.ini` |
| Harbor | 2.7.0 → 2.8.0 removes the installer `--with-chartmuseum` option | caller-declared complete literal installer argv JSON |
| Kibana | 8.18.0 → 9.0.0 removes `xpack.reporting.roles.allow` | complete, precedence-resolved `kibana.yml` |
| KubeVirt | 1.8.4 → 1.9.0 rejects interfaces with no or multiple bindings | VM/VMI JSON |
| Kubernetes | 1.31.0 → 1.32.0 removes the selected flowcontrol v1beta3 GVKs | complete rendered target apply-set JSON with official-upstream distribution and target API apply intent |
| Grafana Loki | 2.9.8 → 3.0.0 removes legacy compactor shared-store settings | complete, precedence-resolved native Loki YAML |
| Grafana Loki | 2.9.8 → 3.0.0 requires `store: tsdb` and `schema: v13` when structured metadata is enabled | complete, precedence-resolved native Loki schema configuration YAML |
| MariaDB | 10.11.8 → 11.4.2 cannot preserve the removed upstream InnoDB defragmentation behavior; the old option is accepted only as an ignored compatibility input | complete, precedence-resolved native option file with explicit upstream-distribution and behavior-requirement declarations |
| OpenCost | 1.119.0 → 1.120.0 and five exact origins → 1.121.2 move enabled cloud-cost collection from provider-derived configuration to an explicitly selected cloud-integration file | operator-declared source selection JSON |
| OpenFGA | 1.17.1 → 1.18.0 requires OIDC issuer and audience when effective config is complete | effective-config JSON |
| OpenTelemetry Collector | 0.110.0 → 0.111.0 removes the selected `logging` exporter | complete, precedence-resolved native Collector YAML with declared official distribution |
| OpenTelemetry Collector | 0.110.0 → 0.111.0 checks the target internal-metrics localhost default against an explicit non-loopback scrape requirement when no metrics override is configured | complete, precedence-resolved native Collector YAML plus declared official distribution, effective feature gate, and scrape requirement |
| Strimzi | 0.51.0 → 1.0.0 removes the `kafka.strimzi.io/v1beta2` served version for `kind: Kafka` | one rendered Kafka resource, or one flat `v1` List, plus declared distribution and target-CRD admission intent |
| Crossplane | 1.20.0 → 2.0.0 removes the `Resources` Composition mode from the official target CRD schema | one rendered `Composition`, or one flat `v1` List, plus declared distribution and target-schema validation intent |
| Prometheus | 2.55.1 → 3.1.0 renames selected `scrape_classic_histograms` | complete, precedence-resolved scrape-config YAML |
| Prometheus | 2.55.1 → 3.1.0 removes selected Alertmanager `api_version: v1` | complete, precedence-resolved `alerting.alertmanagers` entry YAML |
| Velero | 1.17.0 → 1.18.0 requires the target CRDs to be updated before the server deployment | one flat `v1` List of rendered upgrade documents in declared apply order, plus the literal server Deployment name |
| Velero | 1.16.2 → 1.18.0 is outside the documented upgrade path and requires the 1.17.x intermediate first | the same declared upgrade plan; the reviewed pair alone blocks the direct transition |
| Thanos | 0.41.0 → 0.42.0 and five exact origins → 0.42.4 reject one removed literal Receive or Store subcommand flag | native selected Kubernetes workload container JSON |
| CRI-O | 1.34.0 → 1.35.0 rejects a short-name Artifact reference without a declared resolution plan | image-status request JSON with an explicit named-reference-resolution declaration |
| CubeFS | 3.2.1 → 3.3.2 requires `raftSyncSnapFormatVersion: 0` for a MetaNode during the declared upgrade phase | MetaNode configuration JSON with an explicit phase declaration |
| TUF (python-tuf) | 6.0.0 → 7.0.0 requires an explicitly named `bootstrap` keyword argument for `Updater` | caller-supplied Python source with one conservatively bound direct call |
| in-toto | 2.2.0 → 3.0.0 removes the legacy `-k`/`--key` option from `in-toto-run` | caller-supplied planned argv JSON |
| Knative Serving | 1.22.0 → 1.23.0 requires a startup HTTP probe's named port to match a supported named container port | proposed Service JSON |
| Kubeflow Pipelines SDK | 1.8.22 → 2.0.0 removes `create_component_from_func` | caller-supplied Python source with one conservatively bound decorator form |
| Buildpacks Lifecycle | 0.16.5 → 0.17.7 checks a requested Platform API against its declared supported set | paired current/proposed Lifecycle config JSON with declared Platform API values |

Use `prufyx check cncf --project PROJECT` for CNCF scenarios, including Cloud
Custodian, Crossplane, etcd, Falco, Fluentd, Harbor, Jaeger, Karmada, KEDA, KubeEdge, Kuma, Kyverno, Linkerd, OpenCost, Prometheus, SPIRE, Strimzi, Tekton, Thanos and Velero, and `prufyx check
project --project PROJECT` for the separately scoped community-project scenarios
(Argo Workflows, Ceph, Fluent Bit, Grafana, Kibana, Grafana Loki, MariaDB, and MariaDB Operator), with the input contract
documented in [community checks](cli/docs/community-checks.md). Version arguments select
an exact reviewed source contract. They do not identify a running installation.
CNI numbers are specification editions, not a library release claim. OpenFGA's
JSON is a caller-declared, already-resolved effective configuration; it does
not infer flag, environment, or file precedence. Every scenario leaves
unrepresented facts and whole-system behavior **UNKNOWN**.

The embedded profiles also include cert-manager, Prometheus, SPIFFE X.509-SVID
and CloudEvents structured JSON checks, plus a TiKV 8.5.8 GCS WIF full-backup
target preflight. These are named subsets and planned-operation checks, not
additional claims of complete product support.

## Offline operation and result meaning

The quickstart uses vendored modules. Its temporary binary and inputs stay
outside the checkout.

The checks read local files and do not execute supplied source, workloads,
plugins, or commands. Keep inputs under `umask 077` and mode 0600. Reports
minimize recognized facts and omit raw values, paths, credentials, and private
configuration content. Exit status is `0` for PASS, `10` for BLOCKED, `11` for
UNKNOWN or ATTENTION, `2` for invalid input, and `3` for integrity failure.

Knowledge evaluation stays local. An explicit `db update` may download an
operator-selected metadata package for local verification; it can reuse an
existing canonical fact and admitted input format after review. A new fact type
or input format can require a CLI update. There is no official feed, startup
refresh, or automatic knowledge admission.

## Contribute reviewed evidence

Public-source suggestions can begin with the
[project source issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml)
without exact versions or manually calculated hashes. The local
[project onboarding workflow](cli/docs/project-onboarding.md) discovers bounded
release metadata and commit-pinned public files, then emits a source-only
proposal for review.

Maintainers can start with the [upstream contribution guide](cli/docs/upstream-contributions.md),
then use the offline scaffold and validator described there. A packet is a
candidate for independent source and semantic review, not an accepted rule.
The [review record template](cli/docs/upstream-review-record-template.md) keeps
source, implementation, and maintainer decisions separate. Existing facts and
rule operators may support a metadata-only update after review; new facts,
engine behavior, or native input adapters may require a CLI release.

Contributions remain local until a maintainer accepts and publishes reviewed
knowledge. Do not upload customer configuration. The project is maintained by
Spas Atanasov. First-party code is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
Reviewed knowledge data (rules, evidence, attestations) is licensed under
[CC BY-SA 4.0](DATA-LICENSE.md). Third-party files retain their own notices in
[THIRD-PARTY.md](THIRD-PARTY.md). Contributors sign the
[Contributor License Agreement](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).

## Limits

A finding describes only the named predicate, source pair, input shape, and
operator intent supplied to that invocation. It does not prove migration
completion, API discovery, effective configuration, runtime compatibility,
availability, backup completion, identity trust, or security. Review the
project's upstream documentation and test the complete deployment separately.
Feedback can be returned through the repository's contribution and issue
workflow; this preview makes no support or compatibility commitment.
