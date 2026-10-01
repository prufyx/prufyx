# Native CNCF resource checks

These are small JSON and YAML native-input examples for the reviewed predicate in each exact
transition. They do not connect to a cluster, apply a resource, observe runtime defaults,
or establish runtime or whole-upgrade compatibility. Each `broken` input is a
scoped blocker, each `fixed` input clears that predicate only, and each
`unknown` input remains unresolved.

From `cli/`, build the local command once with the accepted offline vendor set:

```sh
go build -mod=vendor -buildvcs=false -o ./prufyx-community ./cmd/prufyx-community
```

## Kubernetes v1.32 flow-control GVK removal

Kubernetes `1.31.0` -> `1.32.0` checks one caller-selected complete rendered
target apply set for the two removed `flowcontrol.apiserver.k8s.io/v1beta3`
GVKs: `FlowSchema` and `PriorityLevelConfiguration`. It requires explicit
official-upstream distribution and target API apply intent. See the
[`kubernetes`](kubernetes/README.md) example. This does not validate general
manifest schema or admission, CRDs, stored objects, runtime clients, API-server
configuration, or whole-upgrade safety.

## Cilium v1.17.18 cluster-name validation

Cilium `1.16.19` -> `1.17.18` checks the whitespace-trimmed `cluster-name` in
one caller-selected complete, precedence-resolved official-upstream v1
ConfigMap. See the [`cilium`](cilium/README.md) example. It does not establish
ClusterMesh, networking, name-collision, runtime, or whole-upgrade safety.

Run the MetalLB example directly from its native resource:

```sh
umask 077
work=$(mktemp -d)
chmod 700 "$work"
cp examples/cncf/native-resources/metallb/broken.json "$work/resource.json"
chmod 600 "$work/resource.json"
./prufyx-community check cncf --project metallb \
  --native-resource "$work/resource.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T18:00:00Z --format human
```

Use the same command with `fixed.json` or `unknown.json`. Contour and KubeVirt
also take one `--native-resource`; use their exact pairs `1.19.0 -> 1.20.0` and
`1.8.4 -> 1.9.0` respectively. A raw `--native-resource-digest sha256:...`
option can bind the exact supplied bytes.

CloudNativePG needs a selected current and proposed resource, not a custom
Prufyx envelope:

```sh
cp examples/cncf/native-resources/cloudnativepg/current-broken.json "$work/current.json"
cp examples/cncf/native-resources/cloudnativepg/proposed-broken.json "$work/proposed.json"
chmod 600 "$work/current.json" "$work/proposed.json"
./prufyx-community check cncf --project cloudnativepg \
  --current-resource "$work/current.json" --resource "$work/proposed.json" \
  --from 1.29.0 --to 1.30.0 --now 2026-09-11T18:00:00Z --format human
```

For CloudNativePG, bind both raw files separately when identity matters. The
check compares only same-object identity and `spec.cluster.name`. With an
external signed knowledge store, that store is authoritative and has no
embedded fallback; historical replay requires every raw digest and all selected
knowledge pins.

## Thanos Receive and Store argv

Thanos `0.41.0` -> `0.42.0` accepts one supplied **proposed target** Kubernetes
workload JSON file. It selects exactly one container named `thanos`, requires
an explicit `command: ["thanos"]`, an admitted Thanos image tagged
`v0.42.0`, and literal args beginning `receive` or `store`. Global arguments
before the subcommand, shell/default entrypoints, expansion syntax, argument
delimiters, custom images, and ambiguous containers stay `UNKNOWN`.

```sh
cp examples/cncf/native-resources/thanos/broken.json "$work/thanos.json"
chmod 600 "$work/thanos.json"
./prufyx-community check cncf --project thanos \
  --native-resource "$work/thanos.json" \
  --from 0.41.0 --to 0.42.0 --now 2026-09-11T19:16:43Z --format human
```

`broken.json` retains the removed Receive option and is a scoped blocker.
`fixed.json` clears only that literal-argv predicate. `unknown.json` uses a
custom image and remains unresolved. The check does not prove that the image
was pulled or deployed, nor Query compatibility, storage, compaction,
discovery, generated configuration, runtime, or whole-upgrade behavior.

## Cortex literal querier argv

Cortex `1.17.2` → `1.21.1` checks a caller-supplied proposed workload for the
removed `querier.at-modifier-enabled` option. The admitted input has one named
`cortex` container, the exact reviewed target image, and literal argv. It accepts
explicit `command: ["/bin/cortex"]` or an omitted command only for
`quay.io/cortexproject/cortex:v1.21.1`, whose retained source maps that exact
image to `/bin/cortex`; this is not a runtime observation. Null or empty
commands, wrappers, custom images, configuration files, environment, and shell
syntax remain unresolved.

```sh
cp examples/cncf/native-resources/cortex/broken.json "$work/cortex.json"
chmod 600 "$work/cortex.json"
./prufyx-community check cncf --project cortex \
  --native-resource "$work/cortex.json" \
  --from 1.17.2 --to 1.21.1 --now 2026-09-11T23:00:00Z --format human
```

`broken.json` is BLOCKED because it retains the removed option. `fixed.json`
is a scoped PASS for its literal argv. `unknown.json` uses a null command and
remains UNKNOWN. The check does not establish query semantics,
storage, tenancy, runtime behavior, or whole-upgrade compatibility.

## Prometheus selected scrape configuration

Prometheus `2.55.1` → `3.1.0` renames `scrape_classic_histograms` to
`always_scrape_classic_histograms`. Supply one complete native `scrape_config`
mapping and select its literal `job_name`; Prufyx discards the name, targets,
and every unrelated setting.

```sh
cp examples/cncf/native-resources/prometheus/broken.yml "$work/prometheus-scrape.yml"
chmod 600 "$work/prometheus-scrape.yml"
./prufyx-community check cncf --project prometheus \
  --scrape-config "$work/prometheus-scrape.yml" --scrape-job selected-api \
  --scrape-config-complete --scrape-config-precedence-resolved \
  --from 2.55.1 --to 3.1.0 --now 2026-09-11T23:00:00Z --format human
```

`broken.yml` is BLOCKED because the selected mapping retains the old key.
`fixed.yml` is a scoped PASS for the key rename. `unknown.yml` is UNKNOWN
because absence of both keys does not establish migration intent. The two
declaration flags are caller assertions that this selected mapping is complete
and that configuration precedence is resolved. The check does not parse a
whole `prometheus.yml`, start Prometheus, verify scraping or targets, or prove
native-histogram or whole-upgrade behavior.

### Alertmanager API selection

The `alertmanager-*.yml` files are individual selected native
`alerting.alertmanagers` entry mappings. They are not full `prometheus.yml`
documents. Run them with `--alertmanager-config FILE` plus
`--alertmanager-config-complete --alertmanager-config-precedence-resolved` for
the same exact `2.55.1` → `3.1.0` transition.

`alertmanager-broken.yml` is BLOCKED because it selects API v1.
`alertmanager-fixed.yml` explicitly selects v2. `alertmanager-default-v2.yml`
omits the key and uses the exact target source-derived v2 default. Both are
scoped PASS results only for API-version selection. `alertmanager-unknown.yml`
is a full-config wrapper and remains UNKNOWN. Addresses, credentials, paths,
and unrelated settings are discarded. These results do not establish that an
actual Alertmanager supports v2, is reachable, or can receive alerts; validate
Alertmanager compatibility and the complete target configuration separately.

### Prometheus 3.14 target-only selections

The `latest-v3.14.0-*` fixtures exercise only the five reviewed origins
`3.9.1`, `3.10.0`, `3.11.3`, `3.12.0`, and `3.13.3` to `3.14.0`. Run the
local Go-built command against one private selected mapping:

```sh
cp examples/cncf/native-resources/prometheus/latest-v3.14.0-alertmanager-blocked.yml "$work/prometheus-alertmanager.yml"
chmod 600 "$work/prometheus-alertmanager.yml"
./prufyx-community check cncf --project prometheus \
  --alertmanager-config "$work/prometheus-alertmanager.yml" \
  --alertmanager-config-complete --alertmanager-config-precedence-resolved \
  --from 3.13.3 --to 3.14.0 --now 2026-09-12T09:03:00Z --format human
```

The `api_version: v1` fixture is BLOCKED. `latest-v3.14.0-alertmanager-fixed.yml`
is PASS and an omitted API key uses the target's source-derived v2 default.
For the classic-histogram setting, `latest-v3.14.0-scrape-blocked.yml` is
BLOCKED only because it explicitly selects the old key;
`latest-v3.14.0-scrape-unknown.yml` remains UNKNOWN because no selected key is
present. These target-only results do not imply an origin default, startup,
scraping, Alertmanager reachability, or whole-upgrade safety.

## NATS selected literal names

NATS `2.10.0` → `2.11.0` rejects ASCII spaces in explicitly supplied
`server_name`, `cluster.name`, or `gateway.name`. The direct route accepts a
small JSON-only configuration subset and does not resolve NATS includes,
variables, defaults, or classic block syntax.

The retained native input path also evaluates the exact target-only constraint
for `2.12.15`, `2.11.17`, `2.10.29`, `2.9.25`, and `2.8.4` proposed to
`2.14.6`. The target source applies the same literal ASCII-space predicate to
the three selected names. These rules do not claim when that behavior began,
that any direct route is supported, or that an intermediate version is
required.

```sh
cp examples/cncf/native-resources/nats/broken.json "$work/nats.json"
chmod 600 "$work/nats.json"
./prufyx-community check cncf --project nats \
  --nats-config "$work/nats.json" \
  --from 2.10.0 --to 2.11.0 --now 2026-09-11T20:22:53Z --format human
```

Run the Go-owned latest-target walkthrough to exercise scoped `BLOCKED`,
`PASS`, and `UNKNOWN` cases for all five exact origins:

```sh
./prufyx-community community-preview example cncf-nats-latest
```

`broken.json` is BLOCKED because a supplied selected name contains an ASCII
space. `fixed.json` is a scoped PASS for the supplied names. `unknown.json`
uses an unresolved include and remains UNKNOWN. Missing selected names,
case-colliding keys, relevant dotted descendants, dynamic values, and
unsupported parent shapes also remain UNKNOWN; the check never infers a
default name, enabled gateway, or runtime configuration. It also rejects JSON
escape forms that the reviewed NATS lexer does not admit, including `\\u` and
`\\/`, rather than decoding them into apparent literal names.

## Flux selected rendered resources

Flux `2.6.4` → `2.7.0` removes five beta API versions. The direct route reads
one caller-selected JSON Kubernetes object or `v1` `List`; it does not parse
YAML, contact a cluster, or establish stored-version migration or reconciliation.

The latest reviewed route is Flux `2.9.5`. It accepts the five exact origins
`2.8.8`, `2.7.5`, `2.6.4`, `2.5.1`, and `2.4.0`. It retains the five earlier
beta API removals and adds the target-confirmed beta2 set. Select the same
private rendered-resource file with `--to 2.9.5` and one of those origins:

```sh
umask 077
./prufyx-community check cncf --project flux \
  --native-resource "$work/flux.json" \
  --from 2.8.8 --to 2.9.5 --resource-scope-complete \
  --now 2026-09-12T10:00:00Z --format human
```

The latest target's controller versions and per-kind served API versions are
bound to the pinned Flux 2.9.5 CRD release files in the retained reviewed source
contract. A selected Flux API group with an unknown kind or an unreviewed API version remains `UNKNOWN`;
ordinary non-Flux resources remain admissible. These checks still do not prove
stored CRD versions, migration execution, reconciliation, runtime, or whole
upgrade safety. The latest predicate covers only the reviewed toolkit kinds
listed in the retained contract; it does not classify source-watcher,
extensions, or every Flux CRD and API version.

```sh
cp examples/cncf/native-resources/flux/broken.json "$work/flux.json"
chmod 600 "$work/flux.json"
./prufyx-community check cncf --project flux \
  --native-resource "$work/flux.json" \
  --from 2.6.4 --to 2.7.0 --now 2026-09-11T21:00:00Z --format human
```

`broken.json` has an admitted removed API and is a scoped blocker even without
completeness. `fixed.json` can produce a scoped PASS only with
`--resource-scope-complete`; that declaration says the supplied nonempty,
non-paginated list is the selected rendered-resource set. `unknown.json` has a
pagination token and remains UNKNOWN. These results never establish stored CRD
versions, full cluster inventory, schema validation, reconciliation, runtime,
or whole-upgrade safety.

## Cortex latest target argv

The latest-target expansion admits exactly `1.16.1`, `1.17.2`, `1.18.1`,
`1.19.1`, or `1.20.1` to `1.21.1`. It applies a target-only argv constraint
and does not assert when that option changed for every origin. The
`cortex/latest-v1.21.1-*.json` examples use the exact target image and show a
blocker, a scoped pass, and an unsupported custom image.

## Thanos latest target argv

The existing `0.41.0` to `0.42.0` command grammar remains unchanged. The
latest-target expansion admits exactly `0.37.2`, `0.38.0`, `0.39.2`, `0.40.1`,
or `0.41.0` to `0.42.4`. For those new pairs the target Dockerfile qualifies
only explicit `command: ["/bin/thanos"]` or an omitted command on an admitted
image. `command: ["thanos"]` remains unsupported for these new pairs.
The admitted image spellings are `quay.io/thanos/thanos:v0.42.4` and
`thanosio/thanos:v0.42.4`; canonical Docker Hub normalization is handled by
the adapter. The `thanos/latest-v0.42.4-*.json` files show blocker, scoped
pass, and unsupported inputs. These results do not prove image pulls, runtime,
compaction, storage, Query compatibility, or whole-upgrade behavior.
