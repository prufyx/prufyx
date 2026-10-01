# Community checks

Build the public binary from the repository root with Go 1.26.8:

```sh
(cd cli && GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community)
```

The Community checks evaluate local files offline. They never contact a cluster
or upload values. The cert-manager values input must be a regular, single-link
JSON file readable only by its owner because Helm values commonly contain
credentials. Relative paths are accepted. Create inputs under `umask 077`, or
run `chmod 600 values.json` before the check.

## Discovering embedded source-rule routes

Use `catalog checks` to inspect the exact embedded source-rule identities for
one project and, optionally, one exact transition. It reads no configuration,
does not evaluate a check, and reports source evidence freshness as
`NOT_EVALUATED`.

```sh
./prufyx catalog checks --project prometheus --from 2.55.1 --to 3.1.0 --format json
./prufyx catalog checks --project mariadb-operator --from 26.3.0 --to 26.6.0
```

The output distinguishes generic embedded CNCF canonical-input coverage from
exact native routes. Each generic canonical input itself contains the listed
exact from/to pair, so its command deliberately has no `--from` or `--to`
flags. Community project rules are discoverable but their generic
declaration route is `NOT_EXPOSED_BY_PUBLIC_CLI`; only a mechanically bound
native descriptor may recommend `check project`. A descriptor is typed command
guidance: replace `FILE`, `NAME`, `RFC3339`, and `BOOL` with caller-supplied
values. It does not declare an assessment, validate a target, or establish
runtime behavior. Named checks appear only as scoped `--help` hints.

Thanos `0.41.0` to `0.42.0`, and the five exact origins to `0.42.4`, are
bound native `check cncf --project thanos --native-resource FILE` routes
under this same discovery; see the
[latest-target coverage matrix](latest-upgrade-coverage-2026-09-12.md) for the
reviewed input and predicate. The Grafana, Kibana, Fluent Bit, Loki, MariaDB,
Ceph, and Argo Workflows community-project routes are documented in
[Community project checks](community-project-checks.md) and are discoverable
the same way with `--project PROJECT`.

KubeVirt `1.8.4` to `1.9.0`, MetalLB `0.12.1` to `0.13.2`, Contour `1.19.0` to
`1.20.0`, Kubernetes `1.31.0` to `1.32.0` (the `flowcontrol.apiserver.k8s.io/v1beta3`
removal), and Cilium `1.16.19` to `1.17.18` (the effective ConfigMap
`cluster-name` guard) are also bound native `check cncf --project PROJECT
--native-resource FILE` routes (Kubernetes additionally needs `--distribution`,
`--target-api-apply-required`, and `--resource-scope-complete`; Cilium uses
`--cilium-config-map`, `--cilium-distribution`, `--cilium-config-complete`, and
`--cilium-config-precedence-resolved` instead). CloudNativePG `1.29.0` to
`1.30.0` needs a paired `--current-resource` and `--resource` instead of one
`--native-resource`. See
[`examples/cncf/native-resources`](../examples/cncf/native-resources/README.md)
for a runnable BLOCKED/PASS/UNKNOWN walkthrough of each.

## Fluentd selected-literal treatment

For Fluentd `1.17.1` to `1.18.0`, `prepare cncf --project fluentd` accepts a
private JSON declaration containing paired selected `current` and `proposed`
literal values. It requires all three caller guards to be true:
`selectedValueComplete`, `currentDefaultUsed`, and
`preserveLiteralTreatment`. It derives only whether one simple unquoted
`#{...}` marker is present. The selected values must be byte-identical, except
for the exact single-quote wrapper around the unchanged current literal.
This does not parse a Fluentd file, Ruby, interpolation, plugins, or runtime
behavior. Use the private-copy walkthrough in
[`examples/cncf/fluentd-literal-treatment`](../examples/cncf/fluentd-literal-treatment/README.md).
It is also reachable as a one-step native route (see "Fluentd Ruby minimum
version" below), which dispatches the same `current`/`proposed` literal
declaration by shape without a separate `prepare` step.

## Fluentd Ruby minimum version

The native Fluentd route decides whether one caller-declared proposed
distribution and proposed Ruby version target satisfy the reviewed minimum
Ruby requirement. It covers the reviewed `1.16.0` to `1.17.0` transition
(Ruby `2.7.0` or newer) and, separately, the target-only `1.19.3` constraint
(Ruby `3.2.0` or newer) from the five reviewed `1.14.6`, `1.15.3`, `1.16.11`,
`1.17.1`, and `1.18.0` origins. It is a local usability route for the
existing `fluentd.ruby-minimum.1-16-to-1-17` and
`fluentd.ruby-minimum-target.*` rules; it does not add a project, rule, or
upgrade-pair claim.

```sh
umask 077
cat > fluentd-ruby.json <<'JSON'
{"distribution":"official_upstream","rubyVersion":"3.2.0"}
JSON
chmod 600 fluentd-ruby.json
./prufyx check cncf --project fluentd \
  --native-resource fluentd-ruby.json \
  --from 1.18.0 --to 1.19.3 --now 2026-09-19T00:00:00Z
```

Both the distribution and the Ruby version are separate caller declarations;
the Ruby version is never observed from an installed interpreter, package, or
plugin. A declared official-upstream distribution whose declared Ruby version
is below the reviewed minimum is `BLOCKED`; a declared Ruby version at or
above the minimum is a scoped `PASS` for this one requirement. An undeclared
Ruby version, a `custom_build` distribution, or an unreviewed version pair all
remain `UNKNOWN` rather than a negative-presence `PASS`.

The route never installs or executes Ruby and does not resolve custom
packaging, plugin compatibility, or runtime behavior. Pinned source evidence
is `fluentd.gemspec` at commits `43c860907e3d`, `206b46b91560`, and
`e763c0761c44`, and `CHANGELOG.md` at commit `e763c0761c44`. Whole-upgrade
safety remains `UNKNOWN`.

## Harbor installer argv

For Harbor `2.7.0` to `2.8.0` and the exact `2.10.3`, `2.11.2`, `2.12.4`, `2.13.5`, or `2.14.4` to `2.15.2` pairs, `prepare cncf --project harbor` accepts one
private JSON declaration of the selected installer argv. Set
`effectiveArgvDeclared=true` only after selecting a complete, literal
`make/install.sh` argument vector. The check classifies only the removed
`--with-chartmuseum` option. `--help`, wrappers, values, duplicates, unknown
options, and unresolved inputs remain UNKNOWN. It does not execute the
installer or inspect Harbor configuration, charts, database state, or runtime.
Use the private-copy walkthrough in
[`examples/cncf/harbor-installer-argv`](../examples/cncf/harbor-installer-argv/README.md).

## containerd selected official runtime shim

For containerd `1.7.28` to `2.0.0`, the native TOML route checks the
`runtime_type` of one explicitly selected CRI runtime handler. It admits config
version 2 under `plugins."io.containerd.grpc.v1.cri"` and config version 3
under `plugins."io.containerd.cri.v1.runtime"`. The target automatically
migrates version 2 configuration and the reviewed migration preserves
`runtime_type`, so version 2 alone never blocks.

The two removed official bundled runtime types are
`io.containerd.runtime.v1.linux` and `io.containerd.runc.v1`.
`io.containerd.runc.v2` clears only this selected shim-availability constraint.
The complete, precedence-resolved, official-upstream, and
official-bundled-runtimes-only flags are caller declarations. The last one
means that no separately installed custom shim supplies the legacy runtime
name. Imports, `runtime_path` overrides, custom runtime types, missing handlers,
wrong plugin tables, or omitted declarations remain UNKNOWN. The parser does
not read imports, search the host, run containerd or a shim, inspect a cluster,
or prove configuration startup, container creation, or whole-upgrade behavior.

See the private-copy walkthrough and BLOCKED, PASS, and UNKNOWN examples in
[`examples/cncf/containerd-runtime-shim`](../examples/cncf/containerd-runtime-shim/README.md).

## CoreDNS direct federation directive

The native Corefile route evaluates the presence of a direct, literal
`federation` directive for only the reviewed `1.6.9` to `1.7.0` transition and
the `1.9.4`, `1.10.1`, `1.11.4`, `1.12.4`, or `1.13.2` to `1.14.7`
transitions. It is a local usability route for the existing CoreDNS federation
rule; it does not add a project, rule, or upgrade-pair claim.

Copy a synthetic Corefile to a private local path before use:

```sh
umask 077
cp examples/cncf/coredns-corefile/blocked.Corefile Corefile
chmod 600 Corefile
./prufyx check cncf --project coredns \
  --coredns-corefile Corefile --coredns-corefile-complete \
  --coredns-distribution official --from 1.13.2 --to 1.14.7 \
  --now 2026-09-13T00:00:00Z
```

The caller declares that the selected local Corefile is complete and belongs to
the official distribution. The parser detects only a literal `federation`
token in a direct directive position inside a simple server block. A direct
directive is `BLOCKED`; a safely admitted absence is a scoped `PASS` for this
one federation-removal constraint. Distribution identity, completeness, other
plugin validity, referenced files, DNS behavior, runtime state, and whole
upgrade safety are outside the result.

Balanced brace-delimited plugin bodies are admitted structurally up to 32
levels, but their properties are opaque and a `federation` token inside one is
not a direct directive. `import`, snippets, substitutions, quoted or escaped
text, malformed Corefile structure, and deeper nesting return `UNKNOWN` rather
than a negative-presence PASS. The parser does not read referenced files or
execute CoreDNS. Pinned
CoreDNS `1.14.7` documentation supports server blocks, comments, imports, and
substitutions (`corefile.5.md` lines 5-11 and 28-37) and ordinary plugin bodies
(`plugin/health/README.md` lines 19-25; `plugin/forward/README.md` lines
34-56). Pinned source evidence for the existing rule is the CoreDNS `1.7.0`
release note at commit `f59c03d09c3a3a12f571ad1087b979325f3dae30` and the
`1.14.7` `plugin.cfg` at commit
`427fc80ed9ca47f354585eb30a3f1332950856c4`. See the complete synthetic
BLOCKED, PASS, and UNKNOWN walkthrough in
[`examples/cncf/coredns-corefile`](../examples/cncf/coredns-corefile/README.md).

## Flux beta CRD API removal

The native rendered-resource route evaluates one caller-selected JSON object,
or one flat `v1` List of rendered resources, for a direct witness of a
removed beta API version. It covers the reviewed `2.6.4` to `2.7.0`
transition and, for the wider `2.8` and `2.9` removals, the `2.4.0`, `2.5.1`,
`2.6.4`, `2.7.5`, or `2.8.8` to `2.9.5` transitions. It is a local usability
route for the existing Flux `flux.beta-api-removal.2-7` and
`flux.latest-beta-api-removal.*` rules; it does not add a project, rule, or
upgrade-pair claim.

```sh
umask 077
cat > resource.json <<'JSON'
{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"app"}}
JSON
chmod 600 resource.json
./prufyx check cncf --project flux \
  --native-resource resource.json --resource-scope-complete \
  --from 2.6.4 --to 2.7.0 --now 2026-09-19T00:00:00Z
```

A direct witness of a removed beta `apiVersion` on the selected object (or any
item of a selected `v1` List) is a scoped `BLOCKED` regardless of the
`--resource-scope-complete` declaration. A `PASS` additionally requires the
caller to declare the selected resource set complete, with no `continue`
pagination token on a supplied List. Stored CRD versions, a cluster
inventory, reconciliation, and runtime behavior stay outside the result. The
`2.9.5` target additionally removes `v1beta2` API versions across five
toolkit controllers; that wider removal is checked only for the five
reviewed `2.4.0`, `2.5.1`, `2.6.4`, `2.7.5`, and `2.8.8` origins.

## NATS selected name ASCII-space rejection

The native configuration route evaluates one caller-selected standalone
JSON-like NATS configuration object for a literal ASCII space in the direct
`server_name`, `cluster.name`, or `gateway.name` values. It covers the
reviewed `2.10.0` to `2.11.0` transition and, for the later `2.11`
strictness, the `2.8.4`, `2.9.25`, `2.10.29`, `2.11.17`, or `2.12.15` to
`2.14.6` transitions. It is a local usability route for the existing NATS
`nats.names-with-ascii-spaces-rejected.*` rules; it does not add a project,
rule, or upgrade-pair claim.

```sh
umask 077
cat > nats-config.json <<'JSON'
{"server_name":"edge node","cluster":{"name":"cluster"}}
JSON
chmod 600 nats-config.json
./prufyx check cncf --project nats \
  --nats-config nats-config.json --from 2.10.0 --to 2.11.0 \
  --now 2026-09-19T00:00:00Z
```

A literal ASCII space in any selected name is `BLOCKED`; a config with all
three supported names present and none containing a space is a scoped
`PASS`. The upstream parser lowercases these keys, so a case-colliding
duplicate key returns `UNKNOWN`. `include` directives, environment-variable
references, dotted descendant paths, and any other classic-syntax block
remain `UNKNOWN` rather than a negative-presence PASS. The route does not
parse a full NATS configuration file, resolve includes or environment
values, or read cluster or gateway runtime state.

## Cortex removed at-modifier querier flag

The native workload route evaluates one caller-selected `apps/v1` Deployment,
StatefulSet, or DaemonSet JSON object for the removed
`-querier.at-modifier-enabled` (or `--querier.at-modifier-enabled`) flag on
one explicitly named `cortex` container. It covers the reviewed `1.16.1`,
`1.17.2`, `1.18.1`, `1.19.1`, or `1.20.1` to `1.21.1` transitions. It is a
local usability route for the existing Cortex
`cortex.querier-at-modifier-flag-removed.1-21` and
`cortex.querier-at-modifier-flag-target-argv.*` rules; it does not add a
project, rule, or upgrade-pair claim.

```sh
umask 077
cat > workload.json <<'JSON'
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"cortex","namespace":"observability"},
 "spec":{"template":{"spec":{"containers":[
   {"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["-querier.at-modifier-enabled"]}
 ]}}}}
JSON
chmod 600 workload.json
./prufyx check cncf --project cortex \
  --native-resource workload.json --from 1.17.2 --to 1.21.1 \
  --now 2026-09-19T00:00:00Z
```

The selected container must use the exact reviewed target image tag and may
explicitly declare `command:["/bin/cortex"]`, or omit `command` and rely on
the exact admitted image's source-derived entrypoint. Its `args` are limited
to an empty list, self-contained `-name=value` options, and the exact removed
option spelling; a shell wrapper, custom image, delimiter, positional token,
dynamic token, or ambiguous multi-container selection remains `UNKNOWN`
rather than a negative-presence PASS. Generated arguments, query behavior,
storage, tenancy, and runtime state stay outside the result.

## Strimzi Kafka v1beta2 API removal

The native Kafka resource route evaluates which `kafka.strimzi.io` API version
one caller-selected rendered `kind: Kafka` resource, or one flat `v1` `List` of
rendered resources, literally uses. It covers only the reviewed `0.51.0` to
`1.0.0` transition. It is a local usability route for the existing Strimzi
`strimzi.kafka-v1beta2-api-removed.1-0` rule; it does not add a project, rule,
or upgrade-pair claim.

```sh
umask 077
cat > kafka.json <<'JSON'
{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"cluster","namespace":"kafka"},"spec":{"kafka":{"replicas":3}}}
JSON
chmod 600 kafka.json
./prufyx check cncf --project strimzi \
  --kafka-resource kafka.json --strimzi-distribution official_upstream \
  --target-kafka-crd-admission-required --from 0.51.0 --to 1.0.0 \
  --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution and that the selected resources
must be admitted by the target Kafka CRD. Any selected `Kafka` document on
`kafka.strimzi.io/v1beta2` is `BLOCKED`; a selection whose `Kafka` documents are
all on `kafka.strimzi.io/v1` is a scoped `PASS` for this one removal
constraint. A `custom_build` declaration, an undeclared target-CRD admission
intent, `KafkaTopic`, `KafkaUser` or unrelated kinds, another served
`kafka.strimzi.io` version, unresolved templating, a paginated or typed list,
and a structurally unresolved object all remain `UNKNOWN` rather than a
negative-presence PASS.

The route does not install or read a CRD, run API admission or conversion,
inspect stored objects, or establish operator, broker, topic, or client
behavior. Pinned source evidence for the existing rule is the Strimzi
`040-Crd-kafka.yaml` served-version block and `CHANGELOG.md` at commit
`4836c7dd74ce973f06d97936916ed7f20c1a2ff0`, the same CRD at commit
`54081abf97d0e5e524de773b88343756934db1a8`, and the
`con-api-conversion-v1.adoc` upgrade module. Whole-upgrade safety remains
`UNKNOWN`.

## Falco removed 0.40 CLI spellings

The native Falco argv route decides whether one caller-declared explicit
effective Falco argv literally contains any of `-A`, `-b`, `--print-base64`,
`-S`, or `--snaplen`. It covers only the reviewed `0.40.0` to `0.41.0` and
`0.40.0` to `0.42.0` transitions. It is a local usability route for the existing
`falco.deprecated-cli-flags-removed` rules; it does not add a project, rule, or
upgrade-pair claim.

```sh
umask 077
cat > falco-argv.json <<'JSON'
["falco","-c","/etc/falco/falco.yaml","--snaplen","256"]
JSON
chmod 600 falco-argv.json
./prufyx check cncf --project falco \
  --falco-argv falco-argv.json --falco-distribution official_upstream \
  --from 0.40.0 --to 0.41.0 --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution. An argv containing a removed
spelling is `BLOCKED`; an argv on the reviewed `falco` executable surface
containing none of the five spellings is a scoped `PASS` for this one removal
constraint.

The adapter models no Falco option table, because an option table that guessed
an arity wrongly could skip a removed spelling as if it were another option's
value. It compares every token instead, so absence is reported only when no
token in the whole argv can be one of the five spellings. A `custom_build`
declaration, an undeclared distribution, a wrapper or any other command surface,
a clustered or value-attached short token such as `-Ab` or `-S256`, a bare `-`
or `--`, unresolved templating, and an unparseable shape all remain `UNKNOWN`
rather than a negative-presence PASS.

The route never executes the argv and does not resolve a wrapper, an image
entrypoint, environment, Helm values, defaults, or runtime behavior. Pinned
source evidence for the existing rules is the Falco `CHANGELOG.md` and
`userspace/falco/app/options.cpp` at commits `b94cda0b12e5`, `ce4b4408988d`, and
`d8e430e35239`. Whole-upgrade safety remains `UNKNOWN`.

## Kuma removed transparent-proxy UID exclusion flags

The native Kuma argv route decides whether one caller-declared explicit
effective `kumactl install transparent-proxy` argv literally contains either
`--exclude-outbound-tcp-ports-for-uids` or
`--exclude-outbound-udp-ports-for-uids`. It covers only the reviewed `2.8.0` to
`2.9.0` transition. It is a local usability route for the existing Kuma
`kuma.deprecated-exclude-uid-flags-removed.2-8-to-2-9` rule; it does not add a
project, rule, or upgrade-pair claim.

```sh
umask 077
cat > kumactl-argv.json <<'JSON'
["kumactl","install","transparent-proxy","--exclude-outbound-tcp-ports-for-uids","3000:1000"]
JSON
chmod 600 kumactl-argv.json
./prufyx check cncf --project kuma \
  --kumactl-argv kumactl-argv.json --kuma-distribution official_upstream \
  --from 2.8.0 --to 2.9.0 --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution. An argv containing either removed
spelling is `BLOCKED`; an argv on the reviewed command surface containing
neither is a scoped `PASS` for this one removal constraint.

Like the Falco route, the adapter models no option table and compares every
token, so absence is reported only when no token in the whole argv can be one of
the two spellings. Only the direct literal command path is resolved: a
`custom_build` declaration, an undeclared distribution, another `kumactl`
subcommand, a global option placed before the subcommand, a wrapper, an
ambiguous short token, a bare `-` or `--`, unresolved templating, and an
unparseable shape all remain `UNKNOWN` rather than a negative-presence PASS.

The route never executes the argv. Presence of the target-supported
consolidated `--exclude-outbound-ports-for-uids` form is not treated as
equivalent to either removed spelling in either direction, and no Dataplane
migration, image, default, or runtime behavior is established. Pinned source
evidence for the existing rule is `app/kumactl/cmd/install/install_transparent_proxy.go`
at commits `1110a0305eec` and `948e6a439163` and `UPGRADE.md` at commit
`948e6a439163`. Whole-upgrade safety remains `UNKNOWN`.

## Crossplane Composition Resources-mode removal

The native Composition route evaluates which mode one caller-selected rendered
`kind: Composition` resource, or one flat `v1` `List` of rendered resources,
literally declares in `spec.mode`. It covers only the reviewed `1.20.0` to
`2.0.0` transition. It is a local usability route for the existing Crossplane
`crossplane.composition-resources-mode-removed.1-20-2-0` rule; it does not add a
project, rule, or upgrade-pair claim.

```sh
umask 077
cat > composition.json <<'JSON'
{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"example"},"spec":{"mode":"Resources"}}
JSON
chmod 600 composition.json
./prufyx check cncf --project crossplane \
  --composition composition.json --crossplane-distribution official_upstream \
  --crossplane-schema-validation-required --from 1.20.0 --to 2.0.0 \
  --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution and that the selected resources
must validate against the official target CRD schema. Any selected
`Composition` whose `spec.mode` is the literal `Resources` is `BLOCKED`; a
selection whose `Composition` documents all declare the literal `Pipeline` is a
scoped `PASS` for this one enum constraint. A `custom_build` declaration, an
undeclared schema-validation intent, an **omitted or unreviewed `spec.mode`**,
other `apiextensions.crossplane.io` kinds, another served Composition version,
unresolved templating, a paginated or typed list, and a structurally unresolved
object all remain `UNKNOWN` rather than a negative-presence PASS.

An omitted `spec.mode` is deliberately never resolved to any historical default:
doing so would author a compatibility claim this route does not hold.

The route does not install or read a CRD, run API admission or conversion,
inspect stored objects, or establish composition, reconciliation, or provider
behavior. Pinned source evidence for the existing rule is the Crossplane
`apiextensions.crossplane.io_compositions.yaml` mode enum block at commits
`2efdb03ae80fc27f4b6b9b0cebc96a462233cf17` and
`b639502e2f93680ff83417a0f517ec459ce079cc`. Whole-upgrade safety remains
`UNKNOWN`.

## Velero CRD-before-server upgrade ordering

The native upgrade-plan route evaluates where the `velero.io` target
`CustomResourceDefinition` documents sit relative to the Velero server
`Deployment` in one caller-selected flat `v1` `List` of rendered documents whose
item order the caller declares to be the apply order. It covers only the
reviewed `1.17.0` to `1.18.0` and `1.16.2` to `1.18.0` transitions. It is a
local usability route for the existing Velero
`velero.crd-update-order.1-18` and `velero.intermediate-1-17.1-18` rules; it
does not add a project, rule, or upgrade-pair claim.

```sh
umask 077
cat > upgrade-plan.json <<'JSON'
{"apiVersion":"v1","kind":"List","items":[
 {"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"backups.velero.io"},"spec":{"group":"velero.io","scope":"Namespaced"}},
 {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"velero","namespace":"velero"},"spec":{"replicas":1}}
]}
JSON
chmod 600 upgrade-plan.json
./prufyx check cncf --project velero \
  --upgrade-plan upgrade-plan.json --velero-server-deployment velero \
  --velero-plan-order-declared --from 1.17.0 --to 1.18.0 \
  --now 2026-09-18T00:00:00Z
```

The caller declares that the supplied item order is the declared apply order
and names the server `Deployment` inside the plan. A plan whose last `velero.io`
CRD document precedes that `Deployment` is a scoped `PASS` for this one
ordering constraint; a plan where any `velero.io` CRD document follows it is
`BLOCKED`. An undeclared plan order, an unselected, absent or ambiguous server
`Deployment`, **a plan containing no `velero.io` CRD document at all**,
unresolved templating, a paginated or typed list, and a structurally unresolved
object all remain `UNKNOWN` rather than a negative-presence PASS. Unrelated
kinds inside the plan are ordinary install documents and do not disturb the
observation.

On the reviewed `1.16.2` to `1.18.0` pair the direct transition is `BLOCKED` by
the mandatory `1.17.x` intermediate regardless of the supplied plan. That gate
is not bypassable by any native input: the same plan that scores a scoped PASS
at `1.17.0` to `1.18.0` still blocks here.

The route does not apply anything, read a cluster, verify that the declared
plan was executed, or establish plugin, node-agent, backup, or restore
behavior: the fact is a plan declaration, not an execution receipt. Pinned
source evidence for the existing rules is the Velero `upgrade-to-1.18.md`
upgrade guide at commit `0b7eaaf4e6bb6bf7719b27443f8da0ae4a3ef2f8`.
Whole-upgrade safety remains `UNKNOWN`.

## KEDA External Scaler legacy TLS transport

The native KEDA route derives the reviewed
`keda.external-scaler-legacy-tls-transport.2-17` rule's facts from one
caller-selected rendered `ScaledObject`, or one flat `v1` `List` of rendered
resources. It covers only the reviewed `2.16.0` to `2.17.0` transition. It is a
local usability route for that existing rule; it does not add a project, rule,
or upgrade-pair claim.

```sh
umask 077
cat > keda-scaled-object.json <<'JSON'
{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"orders"},
 "spec":{"scaleTargetRef":{"name":"orders"},
 "triggers":[{"type":"external","metadata":{"scalerAddress":"orders-scaler.svc:9090","tlsCertFile":"/etc/certs/tls.crt"}}]}}
JSON
chmod 600 keda-scaled-object.json
./prufyx check cncf --project keda \
  --keda-scaled-object keda-scaled-object.json --keda-scaled-object-complete \
  --keda-legacy-tls-transport-required true \
  --from 2.16.0 --to 2.17.0 --now 2026-09-18T00:00:00Z
```

The route deliberately derives less from the document than a reader might
expect, because the reviewed condition fact says so itself: a raw `tlsCertFile`
metadata field can still be forwarded to the external scaler and is **not**
sufficient to establish reliance on the removed direct transport. This route
therefore never turns the presence of `tlsCertFile` into a `BLOCKED` claim on
its own. Presence makes the condition an explicit operator declaration
(`--keda-legacy-tls-transport-required`), and without that declaration the
result is `UNKNOWN`.

What the route does derive natively is the rule's applicability guard: whether
the selected `ScaledObject` set declares an `external` or `external-push`
trigger at all. A selection with no External Scaler trigger declares that guard
false and stops; the condition fact is never declared from it.

A scoped `PASS` is available in two ways, both of which require
`--keda-scaled-object-complete`: no selected external trigger carries
`tlsCertFile` and none carries an `authenticationRef` that could supply it from
a `TriggerAuthentication` this route does not read, or the caller explicitly
declares `--keda-legacy-tls-transport-required false` for a forwarded-only
field. Declaring `true` against a complete selection that carries neither the
field nor an `authenticationRef` is a contradiction and stays `UNKNOWN`.

An unreviewed pair, an undeclared selection scope, a `ScaledJob`,
`TriggerAuthentication` or any unrelated object, another served `keda.sh`
version, a paginated or typed list, a trigger with non-string metadata values,
unresolved templating, and an unparseable shape all remain `UNKNOWN` rather
than a negative-presence PASS. One unresolvable document keeps the whole
selection `UNKNOWN` rather than being silently skipped.

The route reads no cluster and resolves no `TriggerAuthentication`,
`ClusterTriggerAuthentication`, secret, TLS material, scaler reachability, or
runtime behavior. Pinned source evidence for the existing rule is
`pkg/scalers/external_scaler.go` at commits `5c52d032931b` and `dafd9a883acc`
and `CHANGELOG.md` at commit `dafd9a883acc`. Whole-upgrade safety remains
`UNKNOWN`.

## SPIRE removed entry-create TTL option

The native SPIRE argv route decides whether one caller-declared explicit
effective `spire-server entry create` argv literally contains `-ttl` or
`--ttl`. It covers only the reviewed `1.10.4` to `1.11.0` transition. It is a
local usability route for the existing
`spire.removed-entry-ttl.1-11` rule; it does not add a project, rule, or
upgrade-pair claim.

```sh
umask 077
cat > spire-entry-argv.json <<'JSON'
["spire-server","entry","create","-spiffeID","spiffe://example.org/workload","-ttl","3600"]
JSON
chmod 600 spire-entry-argv.json
./prufyx check cncf --project spire \
  --spire-entry-argv spire-entry-argv.json --spire-distribution official_upstream \
  --from 1.10.4 --to 1.11.0 --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution. An argv containing either
removed spelling is `BLOCKED`; an argv on the reviewed
`spire-server entry create` surface containing neither is a scoped `PASS` for
this one removal constraint.

The adapter models no SPIRE option table, because an option table that guessed
an arity wrongly could skip a removed spelling as if it were another option's
value. It compares every token instead, so absence is reported only when no
token in the whole argv can be one of the two spellings. Both removed spellings
are multi-character option names, so neither can hide inside a clustered short
token; single-dash option names such as `-spiffeID` are therefore resolvable
rather than ambiguous. A `custom_build` declaration, an undeclared
distribution, another `spire-server` subcommand, `spire-agent`, a wrapper, a
word placed between the executable and the subcommand, a bare `-` or `--`,
unresolved templating, and an unparseable shape all remain `UNKNOWN` rather
than a negative-presence PASS.

The route never executes the argv and does not resolve a wrapper, an image
entrypoint, environment, Helm values, defaults, existing registration entries,
or runtime behavior. It does not validate any replacement TTL option or its
value; only the two removed spellings are decided. Pinned source evidence for
the existing rule is `cmd/spire-server/util/util.go` and
`cmd/spire-server/cli/entry/create.go` at commits `9c4d83a3b44d` and
`ca35234a30a2` and `CHANGELOG.md` at commit `ca35234a30a2`. Whole-upgrade
safety remains `UNKNOWN`.

## etcd removed v2/proxy and 3.7 experimental flags

The native etcd route decides whether one caller-declared, complete, direct
effective etcd argv (every option in strict `--name=value` form) literally
contains a removed option. It is a local usability route for the existing
`etcd.v2-proxy-flags-removed.3-6` and `etcd.experimental-flags-unsupported.*`
rules; it does not add a project, rule, or upgrade-pair claim.

For the reviewed `3.5.17` to `3.6.0` transition it checks the eight named
v2/proxy options (`enable-v2`, `experimental-enable-v2v3`, `proxy`,
`proxy-failure-wait`, `proxy-refresh-interval`, `proxy-dial-timeout`,
`proxy-write-timeout`, `proxy-read-timeout`). For the reviewed `3.2.32`,
`3.3.27`, `3.4.45`, `3.5.33`, and `3.6.14` origins to `3.7.1` it checks the
finite documented set of 3.7-removed experimental flag names.

```sh
umask 077
cat > etcd-argv.json <<'JSON'
{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=node0","--enable-v2=true"]}
JSON
chmod 600 etcd-argv.json
./prufyx check cncf --project etcd \
  --native-resource etcd-argv.json \
  --from 3.5.17 --to 3.6.0 --now 2026-09-18T00:00:00Z
```

Every option in the declared argv must resolve against the reviewed source
grammar for that pair; an option outside the reviewed known-flag set, a
non-`--name=value` token, or `effectiveArgvDeclared: false` keeps the claim
`UNKNOWN` rather than guessing at an unmodelled flag's arity. For the
`3.5.17` to `3.6.0` pair the rule only ever proves presence of a removed
option: a fully resolved argv containing none of the eight still stays
`UNKNOWN`, never a negative-presence PASS. For the five `3.7.1` origins, an
argv containing none of the finite removed experimental names is a scoped
`PASS` for that predicate alone; four of those five origins additionally match
a separate, unconditional minor-version-skip blocker outside this route's
scope, which keeps the aggregate `BLOCKED` even when this route's own claim
passes.

The route never executes the argv and does not resolve a wrapper, an
entrypoint, a config file, environment, data migration, or quorum health.
Pinned source evidence is `server/etcdmain/config.go` and
`server/embed/config.go` at commits `507c0de87bd5` and `f5d605a93abe`, and the
etcd 3.6 and 3.7 upgrade guides and `server/embed/config.go` at commit
`5e7fd0de9a57`. Whole-upgrade safety remains `UNKNOWN`.

## Kyverno removed reportsChunkSize flag

The native Kyverno route decides whether one caller-selected container's
explicitly declared official-upstream bare literal `reports-controller`
command literally contains the `reportsChunkSize` option. It covers the
reviewed `1.12.5` to `1.13.0` removal and, separately, the target-only
`1.19.1` constraint from the five reviewed `1.14.5`, `1.15.3`, `1.16.4`,
`1.17.2`, and `1.18.2` origins. It is a local usability route for the
existing `kyverno.reports-chunk-size-removed.1-13` and
`kyverno.reports-chunk-size-unsupported-at-1-19-1-from-*` rules; it does not
add a project, rule, or upgrade-pair claim.

```sh
umask 077
cat > kyverno-workload.json <<'JSON'
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"reports-controller","namespace":"kyverno"},"spec":{"template":{"spec":{"containers":[{"name":"reports-controller","image":"ghcr.io/kyverno/reports-controller:v1.12.5","command":["reports-controller"],"args":["--reportsChunkSize=16"]}]}}}}
JSON
chmod 600 kyverno-workload.json
./prufyx check cncf --project kyverno \
  --kyverno-resource kyverno-workload.json --container reports-controller \
  --kyverno-distribution official_upstream \
  --from 1.12.5 --to 1.13.0 --now 2026-09-18T00:00:00Z
```

The caller selects exactly one container by name and declares the proposed
distribution. A selected container whose command is the bare literal
`reports-controller` and whose arguments contain `reportsChunkSize` is
`BLOCKED`; the same surface without that option is a scoped `PASS` for this
one removal constraint.

The adapter models no Kyverno option table: it recognizes only the
`reportsChunkSize` option name in `-name`, `--name`, `-name=value`, or
`--name=value` form and otherwise treats every other flag-shaped argument as
unsupported rather than guessing its arity. An ambiguous or duplicate
container selection, an image-only entrypoint, any command other than the
bare literal `reports-controller`, an unreviewed version pair, a
`custom_build` or undeclared distribution, an argument after `--`, and an
unparseable shape all remain `UNKNOWN` rather than a negative-presence PASS.

The route never executes the command and does not resolve image provenance,
a wrapper, another command surface, controller runtime behavior, or when the
option was actually removed for the five 1.19.1 origins. Whole-upgrade safety
remains `UNKNOWN`.

## Jaeger explicit --config requirement for non-memory storage

The native Jaeger route decides whether one caller-declared, direct Jaeger v2
invocation JSON has exactly one known non-empty literal `--config=value`
selection. It covers the reviewed `1.76.0` to `2.20.0` transition and,
separately, the target-only `2.20.0` constraint from the five reviewed
`2.15.1`, `2.16.0`, `2.17.0`, `2.18.0`, and `2.19.0` origins. It is a local
usability route for the existing
`jaeger.explicit-config-required-for-non-memory.1-76-2-20` and
`jaeger.explicit-config-required-for-non-memory.target.*` rules; it does not
add a project, rule, or upgrade-pair claim.

```sh
umask 077
cat > jaeger-argv.json <<'JSON'
{"authority":"OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY","argv":["--config=/etc/jaeger/config.yaml"]}
JSON
chmod 600 jaeger-argv.json
./prufyx check cncf --project jaeger \
  --jaeger-argv jaeger-argv.json \
  --non-memory-storage-required true --official-jaeger-distribution true \
  --from 1.76.0 --to 2.20.0 --now 2026-09-18T00:00:00Z
```

Non-memory storage requirement and official distribution are separate
caller declarations; they are never inferred from the argv or any runtime
state. The rule only forbids the predicate when both are declared `true` and
`--config` is definitely absent, so this route can only ever reach a genuine
positive-witness `PASS` (an explicit, unambiguous `--config` selection) or
`UNKNOWN` — it never emits a negative-presence PASS from a merely absent or
ambiguous selection. Zero, multiple, split, empty, wrapped, expanded, or
remote `--config` forms, and declarations left unset, all keep the claim
`UNKNOWN`.

The route never reads the referenced config location and does not resolve
its content, storage backend, credentials, or runtime. Pinned source
evidence is `cmd/jaeger/internal/command.go` and
`cmd/jaeger/internal/all-in-one.yaml` at commit `798e4b0fcf22`, and `go.mod`
at the same commit. Whole-upgrade safety remains `UNKNOWN`.

## Harbor removed installer --with-chartmuseum flag

The native Harbor route decides whether one caller-declared, complete,
literal `make/install.sh` argv contains the removed docker-compose installer
`--with-chartmuseum` option. It covers the reviewed `2.7.0` to `2.8.0`
transition and, separately, the target-only `2.15.2` constraint from the
five reviewed `2.10.3`, `2.11.2`, `2.12.4`, `2.13.5`, and `2.14.4` origins.
It is a local usability route for the existing
`harbor.installer-with-chartmuseum-flag-removed.*` rules; it does not add a
project, rule, or upgrade-pair claim.

```sh
umask 077
cat > harbor-argv.json <<'JSON'
{"apiVersion":"prufyx.io/harbor-installer-argv/v1alpha1","kind":"HarborInstallerArguments","effectiveArgvDeclared":true,"argv":["--with-chartmuseum"]}
JSON
chmod 600 harbor-argv.json
./prufyx check cncf --project harbor \
  --native-resource harbor-argv.json \
  --from 2.7.0 --to 2.8.0 --now 2026-09-18T00:00:00Z
```

The adapter models no Harbor option table: it recognizes only the finite
reviewed no-value literal installer options (`--with-trivy`, and, only for
the exact target of each pair, `--with-notary` and `--with-clair`) plus
`--with-chartmuseum`, and otherwise treats every other flag-shaped argument,
`--help`, a duplicate option, or `effectiveArgvDeclared: false` as
unsupported rather than guessing its behavior. A fully modeled argv without
`--with-chartmuseum` is a scoped `PASS`; the installer is never executed, so
this witness always comes from the complete declared argv, never from an
unreviewed absence.

The route never executes the installer and does not resolve a wrapper,
environment variable, response file, chart state, or database migration.
Pinned source evidence is `make/install.sh` at commits `6113469a5676` and
`89ef156d09a6`. Whole-upgrade safety remains `UNKNOWN`.

## OpenCost cloud-cost source selection

The native OpenCost route decides whether an enabled cloud-cost migration
away from a complete, provider-derived current source selection has a
complete target selection with a declared-present cloud-integration
configuration source. It covers the reviewed `1.119.0` to `1.120.0`
transition and, separately, the target-only `1.121.2` constraint from the
five reviewed `1.116.0`, `1.117.6`, `1.118.0`, `1.119.2`, and `1.120.4`
origins. It is a local usability route for the existing
`opencost.cloud-cost-source-migration.*` rules; it does not add a project,
rule, or upgrade-pair claim. The `PrepareOpenCostCloudSource` adapter already
existed and evaluated every one of these six pairs before this route was
wired; only the one-step dispatch and catalog registration were added.

```sh
umask 077
cat > opencost-source.json <<'JSON'
{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}}
JSON
chmod 600 opencost-source.json
./prufyx check cncf --project opencost \
  --native-resource opencost-source.json \
  --from 1.119.0 --to 1.120.0 --now 2026-09-19T00:00:00Z
```

Cloud-cost enablement, source-selection completeness, and the selected
source kind are all separate caller declarations for both the current and
proposed side; a declared `cloudIntegrationConfigSource: present` is not a
filesystem observation. A complete current provider-derived selection with an
enabled, complete proposed selection that stays `provider_derived` (declared
config absent) is `BLOCKED`; the same shape with a declared, present
cloud-integration file is a scoped `PASS` for this one source-kind
constraint. Disabled collection, incomplete selections, an ambiguous
`api_managed` source, or an unreviewed version pair all remain `UNKNOWN`
rather than a negative-presence `PASS`.

The route never opens the declared configuration file and does not resolve
its schema, credentials, provider access, startup, or runtime behavior.
Pinned source evidence is `pkg/cmd/costmodel/costmodel.go`,
`pkg/costmodel/router.go`, and `pkg/cloud/config/watcher.go` at commits
`75253e9ce35a`, `22da667c0477`, `050ce5a64364`, `faff1c39d11a`,
`37e08c6365d0`, `8572a23ed7d9`, `1741baaf3682`, and `e22df84a4fb1`.
Whole-upgrade safety remains `UNKNOWN`.

## Cloud Custodian removed IAM access-key json-diff filter

The native Cloud Custodian route decides whether one caller-selected,
complete policy document containing exactly one `iam-access-key`-resource
policy directly declares the removed `json-diff` revision filter. It covers
the reviewed `0.9.50` to `0.9.51` transition and, separately, the
target-only `0.9.52` constraint from the five reviewed `0.9.47`, `0.9.48`,
`0.9.49`, `0.9.50`, and `0.9.51` origins. It is a local usability route for
the existing `cloud-custodian.iam-access-key-json-diff-*` rules; it does not
add a project, rule, or upgrade-pair claim. The `PrepareCloudCustodian`
adapter already existed and evaluated every one of these six pairs via the
two-step `prepare`/`check` path before this route was wired; only the
one-step dispatch and catalog registration were added.

```sh
umask 077
cat > cloud-custodian-policy.json <<'JSON'
{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}
JSON
chmod 600 cloud-custodian-policy.json
./prufyx check cncf --project cloud-custodian \
  --native-resource cloud-custodian-policy.json \
  --from 0.9.50 --to 0.9.51 --now 2026-09-19T00:00:00Z
```

A policy whose single filters list contains exactly one recognized
`json-diff` filter is `BLOCKED`; an empty filters list on the same
resource-typed policy is a scoped `PASS`. Root-level variables or includes,
any other filter, multiple policies, or an unreviewed version pair all
remain `UNKNOWN` rather than a negative-presence `PASS`. The route never
resolves variables, includes, dynamic resource selection, or AWS API
execution. Pinned source evidence is `c7n/resources/iam.py` and
`c7n/filters/revisions.py`. Whole-upgrade safety remains `UNKNOWN`.

## Argo CD Helm 4 plain-HTTP OCI repository

The native Argo CD repository route decides whether one caller-selected,
pre-apply `stringData` repository `Secret` with `type: helm` and
`enableOCI: "true"` is unusable under the reviewed Helm 4 plain-HTTP
boundary: an insecure OCI registry needs an explicit `insecureOCIForceHttp`
declaration, and Helm 4 now also honors `insecure`. It covers the five
reviewed `3.0.23`, `3.1.16`, `3.2.12`, `3.3.14`, and `3.4.8` origins to
`3.5.2`. It is a local usability route for the existing
`argo-cd.plain-http-oci-repository-helm4.*` rules; it does not add a
project, rule, or upgrade-pair claim. The `PrepareArgoCDLatestRepository`
adapter already existed and evaluated all five origins via the two-step
`prepare`/`check` path before this route was wired; only the one-step
dispatch and catalog registration were added.

```sh
umask 077
cat > argocd-repository-secret.json <<'JSON'
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"false","insecure":"false"}}
JSON
chmod 600 argocd-repository-secret.json
./prufyx check cncf --project argo-cd \
  --repository-secret argocd-repository-secret.json \
  --from 3.4.8 --to 3.5.2 \
  --repository-distribution official_upstream --repository-settings-resolved true --repository-uses-plain-http true \
  --now 2026-09-19T00:00:00Z
```

Distribution, settings-resolved, and plain-HTTP are all separate operator
declarations; a scoped result additionally requires the official
distribution, resolved settings, and a declared plain-HTTP selection. A
`type: helm` repository with OCI enabled and neither `insecureOCIForceHttp`
nor `insecure` set to permit plain HTTP is `BLOCKED`; the same repository
with `insecureOCIForceHttp: "true"` is a scoped `PASS`. A non-`helm` type,
disabled OCI, a missing guard declaration, or an unreviewed origin all
remain `UNKNOWN` rather than a negative-presence `PASS`. The route never
resolves Secret values, names, URLs, credentials, repository connectivity,
or Helm execution. Pinned source evidence is `util/helm/client.go`,
`pkg/apis/application/v1alpha1/repository_types.go`,
`util/db/repository_secrets.go`, and `util/db/secrets.go`. Whole-upgrade
safety remains `UNKNOWN`.

## Linkerd mTLS identity-selector cardinality

The native Linkerd route derives whether a proposed
`policy.linkerd.io/v1alpha1` `MeshTLSAuthentication` resource declares an
empty `identities` or `identityRefs` selector for the reviewed `2.13.7` to
`2.14.0` transition. It is a local usability route for the existing
`linkerd.mtls-identity-selector-minitems.2-13-2-14` rule; it does not add a
project, rule, or upgrade-pair claim. The `PrepareLinkerd` adapter already
existed and evaluated this pair via the two-step `prepare`/`check` path
before this route was wired; only the one-step dispatch and catalog
registration were added.

```sh
umask 077
cat > linkerd-meshtls.json <<'JSON'
{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","metadata":{"name":"private","namespace":"private"},"spec":{"identities":[]}}
JSON
chmod 600 linkerd-meshtls.json
./prufyx check cncf --project linkerd \
  --linkerd-resource linkerd-meshtls.json \
  --from 2.13.7 --to 2.14.0 \
  --linkerd-distribution official_upstream --schema-validation required \
  --now 2026-09-19T00:00:00Z
```

An empty `identities` (or `identityRefs`) array is `BLOCKED`; a nonempty
array is a scoped `PASS`. Both selectors declared together, neither
selector present, or an unreviewed version pair all remain `UNKNOWN` rather
than a negative-presence `PASS`. The route never parses a CRD schema, calls
API admission, or inspects stored objects. Pinned source evidence is
`charts/linkerd-crds/templates/policy/meshtls-authentication.yaml`.
Whole-upgrade safety remains `UNKNOWN`.

## Karmada removed legacy application purgeMode values

The native Karmada route witnesses a removed legacy `purgeMode` value
(`Immediately` or `Graciously`) at
`spec.failover.application.purgeMode` on one proposed `PropagationPolicy` or
`ClusterPropagationPolicy` resource for the reviewed `1.18.3` to `1.19.0`
transition. It is a local usability route for the existing
`karmada.application-purge-mode-legacy-values-removed.1-19` rule; it does
not add a project, rule, or upgrade-pair claim. The `PrepareKarmada` adapter
already existed and evaluated this pair via the two-step `prepare`/`check`
path before this route was wired; only the one-step dispatch and catalog
registration were added.

```sh
umask 077
cat > karmada-policy.json <<'JSON'
{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","metadata":{"name":"private"},"spec":{"failover":{"application":{"purgeMode":"Immediately"}}}}
JSON
chmod 600 karmada-policy.json
./prufyx check cncf --project karmada \
  --karmada-resource karmada-policy.json \
  --from 1.18.3 --to 1.19.0 \
  --karmada-distribution official_upstream --target-policy-crd-admission required \
  --now 2026-09-19T00:00:00Z
```

`Immediately` or `Graciously` is a conclusive `BLOCKED` witness. Every other
observed value, a missing `purgeMode`, or an unreviewed version pair remains
`UNKNOWN`: the adapter can witness a legacy value but never proves its
absence across every proposed resource, so this route never emits `PASS`.
The route never validates a CRD schema, calls API admission, or inspects
stored objects. Pinned source evidence is
`pkg/apis/policy/v1alpha1/propagation_types.go` and
`pkg/util/validation/validation.go`. Whole-upgrade safety remains `UNKNOWN`.

## Cilium nonempty fromRequires/toRequires removal

The native Cilium policy route witnesses a nonempty `fromRequires` or
`toRequires` selector on one proposed `CiliumNetworkPolicy`,
`CiliumClusterwideNetworkPolicy`, or flat `v1`/typed list, for the reviewed
`1.18.6` to `1.19.0` legacy pair and, separately, the target-only `1.19.7`
constraint from the `1.18.13` origin. It is a local usability route for the
existing `cilium.nonempty-requires-rejected.1-19` and
`cilium.nonempty-requires-crd-maxitems.1-18-13-to-1-19-7` rules; it does not
add a project, rule, or upgrade-pair claim. The `PrepareCilium` adapter
already existed and evaluated both pairs via the two-step `prepare`/`check`
path before this route was wired; only the one-step dispatch and catalog
registration were added.

```sh
umask 077
cat > cilium-policy.json <<'JSON'
{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"private"},"spec":{"ingress":[{"fromRequires":[{}]}]}}
JSON
chmod 600 cilium-policy.json
./prufyx check cncf --project cilium \
  --cilium-policy cilium-policy.json \
  --from 1.18.6 --to 1.19.0 \
  --now 2026-09-19T00:00:00Z
```

A nonempty `fromRequires`/`toRequires` entry anywhere in the selected
document is a conclusive `BLOCKED` witness. An empty selector is a scoped
`PASS` only when the caller also declares `--complete-cnp-ccnp-set true`
for the one selected CNP/CCNP set; without that declaration, or with a
partial `List` (a `continue` token or positive `remainingItemCount`), the
result stays `UNKNOWN` rather than a negative-presence `PASS`. The adapter
never discovers set completeness from a cluster; that declaration is always
an operator guard. Pinned source evidence is
`Documentation/operations/upgrade.rst`. Whole-upgrade safety remains
`UNKNOWN`.

## Envoy direct V2 transport blocker

The Envoy native route is a blocker-only usability route for the existing
`component.envoy.xds_api_major` rule. It accepts a private, regular JSON
bootstrap no larger than 1 MiB and the caller's `--envoy-bootstrap-selected`
declaration. It emits `v2` only when a direct, uppercase `V2` witness occurs
at `dynamic_resources.ads_config.transport_api_version` (with `api_type:
GRPC`), `dynamic_resources.lds_config.api_config_source.transport_api_version`,
or `dynamic_resources.cds_config.api_config_source.transport_api_version` (the
latter two require an admitted explicit `api_type`). It supports only the
existing `1.34.14`, `1.35.13`, `1.36.10`, `1.37.6`, and `1.38.4` to `1.39.1`
pairs.

```sh
umask 077
cp bootstrap.json private-bootstrap.json
chmod 600 private-bootstrap.json
./prufyx check cncf --project envoy \
  --envoy-bootstrap private-bootstrap.json --envoy-bootstrap-selected \
  --from 1.38.4 --to 1.39.1 --now 2026-09-13T00:00:00Z
```

Absent, `AUTO`, `V3`, numeric, lowercase, lower-camel aliases, malformed
selected ConfigSource oneofs, and valid but unsupported JSON shapes remain
`UNKNOWN`; malformed JSON containers (objects or arrays), unreadable files,
invalid encoding, and oversized input are rejected. YAML and other non-JSON
text are safely bounded but not parsed, so they remain `UNKNOWN`. It does not
derive a native PASS. Static resources,
`resource_api_version`, `self`, `hds_config`, `config_sources`,
`default_config_source`, `typed_config`/Any, extensions, fetched discovery
resources, network behavior, server behavior, runtime state, and distribution
identity are outside this route. The `1.39.1` target evidence is Envoy commit
`b579d07d3ad7ee11d32b105e91a5a39ad24718d7`: bootstrap proto lines 61-90,
ConfigSource proto lines 25-75 and 182-227, and `utility.h` lines 138-155.

## OpenTelemetry Collector logging exporter and internal-metrics bind

For the reviewed `0.110.0` to `0.111.0` transition, `check cncf --project
opentelemetry` has two native routes over the same complete,
precedence-resolved Collector YAML with declared official distribution: the
default route checks the selected `logging` exporter
(`opentelemetry.logging-exporter-removed.0-111`), and `--otel-rule
internal-telemetry-default-bind` checks the target internal-metrics
localhost-default bind against explicit `--otel-metrics-localhost-default`
and `--otel-metrics-remote-scrape-required` declarations
(`opentelemetry.internal-telemetry-default-bind.0-110-to-0-111`). See
[`examples/cncf/opentelemetry-collector`](../examples/cncf/opentelemetry-collector/README.md).

## Argo CD required RBAC inheritance and resource-exclusions visibility

For the reviewed `2.14.0` to `3.0.0` transition, `check cncf --project
argo-cd` has two native routes: `--config-map FILE` checks the
`server.rbac.disableApplicationFineGrainedRBACInheritance` setting against an
explicit `--requires-inherited-application-permissions` intent
(`argo-cd.required-rbac-inheritance.3-0`), and
`--resource-exclusions-config-map FILE
--resource-exclusions-config-complete --resource-exclusions-precedence-resolved`
checks the `resource.exclusions` target default against an explicit
`--requires-v2-visibility-of-v3-default-excluded-resources` intent
(`argo-cd.resource-exclusions-v2-visibility-preservation.3-0`). Neither route
infers RBAC intent or resource existence from a cluster.

## CRI-O, CubeFS, TUF, in-toto, Knative, Kubeflow, Buildpacks, OpenFGA, Distribution, and CNI native routes

Each of these has one reviewed rule with a working single-step native CLI
route under `check cncf --project PROJECT`, discoverable the same way as the
routes above:

- CRI-O `1.34.0` to `1.35.0`: `--image-status-request FILE
  --artifact-operation named-reference-resolution`
  (`cri-o.artifact-short-name-rejected.1-35`); see
  [`examples/cncf/crio-image-status-request`](../examples/cncf/crio-image-status-request/).
- CubeFS `3.2.1` to `3.3.2`: `--metanode-config FILE [--phase
  metanode-upgrade]` (`cubefs.metanode-raft-snapshot-format.3-2-1-to-3-3-2`);
  see [`examples/cncf/cubefs-metanode`](../examples/cncf/cubefs-metanode/).
- python-tuf (`--project the-update-framework-tuf`) `6.0.0` to `7.0.0`:
  `--python-source FILE` (`tuf.updater-bootstrap-keyword.6-to-7`); see
  [`examples/cncf/tuf-updater`](../examples/cncf/tuf-updater/).
- in-toto `2.2.0` to `3.0.0`: `--in-toto-run-argv FILE`
  (`in-toto.run-legacy-key-argument-removed.2-2-to-3-0`); see
  [`examples/cncf/in-toto-run`](../examples/cncf/in-toto-run/).
- Knative Serving `1.22.0` to `1.23.0`: `--service FILE`
  (`knative.serving-startup-http-named-port.1-22-to-1-23`); see
  [`examples/cncf/proposed-knative-serving-service.json`](../examples/cncf/proposed-knative-serving-service.json).
- Kubeflow Pipelines SDK `1.8.22` to `2.0.0`: `--python-source FILE`
  (`kubeflow.kfp-create-component-from-func-removed.1-8-22-to-2-0-0`); see
  [`examples/cncf/kubeflow-kfp`](../examples/cncf/kubeflow-kfp/).
- Buildpacks Lifecycle `0.16.5` to `0.17.7`: `--current-lifecycle-config FILE
  --proposed-lifecycle-config FILE --current-platform-api 0.11
  --proposed-platform-api 0.12|0.13`
  (`buildpacks.lifecycle-platform-api-support.0-16-5-to-0-17-7`); see
  [`examples/cncf/buildpacks`](../examples/cncf/buildpacks/).
- OpenFGA `1.17.1` to `1.18.0`: `--effective-config FILE
  [--effective-config-complete]` (`openfga.oidc-required-fields.1-17-1-to-1-18-0`);
  see [`examples/cncf/openfga-oidc-upgrade`](../examples/cncf/openfga-oidc-upgrade/README.md).
- Distribution `2.8.3` to `3.0.0`: `--image-manifest FILE`
  (`distribution.schema1-manifest-removed.2-8-3-to-3-0-0`); see
  [`examples/cncf/distribution-manifest`](../examples/cncf/distribution-manifest/).
- CNI spec (`--project container-network-interface-cni`) `0.4.0` to `1.0.0`:
  `--cni-configuration FILE [--operation configuration-spec-migration]`
  (`cni-spec.non-list-configuration-removed.0-4-0-to-1-0-0`); see
  [`examples/cncf/cni-spec`](../examples/cncf/cni-spec/).

Emissary-Ingress `3.10.0` to `4.0.1` (`--diagd-argv FILE`,
`emissary-ingress.metrics-endpoint-removed.3-10-to-4-0`) uses the same
pattern; see
[`examples/cncf/emissary-ingress`](../examples/cncf/emissary-ingress/README.md).
Every one of these routes reads only the caller-supplied private file; it
does not run the target project, inspect a cluster, or resolve wrappers,
environment, or precedence on the operator's behalf.

## cert-manager removed monitor values

```sh
umask 077
cat >values.json <<'JSON'
{"prometheus":{"servicemonitor":{"path":"/custom"}}}
JSON
./prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 --values ./values.json
```

The check has one claim: whether the exact merged values contain any of
`prometheus.servicemonitor.path`,
`prometheus.servicemonitor.targetPort`, or
`prometheus.podmonitor.path`. Presence is `BLOCKED`; absence is a scoped
`PASS`; a non-object parent is `UNKNOWN`. Every report keeps the aggregate
assessment `UNKNOWN`. Arbitrary unknown keys and the rest of the target Helm
schema remain outside this predicate. Run `helm template` with the exact target
chart and schema validation enabled for full schema coverage.

`--schema-validation required` is the default and permits a source-backed
`BLOCKED` when a removed key would fail Helm schema validation. If the intended
render disables that validation, pass `--schema-validation disabled`; a removed
key becomes `ATTENTION` because the target templates ignore the override.

The report displays the baked-in official chart manifest digests. The declared
versions select that reviewed source contract; they do not prove those charts
match a deployed installation. Optional `--current-chart-digest` and
`--target-chart-digest` assertions fail with exit 3 when they differ.

The additive latest target is `1.21.2`. It accepts the five reviewed chart
origins `1.20.3`, `1.19.6`, `1.18.6`, `1.17.4`, and `1.16.5`; each route keeps
the same three removed monitor-value paths. For a local synthetic check, copy
[`examples/community/cert-manager-removed.json`](../examples/community/cert-manager-removed.json)
to a private values file and select any one of those origins:

```sh
umask 077
cp examples/community/cert-manager-removed.json values.json
chmod 600 values.json
./prufyx check cert-manager-values \
  --from 1.19.6 --to 1.21.2 --values values.json \
  --current-chart-digest sha256:5d95e81072636335b7b43fc2517e5336b93b77d41a4c87cbaf291783f03b4a0f \
  --target-chart-digest sha256:634dce9c13b56677a2c05e2ab76c312d0be2664022d5dd05815da67e1fd5f610
```

The target chart identity is pinned to the official OCI manifest digest. The
historical `1.20.3` to `1.21.1` route remains available with its original
contract; neither route proves full Helm schema, rendering, runtime behavior,
or whole-upgrade safety.

To retain and replay a deterministic JSON receipt, bind the original input by
its SHA-256 digest:

```sh
digest="sha256:$(shasum -a 256 values.json | awk '{print $1}')"
./prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 \
  --values ./values.json --values-digest "$digest" --format json >receipt.json
./prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 \
  --values ./values.json --values-digest "$digest" \
  --replay-receipt ./receipt.json --format json
```

Replay requires the original local values file, its explicit digest, and the
receipt. It compares deterministic canonical output. This detects local drift;
the receipt's self-consistency does not authenticate its author.

Exit codes are bound to this named predicate: 0 `PASS`, 10 `BLOCKED`, 11
`ATTENTION` or `UNKNOWN`, 2 invalid input, and 3 integrity mismatch.

## Prometheus agent mode

The synthetic demonstration exercises the pinned PASS, ATTENTION, and UNKNOWN
vectors without observation or compatibility authority:

```sh
./prufyx check prometheus-mode --demo --format json
```

For an actual local observation and proposed workload, use:

```sh
./prufyx check prometheus-mode \
  --observation-root ./observation \
  --proposed-workload ./proposed.json \
  --proposed-digest sha256:... \
  --captured-at 2026-09-07T10:00:00Z \
  --now 2026-09-07T10:00:00Z \
  --max-age 24h
```

The new command exits 0 only when the agent-mode preservation claim is `PASS`;
`ATTENTION` and `UNKNOWN` exit 11. The aggregate remains `UNKNOWN`. The legacy
`community-preview validate-prometheus-mode` route retains its aggregate exit
11 behavior.

## Tekton Pipelines metrics-protocol migration

The native Tekton route decides whether one caller-selected proposed
`config-observability` ConfigMap has exactly one functional
`metrics-protocol` value of `prometheus`, for the reviewed `1.9.0` to
`1.10.0` transition. It is a local usability route for the existing
`tekton.metrics-protocol-prometheus.1-10` rule; it does not add a project,
rule, or upgrade-pair claim. Each accepted outcome is established by the
pinned evidence: the `v1.10` `config/config-observability.yaml` sets
`metrics-protocol: prometheus` in its `data` block under `apiVersion: v1`,
`kind: ConfigMap`, `name: config-observability`; the `v1.10`
`knative.dev/pkg/observability/metrics/config.go` declares the protocol
tokens `grpc`, `http/protobuf`, `prometheus` and `none`, parses only the flat
`metrics-protocol` key, and its `DefaultConfig` returns `ProtocolNone`; and
the `v1.10` legacy note together with the `v1.9`
`knative.dev/pkg/metrics/config.go` parser establish that
`metrics.backend-destination` is the removed OpenCensus spelling the target
parser no longer recognizes.

```sh
umask 077
cat > config-observability.yaml <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-observability
  namespace: tekton-pipelines
data:
  metrics-protocol: prometheus
YAML
chmod 600 config-observability.yaml
./prufyx check cncf --project tekton \
  --tekton-config-observability config-observability.yaml \
  --tekton-distribution official_upstream \
  --tekton-system-namespace tekton-pipelines \
  --tekton-config-observability-complete true \
  --retain-prometheus-metrics-required true \
  --from 1.9.0 --to 1.10.0 --now 2026-09-19T00:00:00Z
```

An exact `metrics-protocol: prometheus` data value is a scoped `PASS`. A
definite absence of that key -- including a ConfigMap that still carries only
the removed `metrics.backend-destination` key, and a ConfigMap with no `data`
block at all -- is `BLOCKED`, because the pinned target `DefaultConfig`
resolves to `ProtocolNone`. Everything else stays `UNKNOWN`: a recognized
non-Prometheus token such as `grpc`, `http/protobuf` or `none`; an empty,
whitespace-padded, differently-cased or unrecognized value; a near-miss or
duplicate key spelling; a non-string value; `binaryData` that overlaps the
reviewed key; a templated or unrendered document; and an unreviewed version
pair. The `_example` block is a data value, not a protocol source, and is
never scanned. The removed `metrics.backend-destination` key is never read as
a protocol, because the reviewed evidence states the target parser no longer
recognizes it and reading it would invent a claim.

Identity binding compares the document's `apiVersion`, `kind` and `name`
with the exact reviewed identity and its `namespace` with
`--tekton-system-namespace`, which is the caller's own declaration of the
proposed system namespace. No ConfigMap is discovered from a cluster, and
effective composition, overlays, endpoint configuration, scrape
availability, dashboards, alerts and runtime rollout are not evaluated.
Pinned source evidence is `config/config-observability.yaml`,
`vendor/knative.dev/pkg/observability/metrics/config.go` and
`vendor/knative.dev/pkg/configmap/parser/parse.go` at revision
`9db88e0a3f07`, and `config/config-observability.yaml` with
`vendor/knative.dev/pkg/metrics/config.go` at revision `0cc798780b36`.
Whole-upgrade safety remains `UNKNOWN`.

## KubeEdge keadm init version-selector migration

The native KubeEdge route decides which of the two reviewed `keadm init`
version-selector forms one caller-declared effective argv literally uses, for
the reviewed `1.18.0` to `1.19.0` transition. It is a local usability route for
the existing `kubeedge.keadm-init-profile-version-selector.1-18-to-1-19` rule;
it does not add a project, rule, or upgrade-pair claim. The reviewed rule's own
fact description already states the whole accepted grammar, and each accepted
form is established by the pinned evidence: the `v1.18` `--profile` flag help
documents `/path/version.yaml or version=v<version>`, the `v1.18` install path
splits that option value on `=` and treats only the literal key `version` as a
version selector, the `v1.19` install path hands `--profile` straight to
external values-file reading with no version parsing, and the `v1.19` release
note states that `--profile version` is no longer supported.

```sh
umask 077
cat > keadm-init-argv.json <<'JSON'
["keadm","init","--advertise-address=10.0.0.9","--profile","version=v1.19.0"]
JSON
chmod 600 keadm-init-argv.json
./prufyx check cncf --project kubeedge \
  --keadm-init-argv keadm-init-argv.json \
  --kubeedge-distribution official_upstream \
  --keadm-argv-complete true \
  --from 1.18.0 --to 1.19.0 --now 2026-09-19T00:00:00Z
```

A literal `--profile version=<version>` selector, in either the separated or
the attached spelling, is a conclusive `BLOCKED` witness. An explicit
`--kubeedge-version=v1.19.0` with `--profile` definitely absent is a scoped
`PASS`, and only when the caller also declares
`--kubeedge-distribution official_upstream` and `--keadm-argv-complete true`.
Every other shape stays `UNKNOWN` rather than becoming a negative-presence
`PASS`: an external `--profile` values file, including a version-like filename
such as `/local/version.yaml`; both selectors together, whose reviewed meaning
is not decided because the `v1.18` install path only consults
`--profile version=` when `--kubeedge-version` is empty; neither selector; a
non-target `--kubeedge-version` value; repeated `--profile` options with
different meanings; any single-dash shorthand token, because the pinned flag
registrations declare only long-form options; a `-`/`--` delimiter; a missing
option value; and templated or unrendered argv. Every token is scanned and
there is no option table, so no selector spelling can be stepped over as
another option's value.

The declared argv is caller-supplied data. It is never executed, no `--profile`
values file is ever opened or interpreted, and wrappers, entrypoints, images,
environment, Helm values, chart defaults, and runtime behavior are not
evaluated. Argv completeness, the distribution, and the command surface remain
the caller's own declarations. Pinned source evidence is
`keadm/cmd/keadm/app/cmd/cloud/init.go`,
`keadm/cmd/keadm/app/cmd/helm/cloudcore.go`,
`keadm/cmd/keadm/app/cmd/helm/helm_helper.go` at revisions `c5e705a7545d` and
`6ca40b8e51d9`, and `blog/release-v1.19/index.mdx` at revision
`656ad81a245c`. Whole-upgrade safety remains `UNKNOWN`.

## SPIFFE X.509-SVID public-leaf URI-SAN subset

Use `prufyx check spiffe-x509-svid --certificate FILE --now RFC3339` for the
embedded standards profile. This command has no from/to versions. It returns
`PASS`, `FAIL`, or `UNKNOWN` for one named subset and leaves complete SPIFFE ID,
X.509-SVID, trust, possession, issuance and runtime checks unresolved. Private
input, exact replay, explicit local profile selection and exit semantics are in
the [SPIFFE conformance guide](spiffe-x509-svid.md).

## CloudEvents structured JSON core-envelope subset

Use `prufyx check cloudevents-structured-json --event FILE --now RFC3339` for
the embedded standards profile. This command has no from/to versions. It
returns `PASS`, `FAIL`, or `UNKNOWN` for one staged CloudEvents edition 1.0
core-envelope subset. Payload schemas, source URI semantics, extensions,
transport, SDK/runtime behavior, delivery, signing, and authentication remain
unresolved. Private input, Unicode and duplicate-key handling, selected local
profile metadata, exact replay, and exit semantics are in the [CloudEvents
conformance guide](cloudevents-structured-json.md).

## TiKV 8.5.8 GCS WIF full-backup planned-operation preflight

Use `prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version
8.5.8 --operation gcs-full-backup-wif --now RFC3339` for the embedded target
profile. The check reads one proposed native TiKV TOML file and evaluates only
whether exactly one supported `[backup]` spelling explicitly sets the GCP v2
backend Boolean to `true` for the caller-declared plan. A scoped `PASS` does not
establish effective configuration, credentials, GCS access, backup execution or
completion, restore or log-backup behavior, runtime behavior, or data safety.
Private input, the exact `BLOCKED` remediation, selected local profile metadata,
raw-byte pinning, historical replay, and exit semantics are in the [TiKV target
preflight guide](tikv-gcp-v2-wif-backup.md).
