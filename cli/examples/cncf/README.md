# CNCF source-constraint examples

## Check the Prometheus remote-write HTTP/2 default

The [`native-resources/prometheus`](native-resources/prometheus) directory has
`remote-write-http2-blocked.yml`, `remote-write-http2-fixed.yml`, and
`remote-write-http2-unknown.yml` for the exact Prometheus `2.55.1` to `3.14.0`
rule. The blocked input omits the direct inline `enable_http2` key while the
caller declares HTTP/2 required; the fixed input sets it to `true`; the unknown
input puts a lookalike under `http_config`, which is not the source-backed
field. See the [bounded command guide](../../docs/prometheus-remote-write-http2.md)
for private-copy, digest, interpretation, and non-claim details.

## Check one Argo CD 3.5.2 Helm repository Secret

[`argocd-35-plain-http-repository-secret.json`](argocd-35-plain-http-repository-secret.json)
is a synthetic pre-apply repository Secret. From the repository root, copy it
to a fresh private directory, prepare the minimized declaration, and check it:

```sh
set -eu
umask 077
argo_dir="$(mktemp -d)"
trap 'rm -rf "$argo_dir"' EXIT
cp cli/examples/cncf/argocd-35-plain-http-repository-secret.json "$argo_dir/repository.json"
chmod 600 "$argo_dir/repository.json"
prufyx prepare cncf --project argo-cd \
  --input "$argo_dir/repository.json" --from 3.4.8 --to 3.5.2 \
  --distribution official_upstream --repository-settings-resolved true \
  --repository-uses-plain-http true \
  --format input > "$argo_dir/input.json"
chmod 600 "$argo_dir/input.json"
input_digest="$(shasum -a 256 "$argo_dir/input.json" | awk '{print $1}')"
set +e
prufyx check cncf --project argo-cd --input "$argo_dir/input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
argo_exit=$?
set -e
printf 'Argo CD scoped check exit: %s\n' "$argo_exit"
```

The example lacks `insecureOCIForceHttp=true`, so it produces the one scoped
`BLOCKED` claim and exit `10` while the whole-upgrade assessment remains
`UNKNOWN`. The same target is reviewed from exact origins `3.0.23`, `3.1.16`,
`3.2.12`, `3.3.14`, and `3.4.8`; change only `--from` to select one of them.
The adapter admits only `type=helm` plus `enableOCI=true`. Native `type=oci`,
dependency chart pulls, custom builds, unresolved inherited repository
credentials/settings, authentication, connectivity, and Helm execution remain
`UNKNOWN`. The completeness/precedence and plain-HTTP flags are caller
declarations. OCI repository URLs use Argo CD's protocol-free registry/path
form. Secret names, URLs, and credentials are discarded rather than copied.

## Check a CloudEvents structured JSON envelope

[`cloudevents-structured-json/event.json`](cloudevents-structured-json/event.json)
is a synthetic native CloudEvents edition 1.0 JSON event. Copy it to a private
single-link file before checking the named core-envelope subset:

```sh
umask 077
cp cli/examples/cncf/cloudevents-structured-json/event.json event.json
chmod 600 event.json
prufyx check cloudevents-structured-json --event event.json \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

The example produces scoped `PASS` only for the staged required-string and
payload-member predicates. Edit the same private file to remove `type` and the
same command produces scoped `FAIL` with exit `10`; restore a valid nonempty
`type` to recheck. The command does not validate source URI-reference
semantics, payload schemas, extensions, transport, SDK/runtime behavior,
delivery, signing, or authentication. See the [full conformance
guide](../../docs/cloudevents-structured-json.md) for selected local metadata,
privacy, and replay.

## Check an OpenTelemetry Collector declaration

[`opentelemetry-collector/input.json`](opentelemetry-collector/input.json) is a
synthetic operator declaration for the OpenTelemetry **Collector** only. It
contains the exact `0.110.0` -> `0.111.0` transition, the `official` distribution
guard, and an explicit declaration that the proposed effective configuration
uses the logging exporter. The facts are manual declarations; the example does
not parse Collector configuration, inspect an image, or prove exporter
replacement or telemetry delivery.

Run the local walkthrough with an already-built Community executable:

```sh
prufyx community-preview example cncf-opentelemetry
```

The Go walkthrough creates private `0600` temporary files, binds every input
with its digest, and removes its temporary directory. The retained `run.sh`
entrypoint is a compatibility shim for an already-built Community executable. The explicit `logging_exporter_present=true` case returns scoped
`BLOCKED` (exit `10`). A declaration with that fact explicitly set to `false`
returns scoped `PASS` (exit `0`), while an absent fact returns `UNKNOWN` (exit
`11`). Every report retains aggregate `UNKNOWN`, and no case proves runtime,
startup, pipeline delivery, or whole-upgrade safety.

## Review OPA and Kyverno latest-target constraints

Two Go walkthroughs exercise all five selected exact origins for each latest
target:

```sh
prufyx community-preview example cncf-opa-latest
prufyx community-preview example cncf-kyverno-latest
```

The OPA walkthrough covers `1.15.2`, `1.16.2`, `1.17.1`, `1.18.2`, and
`1.19.1` targeting `1.20.2`. It checks a declared v0-consumer scenario with the
effective producer `--v0-compatible` mode absent (`BLOCKED`), enabled (`PASS`),
and missing (`UNKNOWN`). These are operator facts; the command does not parse
modules, bundles, consumers, or policy syntax.

The Kyverno walkthrough covers `1.14.5`, `1.15.3`, `1.16.4`, `1.17.2`, and
`1.18.2` targeting `1.19.1`. It uses the native private workload preparer for
an official bare `reports-controller` command with a literal
`--reportsChunkSize` option (`BLOCKED`), definite literal absence (`PASS`), and
a custom distribution (`UNKNOWN`). The exact `1.15.3` release is used; a
misleading `v1.15.20` tag was rejected during source qualification because it
does not identify an official matching stable release.

Both walkthroughs create mode `0600` temporary input files, bind exact bytes by
digest, and remove the temporary directory. They do not contact a network or
cluster, execute OPA or Kyverno, inspect images, or prove controller behavior or
whole-upgrade safety. Each envelope retains aggregate `UNKNOWN`.

## Check three graduated-project declarations

These checked-in files are small, synthetic operator declarations for three
existing, source-reviewed transitions:

| Example | Exact scope | Declared trigger |
| --- | --- | --- |
| [`kubernetes-dockershim-input.json`](kubernetes-dockershim-input.json) | Kubernetes `1.23.17` → `1.24.0` | proposed in-tree dockershim is required |
| [`crossplane-composition-input.json`](crossplane-composition-input.json) | Crossplane `1.20.0` → `2.0.0` | official target CRD declares `resources` Composition mode |
| [`opa-producer-input.json`](opa-producer-input.json) | OPA `0.70.0` → `1.0.0` | v0 consumers remain, modules omit `rego.v1`, and producer v0 compatibility is false |

Each file is a public example of the canonical v1 input shape, not an observed
cluster or workload fact. Copy the selected file to a real private regular
file before use, create it under `umask 077`, and keep it `0600`:

```sh
umask 077
cp cli/examples/cncf/kubernetes-dockershim-input.json kubernetes-input.json
chmod 600 kubernetes-input.json
input_digest="$(shasum -a 256 kubernetes-input.json | awk '{print $1}')"
prufyx check cncf --project kubernetes --input kubernetes-input.json \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

For the other two files, repeat the same private-copy and digest steps with
`crossplane-composition-input.json` and `--project crossplane`, or with
`opa-producer-input.json` and `--project opa`.

The Kubernetes predicate is limited to in-tree dockershim requirement; Docker
use, external `cri-dockerd`, CRI health, and runtime compatibility are outside
its evidence. Crossplane checks the official upstream target CRD schema guard:
`resources` is the scoped trigger and `pipeline` is the declared non-trigger
only when the distribution and schema-validation declarations match. Custom
builds and other schema behavior remain out of scope. OPA checks the producer
option prerequisite while v0 consumers remain; it does not assess policy
syntax, module contents, or bundle delivery. A declared false value is an
operator statement for that predicate, not proof from a live system.

For all three examples, missing or conflicting facts, unsupported values, and
the wrong version pair produce `UNKNOWN`; they are not treated as a false
declaration. The scoped claim can be `BLOCKED`, `PASS`, or `UNKNOWN`, while the
aggregate remains `UNKNOWN`. No example establishes API admission, startup,
runtime behavior, or whole-upgrade safety.

## Check five more graduated-project declarations

These checked-in files are synthetic operator declarations for exact existing
source-reviewed tuples:

| Example | Exact scope | Declared trigger |
| --- | --- | --- |
| [`containerd-input.json`](containerd-input.json) | containerd `1.7.28` → `2.0.0` | proposed CRI API is `v1alpha2` |
| [`coredns-input.json`](coredns-input.json) | CoreDNS `1.6.9` → `1.7.0` | official distribution uses the federation directive |
| [`envoy-input.json`](envoy-input.json) | Envoy `1.17.2` → `1.18.0` | proposed xDS API major is `v2` |
| [`helm-post-renderer-input.json`](helm-post-renderer-input.json) | Helm `3.14.4` → `4.0.0` | proposed post-renderer uses an executable path |
| [`istio-compatibility-profile-input.json`](istio-compatibility-profile-input.json) | Istio `1.23.6` → `1.24.0` | proposed compatibility profile is `1.20` |

The files are public examples of the canonical v1 input shape, not observed
cluster facts. Copy the selected file to a private regular file under
`umask 077`, keep it `0600`, and bind its exact bytes before checking:

```sh
umask 077
cp cli/examples/cncf/containerd-input.json containerd-input.json
chmod 600 containerd-input.json
input_digest="$(shasum -a 256 containerd-input.json | awk '{print $1}')"
prufyx check cncf --project containerd --input containerd-input.json \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

Repeat the same private-copy and digest steps for the other files with
`--project coredns`, `envoy`, `helm`, or `istio`. Containerd covers the CRI API
major only; it does not validate the socket, kubelet, runtime configuration, or
client health. CoreDNS covers the federation directive only for the official
distribution; custom plugin builds remain outside the rule. Envoy covers the
xDS API major declaration only, not every bootstrap reference, schema, control
plane, or rollout. Helm covers the post-renderer argument form; `plugin_name`
is the scoped non-trigger, while plugin installation and rendered output remain
unverified. Istio covers removal of the `1.20` compatibility profile only;
`other` or `unset` means absence of that profile, not validity of another one.

For all five, a declared false or alternate value is an operator statement for
that predicate, not a live observation. Missing or conflicting facts,
unsupported values, and wrong version pairs return `UNKNOWN`; they are not
silently treated as non-triggers. The scoped claim can be `BLOCKED`, `PASS`, or
`UNKNOWN`, while the aggregate remains `UNKNOWN`. These examples establish no
API admission, startup, runtime, traffic, or whole-upgrade safety.

## Check the latest Envoy and CoreDNS target constraints

The native community examples exercise blocked, passing, and unknown declarations
for each of the five exact source-reviewed origins:

```sh
prufyx community-preview example cncf-envoy-latest
prufyx community-preview example cncf-coredns-latest
```

The Envoy example covers `1.34.14`, `1.35.13`, `1.36.10`, `1.37.6`, and
`1.38.4` targeting `1.39.1`. Its only scoped predicate is the declared xDS API
major: `v2` is blocked, `v3` passes that predicate, and a missing declaration
remains `UNKNOWN`. It does not parse bootstrap files, inspect resource type URLs,
validate schemas or control-plane behavior, or establish rollout or whole-upgrade
safety.

The CoreDNS example covers `1.9.4`, `1.10.1`, `1.11.4`, `1.12.4`, and
`1.13.2` targeting the official `1.14.7` distribution. A declared federation
directive is blocked because that directive is absent from the target's complete
generated plugin list; declared absence passes that predicate. Missing directive
state and custom distributions remain `UNKNOWN`. This does not parse a Corefile,
resolve imports, inspect a custom build, execute DNS queries, or establish startup,
runtime, or whole-upgrade safety.

Both examples create digest-bound `0600` inputs in private temporary directories,
use the existing Go `check cncf` route, and perform no network or cluster access.

## Check nine additional graduated-project declarations

These checked-in files are synthetic, operator-declared inputs for the exact
source-reviewed scenarios below. They exercise the existing `check cncf`
workflow; they do not inspect a cluster, parse a product configuration, or
establish runtime behavior.

| Example | Exact component transition | Scoped use and trigger |
| --- | --- | --- |
| [`dragonfly-input.json`](dragonfly-input.json) | Dragonfly `2.2.3` → `2.2.4` | Official manager or scheduler configuration: retained debug logging is required when the declared proposed effective debug setting is `false`; a missing declaration is `UNKNOWN`. The fixture selects `manager_config`; change that declaration to `scheduler_config` for the sibling surface. |
| [`falco-input.json`](falco-input.json) | Falco `0.40.0` → `0.41.0` | Official Falco executable: a declared removed 0.40 CLI flag is present. |
| [`falco-042-input.json`](falco-042-input.json) | Falco `0.40.0` → `0.42.0` | Same official Falco executable predicate for the 0.42 target. |
| [`fluentd-input.json`](fluentd-input.json) | Fluentd `1.16.0` → `1.17.0` | Official upstream Fluentd with Ruby `2.6.9`; Ruby below the proposed `2.7.0` minimum is the scoped trigger. |
| [`flux-input.json`](flux-input.json) | Flux `2.6.4` → `2.7.0` | A declared removed beta API is present. |
| [`harbor-input.json`](harbor-input.json) | Harbor `1.7.5` → `1.8.0` | Docker Compose deployment with legacy `cfg` installer format; `yml` is the declared non-trigger. |
| [`keda-input.json`](keda-input.json) | KEDA `2.16.0` → `2.17.0` | With an external scaler present, a legacy TLS certificate file is required for transport. |
| [`rook-input.json`](rook-input.json) | Rook `1.19.4` → `1.20.0` | Helm deployment exercises the exact intermediate-version rule. For the separate Kubernetes minimum rule, use current Rook `1.19.5` and add proposed Kubernetes `1.30.9` (trigger) or `1.31.0` (non-trigger). |
| [`spire-input.json`](spire-input.json) | SPIRE `1.10.4` → `1.11.0` | Official `spire_server_entry_create` surface with a declared removed entry TTL flag. |
| [`vitess-input.json`](vitess-input.json) | Vitess `22.0.0` → `23.0.0` | A declared multi-statement `ExecuteFetchAsDba` use is present. |

Copy a selected public example to a real private regular file before checking
it, and bind the exact copied bytes with its digest:

```sh
umask 077
cp cli/examples/cncf/flux-input.json flux-input.json
chmod 600 flux-input.json
input_digest="$(shasum -a 256 flux-input.json | awk '{print $1}')"
prufyx check cncf --project flux --input flux-input.json \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

The examples use manual declarations rather than observed workload or
configuration facts. A declared trigger produces the scoped `BLOCKED` result;
an allowed declared non-trigger can produce scoped `PASS`. Missing or
conflicting facts, unsupported values or surfaces, and wrong version pairs
remain `UNKNOWN`; Rook's Helm intermediate rule intentionally has no
non-trigger for its exact guarded pair. The aggregate whole-upgrade result
remains `UNKNOWN` in every case. These scenarios do not claim API admission,
startup, traffic, migration, rollback, or complete upgrade safety.

## Run the synthetic etcd walkthrough

[`etcd/README.md`](etcd/README.md) demonstrates the direct effective-argv
preparation and check flow for the retained etcd 3.5.17 → 3.6.0 route and the
new exact 3.6.14 → 3.7.1 route using only synthetic local inputs. The latest
fixtures cover a removed experimental flag (`BLOCKED`), its documented feature
gate replacement (`PASS`), and an unresolved config-file input (`UNKNOWN`). It
is an offline example and does not establish runtime or whole-upgrade
compatibility.

## Run the Rook 1.20.7 source-constraint walkthrough

[`rook-latest/README.md`](rook-latest/README.md) exercises the Rook 1.20.7
Kubernetes minimum for five exact origins with synthetic `BLOCKED`, `PASS`,
and `UNKNOWN` declarations. The target-only rules make no claim that those
direct routes are supported and require no intermediate Rook version. The
example does not inspect a cluster or establish runtime or whole-upgrade
compatibility.

## Check a Dapr Scheduler declaration

[`dapr-input.json`](dapr-input.json) is a synthetic operator declaration for
the exact Dapr `1.14.0` to `1.15.0` Scheduler transition. Copy it to a private
regular file before checking it:

```sh
umask 077
cp cli/examples/cncf/dapr-input.json dapr-input.json
chmod 600 dapr-input.json
input_digest="$(shasum -a 256 dapr-input.json | awk '{print $1}')"
set +e
./prufyx check cncf --project dapr \
  --input dapr-input.json --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json > dapr-report.json
status=$?
set -e
chmod 600 dapr-report.json
printf 'Dapr exit: %s\n' "$status"
```

The two facts are explicit manual operator assertions about the current
deployment's Dapr Scheduler-owned embedded-etcd data directory. The
`scheduler_embedded_etcd_inventory_complete=true` assertion means the operator
has a complete applicable inventory covering scheduled jobs and
Scheduler-backed actor reminders; ordinary configuration inspection or merely
seeing that Scheduler is enabled does not establish it. The
`scheduler_persisted_data_present=true` assertion means that inventory contains
at least one such job or reminder.

While its source review is current, this declaration returns the scoped Dapr
claim as `BLOCKED` with exit `10`; the aggregate whole-upgrade assessment stays
`UNKNOWN`. An explicitly complete applicable inventory with no such persisted
data makes only this scoped predicate `PASS`. External or custom storage,
partial or unexamined inventories, Scheduler enablement without data knowledge,
missing facts, and other version pairs remain `UNKNOWN`. A snapshot does not by
itself prove a safe migration or restoration. The check does not inspect a
cluster or filesystem, create a backup, restore data, or establish runtime or
whole-upgrade safety.

## Check a KubeEdge keadm init declaration

[The `kubeedge-input.json` file](kubeedge-input.json) is a synthetic manual
operator declaration for the exact official KubeEdge `1.18.0` to `1.19.0`
`keadm init` transition. It declares a complete intended argv whose `--profile
version=<version>` value is explicitly intended as the legacy version selector.
A version-like filename does not establish that intent.

Copy the example to a private regular file, bind its digest, and run `check
cncf` with `--project kubeedge`. While the source review is current, the example
returns scoped `BLOCKED` with exit `10`; the aggregate assessment remains
`UNKNOWN`. For this exact plan, select v1.19.0 with
`--kubeedge-version=v1.19.0`. A scoped `PASS` requires an explicit complete
official `keadm init` declaration using that target flag with `--profile`
absent.

```sh
umask 077
cp cli/examples/cncf/kubeedge-input.json kubeedge-input.json
chmod 600 kubeedge-input.json
input_digest="$(shasum -a 256 kubeedge-input.json | awk '{print $1}')"
./prufyx check cncf --project kubeedge --input kubeedge-input.json \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

A legitimate external `--profile` values file, both selectors, default or
ambiguous selection, partial argv, custom builds, other keadm subcommands, and
other version pairs remain `UNKNOWN`. The check does not parse argv, read a
profile file, contact a cluster, run installation, or establish startup,
runtime, or whole-upgrade safety.

## Prepare a Kyverno declaration

[`proposed-kyverno-deployment.json`](proposed-kyverno-deployment.json) is a
synthetic `apps/v1` Deployment used to demonstrate local preparation. It is
not a customer workload, and its image tag, credentials, options, and runtime
behavior are not verified.

The adapter requires an explicit container name and declared endpoint pair. It
recognizes only the bare `reports-controller` command with the explicit declared distribution and the exact
`--reportsChunkSize=VALUE` argument in this fixture. The value must be a
signed 32-bit Go integer; `--reportsChunkSize=false` is unresolved rather than
proof of presence. The explicit distribution is an operator declaration and
does not verify the image.

Keep the source document as a regular private `0600` file without a symlink and
redirect the minimized declaration under `umask 077`:

```sh
umask 077
chmod 600 proposed-kyverno-deployment.json
source_digest="$(shasum -a 256 proposed-kyverno-deployment.json | awk '{print $1}')"
prufyx prepare cncf --project kyverno \
  --input proposed-kyverno-deployment.json \
  --container kyverno-controller --from 1.12.5 --to 1.13.0 --distribution official_upstream \
  --input-digest "sha256:${source_digest}" --format json
prufyx prepare cncf --project kyverno \
  --input proposed-kyverno-deployment.json \
  --container kyverno-controller --from 1.12.5 --to 1.13.0 --distribution official_upstream \
  --input-digest "sha256:${source_digest}" --format input > kyverno-input.json
chmod 600 kyverno-input.json
```

`--format json` reports preparation state, reason, omissions, and source/input
digests without workload names, environment values, raw arguments,
configuration, image, or local path. `--format input` emits only the canonical
`check cncf` declaration with exactly one trailing newline. `PREPARED` means a
minimized operator declaration was derived; it does not validate Kubernetes,
the image, credentials, options, or target runtime. The hashes bind bytes but
are not anonymity proofs.

Preparation is a local transformation only. It accepts JSON, does not accept
YAML or Helm values, and does not inspect a live cluster, write files, invoke a
model, access a network, or run a compatibility check. Use `check cncf`
separately with the actual canonical UTC time:

```sh
input_digest="$(shasum -a 256 kyverno-input.json | awk '{print $1}')"
prufyx check cncf --project kyverno --input kyverno-input.json \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

While its source review is current, this synthetic example returns scoped
`BLOCKED` and exit `10`: the proposed invocation still contains the removed
`--reportsChunkSize` flag. The whole-upgrade assessment remains `UNKNOWN`.
Preparation exit `0` means `PREPARED`; exit `11`
means unresolved preparation, while still emitting a minimized `missing` or
`unsupported` fact in `--format input`. Invalid input returns `2`, and an
integrity mismatch returns `3`.

## Prepare a Linkerd declaration

[`proposed-linkerd-mesh-tls-authentication.json`](proposed-linkerd-mesh-tls-authentication.json)
is a synthetic `policy.linkerd.io/v1alpha1` `MeshTLSAuthentication` resource.
It contains an intentionally empty `identities` selector; metadata and selector
values are discarded by preparation. Run these commands from the repository
root, after copying the example to a private regular file:

```sh
umask 077
cp cli/examples/cncf/proposed-linkerd-mesh-tls-authentication.json linkerd-resource.json
chmod 600 linkerd-resource.json
source_digest="$(shasum -a 256 linkerd-resource.json | awk '{print $1}')"
set +e
./prufyx prepare cncf --project linkerd \
  --input linkerd-resource.json --from 2.13.7 --to 2.14.0 \
  --distribution official_upstream --schema-validation required \
  --input-digest "sha256:${source_digest}" --format input > linkerd-input.json
status=$?
set -e
chmod 600 linkerd-input.json
printf 'Preparation exit: %s\n' "$status"
```

This declaration is expected to be `PREPARED` with exit `0`; checking the
result produces the scoped Linkerd `BLOCKED` claim and exit `10`, while the
whole-upgrade assessment remains `UNKNOWN`. Use the actual current canonical
UTC time when checking. The adapter derives only selector emptiness and does
not parse the CRD, call API admission, inspect stored objects, migrate them,
or prove runtime behavior. A `false` selector fact is scoped `PASS` only when
exactly one selector property is present and known nonempty while the other is
known absent. Both, neither, malformed, unresolved, custom, disabled, and
other-surface declarations remain `UNKNOWN` or invalid input as applicable.
Malformed Linkerd input reports `LINKERD_PREPARATION_INPUT_INVALID` (exit `2`);
digest or output integrity failures report
`CNCF_PREPARATION_INTEGRITY_FAILURE` (exit `3`), without echoing paths or
resource values.

## Check a Linkerd declaration

[`linkerd-input.json`](linkerd-input.json) is a fully synthetic operator
statement for the reviewed Linkerd `2.13.7` to `2.14.0` target-schema rule.
Run these commands from the repository root after copying it to a private
`0600` file:

```sh
umask 077
cp cli/examples/cncf/linkerd-input.json linkerd-input.json
chmod 600 linkerd-input.json
input_digest="$(shasum -a 256 linkerd-input.json | awk '{print $1}')"
set +e
./prufyx check cncf --project linkerd \
  --input linkerd-input.json --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json > linkerd-report.json
status=$?
set -e
chmod 600 linkerd-report.json
printf 'Linkerd exit: %s\n' "$status"
```

The proposed facts declare the official upstream distribution, the
`meshtls_authentication_crd` surface, a required target-schema validation, and
an exactly-one selector declaration whose known empty side is represented by
`mtls_identity_selector_empty=true`. A current source review produces a named
scoped `BLOCKED` claim and exit `10`; the aggregate whole-upgrade assessment is
`UNKNOWN`. This declaration does not parse the CRD, call API admission, inspect
stored objects, perform migration, or establish runtime behavior. A `false`
selector fact is scoped `PASS` only when exactly one selector is known nonempty
and the other is known absent; missing, conflicting, both, neither, unresolved,
custom, or other-surface facts remain `UNKNOWN`.

## Check a SPIRE declaration

[`spire-input.json`](spire-input.json) is a fully synthetic operator declaration
for the reviewed SPIRE `1.10.4` to `1.11.0` direct `spire-server entry create`
source constraint. Copy it to a private `0600` local file before checking:

```sh
umask 077
cp cli/examples/cncf/spire-input.json spire-input.json
chmod 600 spire-input.json
input_digest="$(shasum -a 256 spire-input.json | awk '{print $1}')"
set +e
./prufyx check cncf --project spire \
  --input spire-input.json --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json > spire-report.json
status=$?
set -e
chmod 600 spire-report.json
printf 'SPIRE exit: %s\n' "$status"
```

The example declares the proposed official upstream distribution and direct
entry-create surface with a legacy `-ttl` or `--ttl` option present, so a current
source review produces a scoped `BLOCKED` claim and exit `10`. The aggregate
whole-upgrade assessment remains `UNKNOWN`. This declaration is not argv
parsing, replacement-TTL validation, entry inspection, a server update, or
runtime evidence. A scoped `PASS` requires an explicit `false` declaration for
both legacy spellings while both guards match; missing, custom, unsupported,
conflicting, wrapped, delimiter-terminated, or other-surface input remains
`UNKNOWN`.

## Check a Dragonfly declaration

[`dragonfly-input.json`](dragonfly-input.json) is a fully synthetic operator
declaration for the reviewed Dragonfly `2.2.3` to `2.2.4` transition. It
selects the manager configuration sibling, declares current verbose debug
intent and proposed retain-debug intent, and declares an effective proposed
debug logger state of `false`. Copy it to a private `0600` file and run these
commands from the repository root:

```sh
umask 077
cp cli/examples/cncf/dragonfly-input.json dragonfly-input.json
chmod 600 dragonfly-input.json
input_digest="$(shasum -a 256 dragonfly-input.json | awk '{print $1}')"
set +e
./prufyx check cncf --project dragonfly \
  --input dragonfly-input.json --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json > dragonfly-report.json
status=$?
set -e
chmod 600 dragonfly-report.json
printf 'Dragonfly exit: %s\n' "$status"
```

When the source review is current, this declaration produces the scoped
manager `BLOCKED` claim and exit `10`; the scheduler sibling has a separate
surface and remains `UNKNOWN` for this input. The aggregate whole-upgrade
assessment remains `UNKNOWN`. A proposed `debug_logging_enabled=true` passes
the narrow matching predicate; a custom distribution or a missing, false, conflicting, or
unresolved retention declaration remains `UNKNOWN`. Current verbose intent
does not infer proposed intent. These are operator declarations, not Dragonfly
argv or configuration parsing, default resolution, logger output, or runtime
evidence.

## Check the Falco 0.42 transition

[`falco-042-input.json`](falco-042-input.json) declares the exact `0.40.0` to
`0.42.0` transition, the official Falco command surface, and retained removed
options. Copy it to a private file before evaluation. The expected scoped claim
is `BLOCKED` (exit `10`); the whole-upgrade assessment remains `UNKNOWN`.
This is a synthetic operator declaration, with no argv parser or runtime proof.
Run the commands from the repository root with `prufyx` on your PATH.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/falco-042-input.json "${example_dir}/falco-input.json"
chmod 600 "${example_dir}/falco-input.json"
prufyx check cncf --project falco --input "${example_dir}/falco-input.json" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json
```

## Check a Cortex declaration

[`cortex-input.json`](cortex-input.json) is a synthetic declaration for the
reviewed Cortex `1.17.2` to `1.21.1` transition. It declares the official
upstream `cortex` command and presence of the removed
`querier.at-modifier-enabled` option. Copy it to a unique private directory
before checking:

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/cortex-input.json "${example_dir}/cortex-input.json"
input_digest="$(shasum -a 256 "${example_dir}/cortex-input.json" | awk '{print $1}')"
set +e
./prufyx check cncf --project cortex \
  --input "${example_dir}/cortex-input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json \
  > "${example_dir}/cortex-report.json"
status=$?
set -e
chmod 600 "${example_dir}/cortex-input.json" "${example_dir}/cortex-report.json"
printf 'Cortex exit: %s\n' "$status"
```

A current source review produces a scoped `BLOCKED` claim and exit `10`; the
whole-upgrade assessment remains `UNKNOWN`. The old option was already
nonfunctional, so this checks only declared input compatibility. It does not
parse argv or establish query behavior or runtime state. A definite `false`
declaration is a scoped `PASS` only when both guards match. Missing, custom,
conflicting, unsupported, other-surface, and outside-pair inputs remain
`UNKNOWN`.

## Check a Strimzi declaration

[`strimzi-input.json`](strimzi-input.json) is a synthetic declaration for the
reviewed Strimzi `0.51.0` to `1.0.0` Kafka custom-resource transition. It
declares a `kind: Kafka` resource using `kafka.strimzi.io/v1beta2` and explicit
intent to admit it against the official target Kafka CRD surface:

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/strimzi-input.json "${example_dir}/strimzi-input.json"
input_digest="$(shasum -a 256 "${example_dir}/strimzi-input.json" | awk '{print $1}')"
set +e
./prufyx check cncf --project strimzi \
  --input "${example_dir}/strimzi-input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json \
  > "${example_dir}/strimzi-report.json"
status=$?
set -e
chmod 600 "${example_dir}/strimzi-input.json" "${example_dir}/strimzi-report.json"
printf 'Strimzi exit: %s\n' "$status"
```

A current source review produces a scoped `BLOCKED` claim and exit `10`; the
whole-upgrade assessment remains `UNKNOWN`. The target-admission fact is a plan
declaration. It does not prove that the target CRD is installed, applied, or
used by an API server. Operator-image-only, retained-old-CRD, custom-target,
missing-intent, false-intent, KafkaTopic, KafkaUser, stored-object, conversion,
reconciliation, and runtime cases remain `UNKNOWN` or outside this rule. A
definite absence of v1beta2 is only a scoped `PASS`, not validation of a v1
resource.

## Check a Helm declaration

This example shows the local, disconnected `check cncf` input shape for one
synthetic Helm transition. It is an operator-declared source-constraint input,
not a customer configuration, a cluster snapshot, or proof that Helm was run.

The subject and fact below are deliberately synthetic but use the registered
fact shape:

- subject: `pkg:github/helm/helm`
- current endpoint: `3.14.4`
- proposed endpoint: `4.0.0`
- fact: `component.helm.post_renderer_mode`
- finite values: `executable_path` and `plugin_name`

Create a private input file (mode `0600`) with the following contents:

```json
{
  "schema": "prufyx.io/operator-declared-constraint-input/v1alpha1",
  "authority": "OPERATOR_DECLARED_MINIMIZED",
  "current": {
    "components": [
      {
        "component": "pkg:github/helm/helm",
        "version": "3.14.4",
        "facts": [
          {
            "id": "component.helm.post_renderer_mode",
            "state": "declared",
            "enumValue": "executable_path"
          }
        ]
      }
    ]
  },
  "proposed": {
    "components": [
      {
        "component": "pkg:github/helm/helm",
        "version": "4.0.0",
        "facts": [
          {
            "id": "component.helm.post_renderer_mode",
            "state": "declared",
            "enumValue": "plugin_name"
          }
        ]
      }
    ]
  }
}
```

For example, save it locally and run a replayable check with an explicit
whole-second UTC time:

```sh
umask 077
cat > helm-input.json <<'JSON'
{
  "schema": "prufyx.io/operator-declared-constraint-input/v1alpha1",
  "authority": "OPERATOR_DECLARED_MINIMIZED",
  "current": {"components": [{"component": "pkg:github/helm/helm", "version": "3.14.4", "facts": [{"id": "component.helm.post_renderer_mode", "state": "declared", "enumValue": "executable_path"}]}]},
  "proposed": {"components": [{"component": "pkg:github/helm/helm", "version": "4.0.0", "facts": [{"id": "component.helm.post_renderer_mode", "state": "declared", "enumValue": "plugin_name"}]}]}
}
JSON
chmod 600 helm-input.json
digest="$(shasum -a 256 helm-input.json | awk '{print $1}')"
prufyx check cncf --project helm --input helm-input.json \
  --input-digest "sha256:${digest}" \
  --now 2026-09-08T12:10:00Z --format json > helm-report.json
chmod 600 helm-report.json
```

With the embedded pack and timestamp shown above, this synthetic declaration
returns exit `0` and the selected Helm claim is `PASS`. Relevant report fields
still include an overall `"assessment":"UNKNOWN"`, because the claim is
scoped to the post-renderer argument form:

```json
{
  "assessment": "UNKNOWN",
  "check": {
    "claims": [
      {
        "ruleId": "helm.post-renderer-argument-form.4-0",
        "status": "PASS"
      }
    ]
  }
}
```

The input digest binds the exact admitted bytes. `--now` is supplied by the
caller and must be canonical UTC with whole-second precision; the command does
not read the system clock. To replay the exact report later, retain both files
as private `0600` files and run:

```sh
prufyx check cncf --project helm --input helm-input.json \
  --now 2026-09-08T12:10:00Z \
  --replay-report helm-report.json --format json
```

The command reads only local files and embedded rule data. It does not inspect
a cluster, collect runtime observations, call a model, download a database or
pack, upload data, or invoke Helm. A replay establishes byte-for-byte local
reproducibility for the supplied input, embedded pack, and timestamp; it does
not establish source freshness, non-revocation, or runtime behavior.

The selected source claims determine the process status: `0` means every
selected nonempty claim is `PASS`, `10` means at least one selected claim is
`BLOCKED`, and `11` means `UNKNOWN` or no generic rules. Invalid arguments or
file/input admission return `2`; an integrity failure returns `3`. The report
aggregate remains `UNKNOWN` in every case because this command evaluates
selected source predicates, not a whole upgrade. Missing, unsupported,
ambiguous, or outside-scope facts remain `UNKNOWN`; they are not treated as
false. A deprecated or retained no-op option is not a blocker without an
actual source predicate showing a violation.

Use the catalogue command to inspect the currently embedded rule selection:

```sh
prufyx catalog cncf --project helm --format json
```

The catalogue and embedded registry are versioned with the binary. Generic
packs are not downloaded or imported by this preview. Future signed data
updates require a separate reviewed capability and are unavailable here.

## Review an Argo CD inheritance change from one ConfigMap

[`proposed-argocd-cm.json`](proposed-argocd-cm.json) is a sanitized private
`v1` ConfigMap containing only the `argocd-cm` name and the explicit Argo CD
inheritance setting. It is an example input, not a live object, RBAC record, or
runtime observation. The adapter supports only the reviewed `2.14.0` to
`3.0.0` pair and requires an explicit access-intent declaration.

The operator path reads this file once, prepares its two minimized facts in
memory, computes the raw and prepared-input digests, and evaluates the existing
source constraint without persisting an intermediate input. Supply the decision
about inherited application update/delete permissions explicitly; it is not
inferred from the ConfigMap, RBAC, users, roles, or defaults.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/proposed-argocd-cm.json "${example_dir}/argocd-cm.json"
chmod 600 "${example_dir}/argocd-cm.json"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project argo-cd \
  --config-map "${example_dir}/argocd-cm.json" \
  --from 2.14.0 --to 3.0.0 \
  --requires-inherited-application-permissions true \
  --now "${review_time}" --format human
```

The explicit `--now` value is the existing evaluation and replay clock. Keep it
with the report to reproduce the same decision against the same embedded
knowledge; the command does not silently use the system clock. The output binds
the raw ConfigMap digest, minimized input digest, evaluation time, embedded
knowledge revision and pack digest. An optional `--config-map-digest` can pin an
unchanged file, but the edit-and-repeat workflow omits it because the digest
necessarily changes with the user-owned file.

The example's exact `true` setting and explicit `true` intent return scoped
`BLOCKED` with exit `10`. Edit that same local ConfigMap value to the exact string
`false` and repeat the same command for scoped `PASS` with exit `0`; both reports
keep aggregate `UNKNOWN`. Before editing, review the reported permission impact:
`false` restores v2 inheritance behavior, which can cause application-level
update/delete grants to apply to managed resources. Prufyx does not change the
ConfigMap or RBAC.

Omit the intent flag to receive `UNKNOWN` with the concrete permission question
and the exact flag to supply. Explicit `false` intent, a missing or malformed
setting, or another version pair also remains `UNKNOWN`; none is converted into
permission safety. The command prints the reviewed setting, declared intent,
pinned source and bounded next action, without printing the path, namespace, or
unrelated ConfigMap data.

The lower-level `prepare cncf` and canonical `check cncf --input` commands remain
available for integrations that deliberately retain a minimized input or replay
an exact JSON report. Run this advanced form from the repository root after
building `prufyx` and place all generated files in a private directory:

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/proposed-argocd-cm.json "${example_dir}/argocd-cm.json"
chmod 600 "${example_dir}/argocd-cm.json"
source_digest="$(shasum -a 256 "${example_dir}/argocd-cm.json" | awk '{print $1}')"
set +e
prufyx prepare cncf --project argo-cd \
  --input "${example_dir}/argocd-cm.json" --from 2.14.0 --to 3.0.0 \
  --requires-inherited-application-permissions true \
  --input-digest "sha256:${source_digest}" --format input \
  > "${example_dir}/argo-input.json"
prepare_exit=$?
set -e
chmod 600 "${example_dir}/argo-input.json"
printf 'Argo CD preparation exit: %s\n' "$prepare_exit"
```

The explicit `true` setting together with the explicit `true` access intent
prepares successfully with exit `0`. Check the minimized declaration locally:

```sh
input_digest="$(shasum -a 256 "${example_dir}/argo-input.json" | awk '{print $1}')"
set +e
prufyx check cncf --project argo-cd \
  --input "${example_dir}/argo-input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json \
  > "${example_dir}/argo-report.json"
check_exit=$?
set -e
chmod 600 "${example_dir}/argo-report.json"
printf 'Argo CD check exit: %s\n' "$check_exit"
```

This advanced form has the same scoped outcomes and limitations. The adapter
does not inspect RBAC, infer defaults, call a cluster, validate a deployment, or
prove application permissions or runtime behavior. Review the source-linked
claim in the report before treating either scoped result as actionable.

## Review a Knative Serving startup probe from one Service

[`proposed-knative-serving-service.json`](proposed-knative-serving-service.json)
is a synthetic `serving.knative.dev/v1` Service for the exact Knative Serving
`1.22.0` to `1.23.0` transition. Replace its image and other fields with your
user-owned proposed Service, keeping the file private. The supported first slice
requires exactly one user container, one explicit `http1` or `h2c` container
port, and one HTTP startup probe using an explicit `http1` or `h2c` named port.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/proposed-knative-serving-service.json "${example_dir}/service.json"
chmod 600 "${example_dir}/service.json"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project knative \
  --service "${example_dir}/service.json" \
  --from 1.22.0 --to 1.23.0 \
  --now "${review_time}" --format human
```

The example's declared container port name is `http1` while
`startupProbe.httpGet.port` is `h2c`, so the target named-port constraint is
scoped `BLOCKED` with exit `10`. Change only the probe port to `http1` in the
same local file and repeat the same command for scoped `PASS` with exit `0`.
Both reports retain aggregate `UNKNOWN`. The command reads the Service once,
builds its minimized fact in memory, and records raw-input, prepared-input,
time, knowledge, and pinned-source identities without writing an intermediate
file or editing the Service. `--service-digest` is an optional unchanged-file
assertion; omit it for the edit-and-repeat workflow.

Missing probes, numeric ports, other probe handlers, multiple containers or
ports, unsupported resource shapes, and other version pairs remain `UNKNOWN`.
This check evaluates only the Knative Serving v1.23 target named HTTP startup-
probe port constraint. It does not reproduce v1.22 admission, validate the rest
of the Service, call a cluster, or prove API-server behavior, startup, traffic,
runtime behavior, or whole-upgrade safety. The report prints the two relevant
field paths, source span, and bounded fix without printing the local path,
metadata, image, unrelated configuration, or raw Service content.

The same raw Service route can use an explicitly selected, verified local CNCF
knowledge store. Import the signed package with `db import --profile cncf` and
an independently trusted bootstrap root, then replace `--now` with the store:

```sh
prufyx check cncf --project knative \
  --service "${example_dir}/service.json" \
  --from VERSION --to VERSION \
  --knowledge-db PRIVATE_CNCF_STORE --format human
```

Current external checks use the verifier's clock. Revision, bundle, and trust-
receipt pins are optional assertions for a current selection. The selected
store is authoritative: a missing exact rule produces `UNKNOWN` and never
falls back to the embedded `1.22.0` to `1.23.0` rule. Imported knowledge does
not change the binary, raw parser, fact meaning, or supported Service shape.

For historical replay, retain the exact JSON report, raw Service, and its
digest. Repeat with `--replay-report`, `--service-digest`, and all three exact
knowledge pins. A replay `MATCH` reproduces the minimized prepared observation,
selected knowledge, and recorded time. The report's prepared-input digest does
not bind unrelated raw Service metadata or the original raw bytes, so the raw
Service digest remains separate operator evidence. Neither current evaluation
nor replay stores the raw Service in the knowledge database.

## Review an in-toto-run key argument plan

[`in-toto-run/argv.json`](in-toto-run/argv.json) is a synthetic planned argv
array for the Python CLI `2.2.0` to `3.0.0` transition. Copy your own tokenized
argv to a private mode `0600` JSON string array. The checker accepts only the
literal `in-toto-run`, `-n` or `--step-name` with one value, exactly one
`-k`/`--key` or `--signing-key` with one value, the first valid `--` boundary,
and a nonempty wrapped command. Every token after that boundary is opaque.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/in-toto-run/argv.json "${example_dir}/argv.json"
chmod 600 "${example_dir}/argv.json"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project in-toto \
  --in-toto-run-argv "${example_dir}/argv.json" \
  --from 2.2.0 --to 3.0.0 --now "${review_time}" --format human
```

The pre-boundary `--key` yields scoped `BLOCKED` and exit `10`. After separately
validating or converting the private key to a target-supported standard
PEM/PKCS8 format and checking password handling, edit only that option spelling
to `--signing-key` and repeat the same command for scoped `PASS` and exit `0`.
That PASS clears only this removed-option predicate. Prufyx never opens the key
or executes the command; key loading, signing, wrapped-command behavior, trust,
process/version provenance, and whole-upgrade safety remain `UNKNOWN`. A
missing, reordered, unknown, GPG, equals-form, ambiguous or otherwise
unsupported prefix remains `UNKNOWN`. Tokens such as `--key`, `--signing-key`,
and further `--` after the first valid boundary remain wrapped-command data.

An explicit `--knowledge-db` selects verified local CNCF knowledge and is
authoritative with no embedded fallback. Current evaluation uses verifier time.
Historical replay requires `--replay-report`, `--in-toto-run-argv-digest`, and
all three knowledge pins. The saved report binds the minimized key-option fact,
knowledge and recorded time rather than original argv bytes, so retain the raw
argv and digest separately. Neither current checking nor replay stores the argv
in the knowledge database.

## Review a KFP Python SDK component-authoring change

[`kubeflow-kfp/component.py`](kubeflow-kfp/component.py) is a synthetic Python
source file using the legacy bare `create_component_from_func` decorator. Copy
your own planned source to a private `0600` file. Prufyx reads it with a Go
lexical parser; it never imports, executes, or requires Python.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/kubeflow-kfp/component.py "${example_dir}/component.py"
chmod 600 "${example_dir}/component.py"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project kubeflow \
  --python-source "${example_dir}/component.py" \
  --from 1.8.22 --to 2.0.0 \
  --now "${review_time}" --format human
```

The legacy import and bare decorator produce scoped `BLOCKED` with exit `10`.
Edit the same file to use unaliased `from kfp import dsl` and bare
`@dsl.component`, then repeat the same command for scoped `PASS` with exit `0`.
That action addresses only the removed public authoring API. Validate component
inputs, outputs, dependencies, base image, compilation, backend and runtime
separately; aggregate assessment remains `UNKNOWN`.

The Go lexical adapter recognizes only one ordinary synchronous function with
one of those two exact unaliased bare decorator forms, a header ending at `:`,
and an indented `return ...` or `pass` body. Aliases, rebinding, decorator
calls, dynamic or conditional imports, mixed or multiple candidates, async
functions, f-strings, escapes, inline suites, nested blocks, and other valid
but unsupported source forms remain `UNKNOWN`. Malformed lexical syntax stops
without a semantic result.

An explicitly selected verified local CNCF store is authoritative with no
embedded fallback. Current external checking omits `--now`. Historical replay
requires the saved JSON report, `--python-source-digest`, and all three exact
knowledge pins. The report binds the minimized enum observation rather than
raw source bytes, so retain the private source and digest separately when byte
identity matters. Neither checking nor replay stores raw source in the database.

## Review a TUF Updater source call

[`tuf-updater/updater.py`](tuf-updater/updater.py) is a synthetic Python source
file with one direct `tuf.ngclient.Updater` call. Copy your own planned source
to a private file. Prufyx reads it with a Go lexical parser and does not import,
execute, or require Python.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/tuf-updater/updater.py "${example_dir}/updater.py"
chmod 600 "${example_dir}/updater.py"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project the-update-framework-tuf \
  --python-source "${example_dir}/updater.py" \
  --from 6.0.0 --to 7.0.0 \
  --now "${review_time}" --format human
```

The example omits `bootstrap`, so the exact Updater `6.0.0` to `7.0.0` rule
returns scoped `BLOCKED` with exit `10`. Add an explicit keyword appropriate to
your application, such as `bootstrap=trusted_root_bytes`, and repeat the same
command for scoped `PASS` with exit `0`. An explicit `bootstrap=None` clears
only this keyword-presence predicate and is appropriate only when the cached
root trust path is intended. Prufyx never chooses or adds a bootstrap value.

The adapter accepts one conservatively bound direct call using either unaliased
`from tuf.ngclient import Updater` or `import tuf.ngclient`. Aliases, rebinding,
multiple or dynamic calls, star arguments, the legacy seventh positional
argument, missing shared required arguments, unknown or duplicate keywords,
and other call shapes remain `UNKNOWN`. The output identifies the blocking
category without printing source, values, paths, URLs, or raw code.

The Go lexical parser admits only the documented direct import and one
top-level direct call; conditional, nested, dynamic, alias, rebinding,
prefixed or escaped strings, and other unsupported source forms remain
`UNKNOWN`. A scoped `PASS` does not
validate the bootstrap value, cached or supplied root, metadata, updates,
network behavior, installed python-tuf package, process provenance, or whole-
upgrade safety. Aggregate assessment remains `UNKNOWN`.

An explicitly selected verified local CNCF store is authoritative and never
falls back to embedded rules. Current selection uses verifier time and omits
`--now`. Historical replay requires the saved JSON report,
`--python-source-digest`, and exact revision, bundle, and trust-receipt pins.
The report binds the minimized keyword observation; retain the private source
and raw digest separately when original byte identity matters.

## Review a CubeFS MetaNode planned-upgrade guard

[`cubefs-metanode/metanode.json`](cubefs-metanode/metanode.json) is a synthetic
native-shaped MetaNode JSON config for the exact CubeFS `3.2.1` to `3.3.2`
planned MetaNode upgrade phase. The checker reads only the root `role` and
`raftSyncSnapFormatVersion`; unrelated ordinary fields stay local and are not
included in the minimized input or report.

Run this from the repository root with `prufyx` on `PATH`:

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/cubefs-metanode/metanode.json "${example_dir}/metanode.json"
chmod 600 "${example_dir}/metanode.json"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
prufyx check cncf --project cubefs \
  --metanode-config "${example_dir}/metanode.json" \
  --from 3.2.1 --to 3.3.2 --phase metanode-upgrade \
  --now "$now" --format human
first_exit=$?
set -e
printf 'CubeFS first check exit: %s\n' "$first_exit"
```

An absent `raftSyncSnapFormatVersion` produces a scoped `BLOCKED` result and
exit `10` because target source defines default `1`. An explicit numeric `1`
is also blocked, but is reported separately as an observed value in the
supplied planned config. Set the root field to numeric `0` and repeat the same
command for a scoped `PASS` and exit `0`. Missing or other phase, wrong role or
version pair, ambiguous keys, and unsupported setting types or values remain
`UNKNOWN` with exit `11`.

This is one operator-supplied planned MetaNode config, not observed effective
cluster state. It does not verify peer versions, rollout completion, restarts,
client ordering, mounts, runtime behavior, or data safety. Upstream's later
remove-setting, restart-all-MetaNodes, and client-last steps remain unverified
follow-up requirements. Prufyx does not modify the file or contact CubeFS.
With selected verified local knowledge, omit `--now`; historical replay also
requires `--replay-report`, `--metanode-config-digest`, and all three knowledge
pins. The saved report binds the minimized phase and guard facts, so retain the
raw config and its digest separately when raw-byte identity matters.

## Review a CRI-O ArtifactStore named-reference plan

[`crio-image-status-request/image-status-request.json`](crio-image-status-request/image-status-request.json)
is a synthetic native CRI `ImageStatusRequest` for an exact CRI-O `1.34.0` to
`1.35.0` ArtifactStore named-reference-resolution plan. Copy your own planned
request to a private regular file; the checker reads only root `image.image`
and the caller-declared operation.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/crio-image-status-request/image-status-request.json \
  "${example_dir}/request.json"
chmod 600 "${example_dir}/request.json"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
prufyx check cncf --project cri-o \
  --image-status-request "${example_dir}/request.json" \
  --artifact-operation named-reference-resolution \
  --from 1.34.0 --to 1.35.0 \
  --now "${review_time}" --format human
first_exit=$?
set -e
printf 'CRI-O first check exit: %s\n' "$first_exit"
```

The example's short explicit-tag reference produces scoped `BLOCKED` and exit
`10`. Change only `widget:v1` to a fully-qualified reference such as
`registry.example/repository/widget:v1`, then repeat the same command for
scoped `PASS` and exit `0`. That pass clears only the target ArtifactStore
short-name guard. It does not resolve aliases, infer a registry, inspect store
contents, prove request routing, contact a registry, or validate ordinary
images, access, pulls, removal, runtime behavior or whole-upgrade safety.

The admitted subset requires an explicit tag. Short names use conservative
repository components and a 237-byte name bound. Fully-qualified names use a
lowercase dotted DNS host, conservative repository components and a 255-byte
name bound. Digests, ports, IPs, `localhost`, transport prefixes, missing tags,
unsupported separators, ambiguous relevant JSON keys, missing or other
operation intent, and other version pairs remain `UNKNOWN`. Unrelated JSON
fields remain local and are omitted from the minimized report.

With an explicitly selected verified local CNCF store, omit `--now`; the store
is authoritative and an absent rule stays `UNKNOWN` without embedded fallback.
Historical replay requires the saved JSON report,
`--image-status-request-digest`, and all three knowledge pins. The report binds
the minimized operation and reference classification rather than original
request bytes, so retain the private request and raw digest separately.

## Review a Buildpacks Lifecycle Platform API plan

The two files in [`buildpacks/`](buildpacks/) are retained, config-shaped OCI
JSON examples for Lifecycle `0.16.5` and `0.17.7`. Copy your own current and
proposed Lifecycle config JSON to private files instead of treating these
examples or a locally computed digest as registry provenance. The supported
first slice reads only three supplied labels: the exact Lifecycle version, the
Lifecycle API declarations, and the optional builder-metadata Lifecycle
version consistency declaration. Other image metadata is omitted from output.

Review a plan that asks Lifecycle `0.17.7` to use Platform API `0.13`:

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/buildpacks/current-lifecycle-config.json "${example_dir}/current.json"
cp cli/examples/cncf/buildpacks/proposed-lifecycle-config.json "${example_dir}/proposed.json"
chmod 600 "${example_dir}/current.json" "${example_dir}/proposed.json"
review_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project buildpacks \
  --current-lifecycle-config "${example_dir}/current.json" \
  --proposed-lifecycle-config "${example_dir}/proposed.json" \
  --from 0.16.5 --to 0.17.7 \
  --current-platform-api 0.11 --proposed-platform-api 0.13 \
  --now "${review_time}" --format human
```

The supplied target metadata does not declare Platform API `0.13`, so the
exact plan is scoped `BLOCKED` with exit `10`. If the platform implementation
can use `0.12`, change only `--proposed-platform-api 0.13` to `0.12` and repeat
the command for scoped `PASS` with exit `0`. Otherwise choose a Lifecycle that
declares the required API. Either result keeps aggregate `UNKNOWN`: this check
does not establish Platform API negotiation, deprecation-mode behavior,
building, runtime behavior, registry provenance, or whole-upgrade safety.
The pinned Lifecycle `0.19.6` source establishes only that Platform API `0.13`
is a real later upstream API. It is not the proposed product version, does not
add `0.19.6` coverage, and is not evidence that `0.17.7` supports that API.

The command reads both files once, verifies optional
`--current-lifecycle-config-digest` and `--proposed-lifecycle-config-digest`
pins, minimizes the selected API values and support observations in memory,
then uses the existing CNCF evaluator. A raw digest proves only which supplied
bytes were read. The JSON report binds the minimized facts and knowledge, not
the original OCI bytes. Values outside the first supported `0.11`, `0.12`, and
`0.13` API domain, malformed or ambiguous label JSON, inconsistent Lifecycle
identity, deprecated APIs absent from the supported set, and other version
pairs remain `UNKNOWN` or are rejected as malformed input. This is a strict
projection of caller-supplied config-shaped JSON, not a general OCI validator.

The same route accepts `--knowledge-db PRIVATE_CNCF_STORE` after a package is
verified and imported with the existing CNCF knowledge workflow. Current
selection uses verifier time and treats the selected revision as authoritative;
missing rules return `UNKNOWN` with no embedded fallback. Historical replay
requires `--replay-report`, both raw-config digest pins, and exact revision,
bundle, and trust-receipt pins. It reproduces the saved minimized plan and
recorded knowledge/time even if unrelated raw metadata changed, so retain both
original raw files and their digests separately. Current evaluation may update
the selected store's anti-rollback clock floor; neither evaluation nor replay
stores the supplied raw configs in the knowledge bundle.

## Prepare a Karmada blocker witness

[`proposed-karmada-propagation-policy.json`](proposed-karmada-propagation-policy.json)
is a synthetic private `PropagationPolicy` with a legacy application-failover
`purgeMode`. The adapter reads one exact policy resource locally; it can witness
a legacy blocker, but cannot establish that every rendered policy is legacy-free. Run these commands from the repository root with `prufyx` on your `PATH`.

```sh
umask 077
mkdir -p .private-karmada-example
cp cli/examples/cncf/proposed-karmada-propagation-policy.json .private-karmada-example/policy.json
chmod 600 .private-karmada-example/policy.json
source_digest="$(shasum -a 256 .private-karmada-example/policy.json | awk '{print $1}')"
prufyx prepare cncf --project karmada --input .private-karmada-example/policy.json \
  --from 1.18.3 --to 1.19.0 --distribution official_upstream \
  --target-policy-crd-admission required --input-digest "sha256:${source_digest}" \
  --format input > .private-karmada-example/karmada-input.json
karmada_prepare_exit=$?
chmod 600 .private-karmada-example/karmada-input.json
printf 'Karmada preparation exit: %s\n' "$karmada_prepare_exit"
```

The synthetic legacy value produces a prepared blocker witness. `Directly`,
`Gracefully`, `Never`, missing or unresolved path values produce `UNKNOWN`; this
single-resource adapter never creates a scoped PASS. It does not validate a CRD,
call an API server, inspect stored objects or evaluate runtime behavior.

## Check a Karmada declaration

[`karmada-input.json`](karmada-input.json) is a synthetic declaration for the
reviewed Karmada `1.18.3` to `1.19.0` policy-CRD transition. It declares the
official upstream distribution, application-failover policy surface, explicit
target-CRD admission intent, and presence of a removed legacy purge-mode value.

Run this from the repository root after placing `prufyx` on your `PATH`.

```sh
umask 077
example_dir="$(mktemp -d)"
cp cli/examples/cncf/karmada-input.json "${example_dir}/karmada-input.json"
input_digest="$(shasum -a 256 "${example_dir}/karmada-input.json" | awk '{print $1}')"
set +e
prufyx check cncf --project karmada \
  --input "${example_dir}/karmada-input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json \
  > "${example_dir}/karmada-report.json"
karmada_exit=$?
set -e
chmod 600 "${example_dir}/karmada-input.json" "${example_dir}/karmada-report.json"
printf 'Karmada exit: %s\n' "$karmada_exit"
```

The supplied declaration produces a scoped `BLOCKED` claim and exit `10`; the
whole-upgrade assessment remains `UNKNOWN`. A definite absence is a scoped
`PASS` only when official distribution, application-failover policy surface,
and target-CRD admission intent all match. This does not parse resources or
prove a CRD installation, API-server validation, stored-object migration,
reconciliation, or failover runtime.

### Tekton metrics migration

`tekton-input.json` is a complete effective proposed `config-observability`
declaration for Tekton Pipelines `1.9.0` → `1.10.0`. It binds the official
upstream distribution to `apiVersion: v1`, `kind: ConfigMap`, name
`config-observability`, and the proposed system namespace, and declares the
Prometheus retention intent plus `metrics-protocol: prometheus`.

Copy it to a private file before checking. The file must remain mode `0600`:

```sh
umask 077
cp cli/examples/cncf/tekton-input.json tekton-input.json
chmod 600 tekton-input.json
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project tekton --input tekton-input.json \
  --now "$now" --format json > tekton-report.json
chmod 600 tekton-report.json
```

The `proposed_metrics_protocol_prometheus` fact is `true` only for one exact
functional `metrics-protocol: prometheus` value in the complete effective data.
`false` means definitive absence of that key. A present non-Prometheus, empty,
duplicate, ambiguous, or unresolved value must be represented as `unsupported`
or `conflict`; it must never be represented as `false`. The old
`metrics.backend-destination` key is diagnostic only and does not drive the
verdict. The check remains a scoped declaration result; composition, endpoint
reachability, scraping, and runtime behavior are unverified.

## Check a Cilium target CRD declaration

[`cilium-input.json`](cilium-input.json) is a canonical declaration for the
narrowly scoped Cilium `1.18.13` to `1.19.7` target-schema rule. The
`prepare cncf --project cilium` adapter can derive its existing nonempty-requires
fact from one private CNP, CCNP, or bounded List JSON for this exact pair as
well as `1.18.6` to `1.19.0`. Other Cilium pairs remain unsupported. A
project-level prepare command does not imply that every listed Cilium rule pair
is prepared.
The operator must inspect the complete relevant CiliumNetworkPolicy and
CiliumClusterwideNetworkPolicy set. `boolValue: false` means a definite absence
of every nonempty `fromRequires` and `toRequires` array in that complete set;
it does not mean that the operator omitted the inspection. A partial, unresolved, or ambiguous declaration cannot be declared false and remains
unsupported or unknown as applicable.

To derive the declaration from a private local policy document instead of
copying the canonical example, first keep that document as a regular mode
`0600` file, then run:

```sh
umask 077
source_digest="$(shasum -a 256 private-cilium-policies.json | awk '{print $1}')"
set +e
prufyx prepare cncf --project cilium \
  --input private-cilium-policies.json --from 1.18.13 --to 1.19.7 \
  --input-digest "sha256:${source_digest}" \
  --format input > cilium-input.json
prepare_exit=$?
set -e
chmod 600 cilium-input.json
printf 'Cilium preparation exit: %s\n' "$prepare_exit"
```

Add `--complete-cnp-ccnp-set true` only when that local document represents the
complete relevant set. Leave the flag out when completeness is unknown; a nonempty
requires witness can still produce a scoped blocker, while a clean incomplete
or partial set remains `UNKNOWN`.

Alternatively, copy the canonical example to a private regular file. Keep a
prepared or copied declaration mode `0600`, then run the check from the
repository root:

```sh
umask 077
cp cli/examples/cncf/cilium-input.json cilium-input.json
chmod 600 cilium-input.json
input_digest="$(shasum -a 256 cilium-input.json | awk '{print $1}')"
set +e
./prufyx check cncf --project cilium \
  --input cilium-input.json --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json > cilium-report.json
status=$?
set -e
chmod 600 cilium-report.json
printf 'Cilium check exit: %s\\n' "$status"
```

This complete-set absence declaration returns the scoped Cilium target-schema
`PASS` with exit `0`; a true declaration for any nonempty relevant array is
scoped `BLOCKED` with exit `10`. Missing, partial, unsupported, or ambiguous
operator facts and wrong version pairs remain `UNKNOWN`; malformed input keeps
the existing invalid-input behavior. The rule records only that the pinned
v1.19.7 CNP and CCNP CRD schemas set the relevant array `maxItems` to `0`. It
does not establish historical support removal, API-server admission, pruning,
startup, traffic, or whole-upgrade safety. The aggregate assessment remains
`UNKNOWN`.

## Check Prometheus 2.55.1 to 3.14.0 configuration declarations

[`prometheus-2-55-1-to-3-14-0.json`](prometheus-2-55-1-to-3-14-0.json) is a
synthetic operator declaration for two independent target configuration
predicates. It includes both facts so the canonical `check cncf` route can
select both reviewed rules: `api_version: v1` for the selected Alertmanager
mapping and the old `scrape_classic_histograms` key for the selected scrape
configuration.

Run this from the repository root after placing `prufyx` on your `PATH`:

```sh
set -eu
umask 077
example_dir="$(mktemp -d)"
trap 'rm -rf "$example_dir"' EXIT
cp cli/examples/cncf/prometheus-2-55-1-to-3-14-0.json "$example_dir/input.json"
chmod 600 "$example_dir/input.json"
input_digest="$(shasum -a 256 "$example_dir/input.json" | awk '{print $1}')"
set +e
prufyx check cncf --project prometheus --input "$example_dir/input.json" \
  --input-digest "sha256:${input_digest}" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json \
  > "$example_dir/report.json"
status=$?
set -e
chmod 600 "$example_dir/report.json"
printf 'Prometheus scoped check exit: %s\n' "$status"
```

The supplied declaration produces two scoped `BLOCKED` claims and exit `10`.
To test the fixed declaration, change both proposed enum values to
`v2` and `always_scrape_classic_histograms`; both scoped predicates can then
pass, while the whole-upgrade assessment remains `UNKNOWN`. Missing or
unsupported facts and a different version pair remain `UNKNOWN`. These are
operator-declared configuration facts; the check does not parse a live
Prometheus configuration, inspect an image, validate Alertmanager reachability
or delivery, or establish complete 2.x to 3.x upgrade safety.
