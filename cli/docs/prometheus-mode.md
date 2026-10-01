# Prometheus Agent mode preservation

The Prometheus mode check answers one bounded question:

> Does an exact proposed Prometheus `3.1.0` declaration preserve the current
> declared Agent or Server mode from Prometheus `2.55.1`?

The scoped claim is `PASS`, `ATTENTION`, or `UNKNOWN`. The aggregate always
remains `UNKNOWN`. The named `check prometheus-mode` command exits `0` for
scoped `PASS` and `11` for `ATTENTION` or `UNKNOWN`. The legacy
`community-preview validate-prometheus-mode` command preserves aggregate exit
`11` for every completed assessment, including a scoped `PASS`. The legacy
route also preserves exit `3` for proposed-file admission failures. The new
named check distinguishes invalid or unsafe input (`2`) from a digest mismatch
(`3`).

## First run: no cluster

From the repository root, build with Go 1.26.8 and run the embedded demo:

```sh
(cd cli && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community)
set +e
./prufyx check prometheus-mode --demo
code=$?
set -e
[ "$code" -eq 11 ]
```

The demonstration checks three embedded, digest-pinned synthetic vectors through
the actual proposed-manifest parser and claim reducer: Agent → Agent is scoped
`PASS`, Agent → Server is `ATTENTION`, and a wrapper command is `UNKNOWN`.
Every case keeps aggregate `UNKNOWN`; the demonstration exits `11`.

For the unchanged machine-readable alpha.3 demonstration envelope:

```sh
set +e
./prufyx community-preview demo-prometheus-mode >demo.json
code=$?
set -e
[ "$code" -eq 11 ]
cat demo.json
```

`demo-prometheus-mode` takes no flags, files, time, credentials, or cluster
context. Its report kind is `PrometheusModeSyntheticDemonstration`, its status
is `SYNTHETIC_DEMONSTRATION`, and `truth.actualObservationUsed` is `false`.
The sample current fact is explicitly
`SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT`; it never becomes a verified current
artifact. The real assessment path rejects synthetic current evidence.

## Interpret the scoped result

- `PASS`: exact declared current and proposed modes match.
- `ATTENTION`: both modes are exact and the declaration changes mode.
- `UNKNOWN`: admitted current evidence is missing, stale, incomplete, or
  unsupported, or the proposed identity/entrypoint/argument grammar cannot be
  resolved within this slice. Synthetic current evidence is rejected as an
  integrity error; it does not become a scoped result.

`PASS` does not mean `SAFE`. The result does not prove process startup, applied
runtime mode, data safety, remote-write behavior, rollback safety, or
whole-upgrade compatibility. Those omissions remain explicit in every report.

## Real read-only observation

Real assessment is opt-in and separate from the synthetic demonstration. This
collection step invokes local `kubectl` against the context you name. It reads
the already disclosed component-configuration workload surfaces and adds no
Kubernetes verb or resource beyond the v2 component profile. A kubeconfig may
invoke credential plugins; the acknowledgement flag is required. The collector
requires the native `prufyx-collector` executable and caller-trusted `kubectl`;
no Python, jq, or shell projection runtime participates.

Review the [collector request and data scope](local-collection.md)
before running it. Then collect the producer-v3 profile into a new private
directory:

```sh
mkdir -m 700 /absolute/private/prometheus-observation
cli/bin/prufyx-collector collect \
  /absolute/private/prometheus-observation \
  --kubeconfig /absolute/private/kubeconfig \
  --acknowledge-kubeconfig-exec-risk \
  --include-component-configuration \
  --component-configuration-profile v3 \
  my-context

observation_root="/absolute/private/prometheus-observation/<capture-directory>"
# Copy generatedAt from the collector's JSON index before evaluating.
captured_at="<index-generatedAt>"
evaluation_now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

The v3 producer must observe one unambiguous Prometheus `server` controller at
`2.55.1`, with both eligible Deployment and StatefulSet reads completed. It
pairs these predicates on the same source binding:

- `component.prometheus.agent_mode`;
- `component.prometheus.image_digest`.

The evidence class is `declared_container_context_v1`. The image predicate
must bind the reviewed Linux `arm64/v8` manifest
`sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad`.
Older producer profiles, tag-only or index-only identity, conflicting
controllers, failed workload reads, and synthetic evidence cannot supply an
exact current fact.

## Assess a proposed manifest

Save one `apps/v1` `Deployment` or `StatefulSet` as a private JSON file. This
Agent-mode example uses the reviewed Prometheus `3.1.0` Linux `arm64/v8`
platform manifest:

```json
{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "prometheus",
          "image": "prom/prometheus:v3.1.0@sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2",
          "command": ["/bin/prometheus"],
          "args": ["--config.file=/etc/prometheus/prometheus.yml", "--agent"]
        }]
      }
    }
  }
}
```

Pin the exact bytes and assess them locally:

```sh
chmod 600 /absolute/private/proposed-prometheus.json
proposed_digest="sha256:$(shasum -a 256 \
  /absolute/private/proposed-prometheus.json | awk '{print $1}')"

set +e
report="$(./prufyx community-preview validate-prometheus-mode \
  --observation-root "$observation_root" \
  --proposed-workload /absolute/private/proposed-prometheus.json \
  --proposed-digest "$proposed_digest" \
  --captured-at "$captured_at" \
  --now "$evaluation_now" \
  --max-age 2h)"
code=$?
set -e

[ "$code" -eq 11 ] || exit 1
printf '%s\n' "$report"
```

The command reads only the named local observation and proposed file. It does
not invoke `kubectl`, use ambient credentials, access the network, run a model,
sign or publish an artifact, or mutate anything.

## Exact proposed-input grammar

The manifest must contain exactly one regular Prometheus container and no
matching init container. Only `spec.template.spec.containers`,
`initContainers`, and candidate `image`, `command`, and `args` are parsed.
Names, arbitrary manifest fields, raw command lines, argument values, private
paths, and the input-file digest are not retained in the report.

The only admitted image spellings are `prom/prometheus` and
`docker.io/prom/prometheus`, with tag `v3.1.0` and platform-manifest digest
`sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2`.
The spelling `3.1.0` without `v`, tag-only or index-only references, other
versions, platforms, registries, and uppercase digest hex remain `UNKNOWN`.

An omitted command uses the reviewed image entrypoint. The only admitted
explicit command is the single token `/bin/prometheus`; an explicit empty
command or wrapper remains `UNKNOWN`. An omitted or empty argument list selects
the reviewed Server-mode default. One bare `--agent` selects Agent mode.
Legacy `--enable-feature=agent` is recognized but does not select Agent mode in
`3.1.0`.

Assigned or split boolean forms, `--no-agent`, duplicate `--agent`, argument
interpolation, `--`, ambiguous bare-flag arity, unbound positional arguments,
multiple matching containers, and matching init containers remain `UNKNOWN`.

The immutable [source contract](../internal/prometheusmode/source-contract-v1.json)
binds both image manifests, exact Prometheus source commits and spans, parser
grammar, and evidence role. The independent
[expected vectors](../internal/prometheusmode/expected-vectors-v1.json) cover
the admitted and unresolved branches. The Prometheus
[3.0 migration guide](https://github.com/prometheus/prometheus/blob/7086161a93b262aa0949dbf2aba15a5a7b13e0a3/docs/migration.md)
documents the upstream Agent-mode flag change.

## Current limits

Runtime/startup verification for this same exact transition is not
supported. It will remain unsupported until a reproducible public
test record ships with exact inputs, assertions, cleanup receipts, and stated
fidelity omissions. Data and remote-write safety, rollback, broader Prometheus
versions, other architectures, and whole-upgrade assessment are also
unimplemented in this alpha.
