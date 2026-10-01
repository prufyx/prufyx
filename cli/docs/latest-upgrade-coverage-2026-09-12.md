# Latest-target coverage selected on 2026-09-12

This development preview covers 115 exact project/version pairs across 23
projects. For each project, maintainers selected five earlier stable releases
and one exact target after reviewing immutable upstream release identities and
the source for the stated predicate. The selection is a curated sample; it does
not claim that every project has five minor release lines or that the listed
origins are the only supported releases upstream.

Each result evaluates only the exact endpoints and input described below.
Native input means the CLI parses a bounded part of a caller-supplied project
configuration or workload. Operator declaration means the CLI evaluates
explicit minimized facts and does not discover effective or runtime state.
Missing, custom, incomplete, ambiguous, or out-of-scope input stays `UNKNOWN`.
A `PASS` does not establish that an upgrade, cluster, workload, or data
migration is safe.

| Project | Five selected origins | Exact target | Input route | Scoped predicate |
| --- | --- | --- | --- | --- |
| Argo CD | `3.0.23`, `3.1.16`, `3.2.12`, `3.3.14`, `3.4.8` | `3.5.2` | Native selected pre-apply repository Secret plus operator-declared route guards | For one official Helm OCI repository declared to use plain HTTP, requires `insecureOCIForceHttp=true` without the conflicting direct-repository `insecure` flag; credential templates, dependency repositories, custom builds, connectivity, and Helm execution stay `UNKNOWN`. |
| Argo Workflows | `3.4.18`, `3.5.15`, `3.6.19`, `3.7.18`, `4.0.11` | `4.1.3` | Native selected exact-image Kubernetes Deployment container | Rejects the literal legacy `--basehref` option on the reviewed `argo server` argv; wrappers, other images or containers, incomplete argv, cluster state, and runtime stay `UNKNOWN`. |
| cert-manager | `1.16.5`, `1.17.4`, `1.18.6`, `1.19.6`, `1.20.3` | `1.21.2` | Native selected values JSON | Checks three curated values paths removed from the target chart schema; the rest of the values schema and runtime stay `UNKNOWN`. |
| Cortex | `1.16.1`, `1.17.2`, `1.18.1`, `1.19.1`, `1.20.1` | `1.21.1` | Native selected Kubernetes workload container | Rejects the removed `querier.at-modifier-enabled` argv option for the exact target image and admitted entrypoint; wrappers, custom images, query behavior, and runtime stay `UNKNOWN`. |
| Thanos | `0.37.2`, `0.38.0`, `0.39.2`, `0.40.1`, `0.41.0` | `0.42.4` | Native selected Kubernetes workload container | Rejects the reviewed removed Receive or Store argv flags; other commands, storage, Query behavior, and runtime stay `UNKNOWN`. |
| Prometheus | `3.9.1`, `3.10.0`, `3.11.3`, `3.12.0`, `3.13.3` | `3.14.0` | Native selected scrape or Alertmanager YAML | Checks two target constraints: Alertmanager `api_version` cannot be `v1`, and the selected classic-histogram key must use `always_scrape_classic_histograms`; other configuration and runtime stay `UNKNOWN`. |
| Fluentd | `1.14.6`, `1.15.3`, `1.16.11`, `1.17.1`, `1.18.0` | `1.19.3` | Operator-declared official package and Ruby version | Requires Ruby 3.2 or newer for the reviewed official target package; custom packages, plugins, and startup stay `UNKNOWN`. |
| Rook | `1.15.9`, `1.16.9`, `1.17.9`, `1.18.11`, `1.19.11` | `1.20.7` | Operator-declared Kubernetes version | Requires Kubernetes 1.31 or newer for the target; it does not infer an intermediate Rook hop or cover other upgrade requirements. |
| etcd | `3.2.32`, `3.3.27`, `3.4.45`, `3.5.33`, `3.6.14` | `3.7.1` | Bounded proposed direct-argv declaration | Rejects the finite reviewed removed experimental flags for all five pairs and blocks direct minor skips for the first four under the explicit one-minor-at-a-time policy; health, sequencing execution, and runtime stay `UNKNOWN`. |
| NATS | `2.8.4`, `2.9.25`, `2.10.29`, `2.11.17`, `2.12.15` | `2.14.6` | Native bounded JSON configuration subset | Rejects ASCII spaces in directly supplied server, cluster, and gateway names; includes, variables, other grammar, startup, and connectivity stay `UNKNOWN`. |
| Envoy | `1.34.14`, `1.35.13`, `1.36.10`, `1.37.6`, `1.38.4` | `1.39.1` | Operator-declared effective xDS API major | Rejects xDS v2 for the target transport surface; bootstrap resolution, resources, control-plane behavior, and rollout stay `UNKNOWN`. |
| CoreDNS | `1.9.4`, `1.10.1`, `1.11.4`, `1.12.4`, `1.13.2` | `1.14.7` | Operator-declared official distribution and Corefile result | Rejects a federation directive only for the reviewed official target plugin set; custom builds, unresolved Corefiles, and DNS behavior stay `UNKNOWN`. |
| OPA | `1.15.2`, `1.16.2`, `1.17.1`, `1.18.2`, `1.19.1` | `1.20.2` | Operator-declared producer and module facts | Requires the target producer's v0-compatible mode when declared v0 consumers remain and the relevant modules do not use the `rego.v1` import alternative; module contents and runtime stay `UNKNOWN`. |
| Kyverno | `1.14.5`, `1.15.3`, `1.16.4`, `1.17.2`, `1.18.2` | `1.19.1` | Native selected bare reports-controller invocation | Rejects `reportsChunkSize` on the reviewed official command surface; wrappers, other commands, provenance, and runtime stay `UNKNOWN`. |
| Flux | `2.4.0`, `2.5.1`, `2.6.4`, `2.7.5`, `2.8.8` | `2.9.5` | Native selected Kubernetes JSON resource or `v1/List` | Rejects source-confirmed removed beta APIs for the reviewed toolkit kinds; absence needs an explicit complete, non-paginated set, while stored versions and reconciliation stay `UNKNOWN`. |
| Cloud Custodian | `0.9.47`, `0.9.48`, `0.9.49`, `0.9.50`, `0.9.51` | `0.9.52` | Native selected policy JSON | Rejects `json-diff` for the selected IAM access-key resource because the target package does not register that combination; other resources, filters, and execution stay `UNKNOWN`. |
| OpenCost | `1.116.0`, `1.117.6`, `1.118.0`, `1.119.2`, `1.120.4` | `1.121.2` | Operator-declared complete cloud-cost source selection | Requires a declared-present cloud-integration source when enabled collection currently relies on provider-derived selection; file contents, APIs, and collection runtime stay `UNKNOWN`. |
| Jaeger | `2.15.1`, `2.16.0`, `2.17.0`, `2.18.0`, `2.19.0` | `2.20.0` | Bounded official-distribution and direct `--config` declaration | Requires one non-empty local config selection for declared non-memory storage; config content, backend, credentials, and runtime stay `UNKNOWN`. |
| Ceph | `15.2.17`, `16.2.15`, `17.2.9`, `18.2.8`, `19.2.6` | `20.2.4` | Native selected current OSD metadata JSON | Rejects FileStore for one explicitly selected numeric OSD whose metadata object is declared complete; other OSDs, cluster state, migration, and runtime stay `UNKNOWN`. |
| Fluent Bit | `3.2.10`, `4.0.14`, `4.1.2`, `4.2.8`, `5.0.10` | `5.1.2` | Native selected complete classic output configuration | Requires HTTP/2 only when the caller explicitly requires it; HTTP/1.1 is otherwise allowed, and other outputs and runtime stay `UNKNOWN`. |
| Grafana | `12.2.10`, `12.3.11`, `12.4.10`, `13.0.8`, `13.1.5` | `13.2.1` | Native complete, precedence-resolved `grafana.ini` | Rejects `[alerting] enabled=true` at target startup; alert data migration, plugins, and runtime stay `UNKNOWN`. |
| Kibana | `9.0.8`, `9.1.10`, `9.2.8`, `9.3.8`, `9.4.6` | `9.5.3` | Native complete, precedence-resolved `kibana.yml` | Requires the selected status settings for a declared need to expose full status to authenticated callers without monitor privilege; authorization, Elasticsearch, and runtime stay `UNKNOWN`. |
| Harbor | `2.10.3`, `2.11.2`, `2.12.4`, `2.13.5`, `2.14.4` | `2.15.2` | Native complete literal installer argv | Rejects `--with-chartmuseum` on the reviewed docker-compose installer surface; wrappers, other modes, installation, charts, databases, and runtime stay `UNKNOWN`. |

The Cortex `1.17.2` pair already existed in the embedded catalogue and is one
of the five selected pairs above. Jaeger also retains the earlier
`1.76.0` to `2.20.0` rule; that historical route is additional to this
115-pair selection.

Prometheus also has an additional canonical `2.55.1` to `3.14.0` depth
route over the existing Alertmanager API and classic-histogram facts. It is
outside the curated five-origin selection above and does not increase the
23-project or 115-pair counts. Missing declarations, custom or unresolved
configuration, runtime behavior, and whole-upgrade safety remain `UNKNOWN`.

Notation was source-qualified for this review wave, but no substantive target
predicate was established for an executable rule. It remains an explicit
qualification gap and is excluded from the project and pair counts.
