# CNCF source-constraint preview

The Community CLI exposes a local preview of narrowly scoped, source-linked compatibility constraints. The commands below use embedded rules. For optional signed local revisions, see the [CNCF knowledge database](cncf-knowledge-database.md); that path uses the verifier's actual clock and rejects `--now`.

These examples assume `prufyx` is on your `PATH`. After the README source build,
return to the repository root and run `export PATH="$PWD:$PATH"` in that shell;
this uses the locally built binary without a global installation.

```text
prufyx prepare cncf --project kyverno --input FILE --container NAME \
  --from 1.12.5 --to 1.13.0 [--distribution official_upstream|custom_build] \
  [--input-digest sha256:<digest>] \
  [--format human|json|input]
prufyx prepare cncf --project linkerd --input FILE \
  --from 2.13.7 --to 2.14.0 \
  [--distribution official_upstream|custom_build] \
  [--schema-validation required|disabled] \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx prepare cncf --project etcd --input FILE \
  --from 3.5.17 --to 3.6.0 \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx prepare cncf --project jaeger --input FILE \
  --from 1.76.0 --to 2.20.0 \
  [--non-memory-storage-required true|false] \
  [--official-jaeger-distribution true|false] \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx prepare cncf --project opencost --input FILE \
  --from 1.119.0 --to 1.120.0 \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx prepare cncf --project opencost --input FILE \
  --from 1.116.0|1.117.6|1.118.0|1.119.2|1.120.4 --to 1.121.2 \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx prepare cncf --project cloud-custodian --input FILE \
  --from 0.9.47|0.9.48|0.9.49|0.9.50|0.9.51 --to 0.9.52 \
  [--input-digest sha256:<digest>] [--format human|json|input]
prufyx catalog cncf [--priority] [--project SLUG] [--format human|json]
prufyx check cncf --project SLUG --input FILE --now RFC3339 \
  [--input-digest SHA256] [--replay-report FILE] [--format human|json]
```

`prepare cncf` is a pure local transformation for a project-specific private JSON
resource or declaration. Kyverno accepts a proposed Pod or `apps/v1` Deployment
JSON document. The source file must be a regular private file with mode `0600`; the command does not write it. Select the intended
container explicitly. A scoped result requires the explicit operator declaration
`--distribution official_upstream` and a literal bare `reports-controller`
command, with `command[1:]` followed by `args`. Image entrypoints,
`/reports-controller`, `kyverno`, `/kyverno`, shell or other wrappers,
environment expansion, unknown command forms, and `--` delimiters remain
`UNKNOWN`. The adapter derives false only when there are no argument tokens. It
derives true only from one or more `-reportsChunkSize` or `--reportsChunkSize`
options using attached or following signed-32-bit Go integer values, with no
other tokens. Invalid, overflowing, unrelated, positional, or ambiguous
arguments remain `UNKNOWN`; `--reportsChunkSize=false` is not a valid integer
and is therefore unresolved. Distribution is a declaration, never image
provenance.

The original `PrepareKyverno` Go signature supplies no distribution declaration
and therefore remains `UNKNOWN`. Older JSON declarations containing only the
flag-presence fact remain parseable, but lack the new distribution and execution
surface guards. Preserve older binaries and database stores to replay their
historical reports; this registry change does not promise cross-binary replay.

The adapter accepts only canonical numeric `major.minor.patch` version syntax.
It prepares the retained exact pair `1.12.5` to `1.13.0`, plus exact origins
`1.14.5`, `1.15.3`, `1.16.4`, `1.17.2`, and `1.18.2` targeting `1.19.1`. The
`--from` and `--to` values are operator declarations; an image tag or digest is
not verified. Unsupported but well-formed pairs produce `UNKNOWN` with an
`unsupported` fact state. Missing or ambiguous container selection and
unresolved command arguments produce `UNKNOWN` with a `missing` or
`unsupported` fact state. Invalid syntax returns exit `2`.

The five `1.x` to `1.19.1` rules are target-only constraints. They do not claim
that `reportsChunkSize` first became unsupported on any of those transitions.
For the official upstream bare `reports-controller` surface, a conservatively
parsed literal flag is scoped `BLOCKED`, definite literal absence is scoped
`PASS`, and custom builds, wrappers, unsupported argument grammar, missing or
conflicting facts, and wrong endpoints remain `UNKNOWN`. The retained target
changelog text records the historical removal; the target registration and Go
flag parser sources bind the actual `1.19.1` surface and admitted integer/token
grammar.

OPA has target-only rules for exact origins `1.15.2`, `1.16.2`, `1.17.1`,
`1.18.2`, and `1.19.1` targeting `1.20.2`. When an operator declares that v0
consumers remain and relevant modules omit the `rego.v1` import alternative,
an effective producer without `--v0-compatible` is scoped `BLOCKED` and one
with that producer mode is scoped `PASS`. The `rego.v1` alternative, missing or
conflicting declarations, and wrong endpoints remain `UNKNOWN`. This generic
route does not parse modules or bundles, inspect consumers, execute OPA, or
prove policy, runtime, or whole-upgrade compatibility.

The Linkerd preparation adapter accepts only a private regular `0600`
`policy.linkerd.io/v1alpha1` `MeshTLSAuthentication` JSON object. Its `spec` may contain only `identities`
or `identityRefs`; it validates both selector arrays before deciding whether
exactly one is present. For the reviewed `2.13.7` to `2.14.0` pair, an empty
selector with the other selector known absent derives
`component.linkerd.mtls_identity_selector_empty=true`; a nonempty selector in
that same arrangement derives `false`. Both selectors, neither selector,
unsupported version pairs, malformed values, and unsupported declarations stay
`UNKNOWN` or return invalid input as appropriate. `--distribution` and
`--schema-validation` are explicit operator declarations: the matching values
are `official_upstream` and `required`. Custom or disabled declarations may be
prepared but do not satisfy the reviewed rule and therefore check as
`UNKNOWN`. Preparation does not parse a CRD, call API admission, inspect stored
objects, migrate resources, or establish runtime behavior. Metadata, selector
values, and all other resource data are discarded from the minimized output.
The `--from` and `--to` endpoints are explicit operator declarations; the
adapter does not verify an image, installed release, or stored object.
After the shared argument parser selects Linkerd, invalid Linkerd arguments,
resource shapes, or local input admission failures report
`LINKERD_PREPARATION_INPUT_INVALID` with exit `2`. Common parser and routing
errors, including duplicate flags, unknown flags, or a missing project, retain
the generic usage diagnostic with exit `2`. They are rejected before opening
the private input and leave stdout empty. Digest mismatches, unsafe file
identities, and output integrity failures report
`CNCF_PREPARATION_INTEGRITY_FAILURE` with exit `3`. Diagnostics contain no
input path or resource value. A failed output write may leave partial stdout;
discard that output. Human and JSON preparation reports always include
`CRD_SCHEMA_VALIDATION_NOT_PERFORMED`; canonical `--format input` contains only
the minimized declaration, without preparation report metadata.

`PREPARED` means only that a minimized operator declaration was derived. It is
not Kubernetes validation, image or credential validation, command execution,
or proof that the target is runnable. The output retains no workload names,
environment values, raw arguments, configuration, image, or local path. Its
source and input hashes are integrity bindings, not anonymity proofs. Use
`--format json` for preparation metadata, or `--format input` to emit only the
canonical declaration accepted by `check cncf`; that output has exactly one
trailing newline.

Preparation does not run a compatibility check. It reads no cluster or database,
contacts no network and invokes no model. It writes output to stdout; the caller
chooses whether to save it. The adapter accepts JSON only; YAML, Helm
values, live-cluster inspection, credential resolution, arbitrary options and
complete workload validation remain outside this preview.

The etcd preparation adapter accepts one private regular `0600`
`EtcdEffectiveArguments` JSON object with `effectiveArgvDeclared: true` and an
arguments-only `argv` array. The array must describe one complete, direct etcd
invocation; the adapter does not infer authority from a process, image, wrapper,
environment, response file, config file, `ETCD_*` setting, or shell expansion.
The first slice accepts only self-contained long atoms in `--name=value` form.
It recognizes the eight removed options from the exact `3.5.17` to `3.6.0`
transition: `enable-v2`, `experimental-enable-v2v3`, `proxy`, and the five
proxy timeout options. Boolean values are `true` or `false`; `proxy` accepts
`off`, `readonly`, or `on`; timeout values are unsigned decimal; the experimental
string is bounded to conservative non-control literals. A valid occurrence,
including `--enable-v2=false` or `--proxy=off`, declares the existing removed
option fact and therefore produces a scoped `BLOCKED` check. The adapter never
emits a false fact, so an empty or target-free vector remains `UNKNOWN`.

Separated values, single-dash spellings, positional or `--` tokens, unknown or
unmodelled options, duplicate or malformed targets, config/environment syntax,
wrappers, substitutions, control characters, missing authority, and any other
ambiguous interpretation remain `UNKNOWN`. The canonical output retains only
the existing fact and fixed component/version metadata; raw argv, values and
paths are discarded. This is an operator-declared local witness only: it does
not execute etcd, inspect a cluster, evaluate config precedence, or prove data
migration, quorum, runtime, or whole-upgrade compatibility.

For a private source file and declaration output:

```sh
umask 077
chmod 600 proposed-kyverno-deployment.json
source_digest="$(shasum -a 256 proposed-kyverno-deployment.json | awk '{print $1}')"
prufyx prepare cncf --project kyverno \
  --input proposed-kyverno-deployment.json \
  --container kyverno-controller --from 1.12.5 --to 1.13.0 --distribution official_upstream \
  --input-digest "sha256:${source_digest}" --format input > kyverno-input.json
chmod 600 kyverno-input.json
```

Run `check cncf` separately with the actual current canonical UTC time for a
fresh assessment. The check selects only an exact reviewed source rule and
keeps the whole-upgrade assessment `UNKNOWN`; it does not validate the full
workload or runtime behavior.

`catalog cncf` reads embedded public metadata. It separates catalogue identity, generic source-rule coverage, and runtime reproduction. The pinned catalogue currently contains 255 CNCF project identities. The initial priority portfolio contains 30 maintainer-selected projects; that selection is not an adoption ranking. Use `--format json` to inspect the counts and coverage state of your exact binary:

```sh
prufyx catalog cncf --format json
prufyx catalog cncf --priority
prufyx catalog cncf --project helm --format json
```

The generic check accepts one local JSON file containing minimized, operator-declared current and proposed component identities and facts. The file must be a regular private file with mode `0600`; symlinks, permissive files, oversized files, malformed JSON, and untyped values are rejected. The CLI reads bytes locally and does not collect a cluster, inspect live state, invoke a model, download a database, or upload data.

The current embedded preview has 158 exact rules across 54 rule projects, 123
registered boolean or finite-enum facts, and 842 rule-scoped cases. The
separate SPIFFE X.509-SVID and CloudEvents structured JSON
standards-conformance profiles have no from/to pairs and do not alter these
transition-rule totals. SPIFFE does not duplicate the SPIRE project's
versioned CLI rule. See the [SPIFFE](spiffe-x509-svid.md) and
[CloudEvents](cloudevents-structured-json.md) conformance guides.
The separate [TiKV 8.5.8 GCS WIF full-backup target preflight](tikv-gcp-v2-wif-backup.md)
also has no from/to pair and does not alter the transition-rule totals.

Prometheus also has two independently selected `2.55.1` → `3.1.0` native
routes: the existing selected `scrape_config` key rename and one selected
`alerting.alertmanagers` entry's `api_version` choice. The Alertmanager route
reports `BLOCKED` only for literal v1 and treats an omitted key as the exact
target source-derived v2 default; complete-entry and resolved-precedence flags
remain caller declarations. It does not parse a full `prometheus.yml`, prove
Alertmanager compatibility or reachability, or establish alert delivery. See
the [native resource examples](../examples/cncf/native-resources/README.md).

The same canonical Prometheus facts also support two additional exact
`2.55.1` → `3.14.0` operator-declared constraints: the selected
Alertmanager API must not be literal `v1`, and the selected scrape
configuration must not use `scrape_classic_histograms`. Missing either fact,
custom or unresolved configuration, and runtime behavior remain `UNKNOWN`.
This depth route is additional to the 115 selected latest-target pairs in the
2026-09-12 matrix.

OpenTelemetry Collector has two independently selected `0.110.0` → `0.111.0`
native routes. The existing logging-exporter route reads one caller-selected
complete, precedence-resolved Collector YAML and requires a caller declaration
of the official distribution. The internal-metrics route additionally requires
caller declarations for the effective feature gate and whether non-loopback
scraping is required; it evaluates only the source-defined default bind when no
`service.telemetry.metrics` override is present. Unsupported YAML or values,
defaults outside this contract, custom distributions, resource presence,
pipeline behavior, exporter execution, listener or scrape behavior, runtime
behavior, and whole-upgrade safety remain `UNKNOWN`. See the [OpenTelemetry
Collector native examples](../examples/cncf/opentelemetry-collector/README.md).

Cilium project-level `prepare cncf --project cilium` adapter accepts raw policy input only for the exact `1.18.6` → `1.19.0` and `1.18.13` → `1.19.7` pairs. It derives only the existing nonempty-requires fact; a scoped false result still requires an explicit complete CNP and CCNP set declaration. A project-level prepare command never implies preparation of every exact rule pair listed for that project. The
catalogue's 255 identities and 30 maintainer-selected priority projects are
separate counts and are not an adoption ranking. The table below summarizes
selected narrow source constraints:

| Project and reviewed pair | Declared facts | Scoped result |
| --- | --- | --- |
| Falco `0.40.0` → `0.41.0` | `distribution=official_upstream`, `execution_surface=falco`, `removed_040_cli_flags_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with both guards |
| Falco `0.40.0` → `0.42.0` | `distribution=official_upstream`, `execution_surface=falco`, `removed_040_cli_flags_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with both guards |
| Karmada `1.18.3` → `1.19.0` | `distribution=official_upstream`, `execution_surface=karmada_policy_application_failover`, `target_policy_crd_admission_required=true`, `removed_application_purge_mode_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with all three guards |
| Argo CD `2.14.0` → `3.0.0` | `disable_fine_grained_inheritance`, `requires_inherited_application_permissions` | `true` is `BLOCKED` with intent `true`; explicit `false` is `PASS` only with intent `true` |
| Argo CD `3.0.23`, `3.1.16`, `3.2.12`, `3.3.14`, or `3.4.8` → `3.5.2` | `distribution=official_upstream`, `execution_surface=repository_secret`, `repository_settings_complete_and_precedence_resolved=true`, `selected_repository_uses_plain_http=true`, `plain_http_oci_repository_unusable` | `true` is `BLOCKED`; definite `false` is `PASS` only with all four guards |
| Kuma `2.8.0` → `2.9.0` | `distribution=official_upstream`, `execution_surface=kumactl_install_transparent_proxy`, `removed_exclude_uid_flags_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with both guards |
| Linkerd `2.13.7` → `2.14.0` | `distribution=official_upstream`, `execution_surface=meshtls_authentication_crd`, `schema_validation_required=true`, `mtls_identity_selector_empty` | `true` is `BLOCKED`; definite `false` is `PASS` only with all three guards |
| SPIRE `1.10.4` → `1.11.0` | `distribution=official_upstream`, `execution_surface=spire_server_entry_create`, `removed_entry_ttl_flag_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with both guards |
| Tekton Pipelines `1.9.0` → `1.10.0` | `distribution=official_upstream`, `config_observability_identity_bound=true`, `proposed_config_observability_complete_effective=true`, `retain_prometheus_metrics_required=true`, `proposed_metrics_protocol_prometheus` | `false` is `BLOCKED`; exact `true` is `PASS`; missing, unsupported, conflict, partial overlay, non-Prometheus, or wrong-pair declarations remain `UNKNOWN` |
| Dragonfly `2.2.3` → `2.2.4` | `distribution=official_upstream`, `execution_surface=manager_config` or `scheduler_config`, `legacy_verbose_debug_intent`, `retain_debug_logging_required`, `debug_logging_enabled` | `false` effective debug state is `BLOCKED` only for the matching sibling surface and all declared intents; declared `debug_logging_enabled=true` is scoped `PASS` only for the matching sibling surface with all guards satisfied |
| Cortex `1.17.2` → `1.21.1` | `distribution=official_upstream`, `execution_surface=cortex`, `removed_at_modifier_flag_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with both guards |
| Cloud Custodian package `0.9.47`, `0.9.48`, `0.9.49`, `0.9.50`, or `0.9.51` → `0.9.52` | caller-declared IAM Access Key `json-diff` filter presence | a direct selected `json-diff` filter is `BLOCKED`; an explicitly complete empty filter list is scoped `PASS`; missing, ambiguous, unsupported, or wrong-pair declarations remain `UNKNOWN` |
| OpenCost `1.119.0` → `1.120.0` | caller-declared current and proposed cloud-cost enablement, complete source selection, current provider-derived reliance, and proposed cloud-integration source selection with declared file presence | provider-only target selection is `BLOCKED`; an explicitly selected, declared-present cloud-integration file is scoped `PASS`; disabled, incomplete, ambiguous, API-managed, contradictory, or other-pair declarations remain `UNKNOWN` |
| OpenCost `1.116.0`, `1.117.6`, `1.118.0`, `1.119.2`, or `1.120.4` → `1.121.2` | caller-declared current and proposed cloud-cost enablement, complete source selection, current provider-derived reliance, and proposed cloud-integration source selection with declared file presence | provider-only target selection is `BLOCKED`; an explicitly selected, declared-present cloud-integration file is scoped `PASS`; disabled, incomplete, ambiguous, API-managed, contradictory, or other-pair declarations remain `UNKNOWN` |
| CRI-O `1.34.0` → `1.35.0` | caller-declared `named-reference-resolution` operation plus strict short-reference classification from one supplied CRI `ImageStatusRequest` JSON document | a short explicit-tag reference is `BLOCKED`; a fully-qualified explicit-tag reference in the reviewed grammar is scoped `PASS`; unsupported intent, grammar, input shape, ambiguity or other pairs remain `UNKNOWN` |
| Strimzi `0.51.0` → `1.0.0` | `distribution=official_upstream`, `execution_surface=kafka_custom_resource`, `target_kafka_crd_admission_required=true`, `kafka_v1beta2_api_present` | `true` is `BLOCKED`; definite `false` is `PASS` only with all three guards |
| Keycloak `26.7.2` → `26.7.3` | `server_allow_oidc_params_in_redirect_uris`, `client_allow_oidc_params_in_redirect_uris`, `oidc_response_parameter_in_redirect_fragment` for one selected authorization redirect URI | with both allowances explicitly `false`, fragment `true` is `BLOCKED` and fragment `false` is scoped `PASS`; facts must stay bound to that one context, while missing, mixed, conflicting, or opt-in evidence is represented as `UNKNOWN` |
| Knative Serving `1.22.0` → `1.23.0` | `serving_startup_http_named_port_mismatch` derived from one supported proposed Service | `true` is `BLOCKED`; exact `false` is scoped `PASS`; missing, numeric, non-HTTP, multi-container, multi-port, unsupported, or ambiguous shapes remain `UNKNOWN` |
| Buildpacks Lifecycle `0.16.5` → `0.17.7` | current and proposed `selected_platform_api` plus whether each supplied Lifecycle API label declares support | requested target API `0.13` is `BLOCKED`; target-declared `0.12` is scoped `PASS`; malformed, inconsistent, out-of-domain, unsupported-current, or other-pair inputs remain `UNKNOWN` |
| in-toto Python CLI `2.2.0` → `3.0.0` | `in_toto_run_key_argument` derived from one conservatively parsed planned argv | pre-boundary `legacy_key` is `BLOCKED`; `signing_key` is scoped `PASS`; unsupported prefix grammar and other pairs remain `UNKNOWN` |
| CubeFS `3.2.1` → `3.3.2` | caller-declared `metanode-upgrade` phase plus `raftSyncSnapFormatVersion` guard derived from one supplied planned MetaNode JSON config | explicit numeric `0` is scoped `PASS`; absent (target default `1`) or explicit numeric `1` is `BLOCKED`; unsupported phase, role, type, value, ambiguity or other pairs remain `UNKNOWN` |
| TUF Updater `6.0.0` → `7.0.0` | `updater_bootstrap_keyword_present` derived from one conservatively bound direct call in supplied Python source | absent keyword is `BLOCKED`; explicit keyword, including `None`, is scoped `PASS`; unsupported bindings or call shapes and other pairs remain `UNKNOWN`, while malformed lexical input stops without a semantic result |
| Kubeflow KFP Python SDK `1.8.22` → `2.0.0` | `kfp_component_authoring_api` derived from one conservatively bound bare decorator in supplied Python source | unaliased `create_component_from_func` is `BLOCKED`; unaliased `dsl.component` is scoped `PASS`; aliases, rebinding, multiple or dynamic forms, unsupported syntax shapes and other pairs remain `UNKNOWN`, while malformed lexical input stops without a semantic result |

Cloud Custodian endpoints above are the three-part package versions declared by
the immutable `c7n/version.py` files. Their corresponding upstream release tags
have a fourth `.0` component, such as package `0.9.52` at tag `0.9.52.0`; the
adapter does not accept the tag spelling as a package version. It reads one
private operator declaration and does not execute Custodian, read an AWS
account, inspect policies, or prove runtime compatibility.

The OpenCost rows use the same minimized cloud-source declaration. The adapter
does not parse a deployment, inspect a cluster, contact a provider, open a
configuration file named in the declaration, or prove cost-model behavior.
Each endpoint is an exact reviewed release identity; no intermediate upgrade
sequence is implied.

The Karmada fact covers only declared proposed rendered `PropagationPolicy` or
`ClusterPropagationPolicy` application-failover `purgeMode` values at the exact
reviewed endpoints. The optional local `prepare cncf --project karmada` adapter
reads one private resource and can witness `Immediately` or `Graciously` as a
scoped blocker. It deliberately cannot prove that every proposed policy is free
of legacy values: `Directly`, `Gracefully`, `Never`, missing and unresolved values
remain `UNKNOWN` through this adapter. A manual reviewed complete declaration is
still required for the rule's separate definite-absence/PASS path. The removed names are `Immediately` and `Graciously`; their
source-documented replacements are `Directly` and `Gracefully`, respectively. The target-admission guard is a plan declaration for the
official 1.19.0 policy CRD schema; it does not prove CRD installation,
API-server validation, stored-object migration, reconciliation, or failover
runtime. Cluster failover, other resources, custom distributions, missing or
false admission intent, unresolved rendering, and all other pairs stay
`UNKNOWN`. The check command has no resource parser; the optional preparation adapter only maps the one private resource as described above.

The Argo CD fact covers only the declared `argocd-cm` ConfigMap setting
`server.rbac.disableApplicationFineGrainedRBACInheritance` for the reviewed
`2.14.0` to `3.0.0` pair. The optional local `prepare cncf --project argo-cd`
adapter reads one private JSON resource and requires the operator to declare
whether inherited application permissions are needed. An explicit `true`
setting with intent `true` is a scoped blocker; an explicit `false` setting with
intent `true` is a scoped pass. Missing or malformed settings, missing or false
intent, unsupported pairs, RBAC policy, CLI or environment overrides, stored
objects, and all runtime behavior remain `UNKNOWN`. It does not inspect a
cluster, validate RBAC, or prove whole-upgrade compatibility.

The separate Argo CD `3.5.2` preparation route reads one caller-selected,
pre-apply v1 repository Secret labeled `argocd.argoproj.io/secret-type:
repository`. It admits only `type=helm` with `enableOCI=true`, then classifies
the selected protocol-free OCI registry/path and `insecureOCIForceHttp`/`insecure`
flags. Plain-HTTP use is an explicit caller declaration, not inferred from the URL.
A scoped result additionally requires `distribution=official_upstream` and an
explicit declaration that repository settings are complete and precedence
resolved. This guard is required because repository credential templates can
override selected settings. Native `type=oci`, dependency pulls, custom builds,
missing guards, unsupported shapes, and other version pairs stay `UNKNOWN`.
The adapter discards names, URLs, credentials, and unrelated fields. It does
not read credential templates, authenticate, contact a repository, execute
Helm, inspect a cluster, or establish whole-upgrade compatibility. A runnable
private-file example is in the [CNCF examples guide](../examples/cncf/README.md).

The Knative Serving observation is a named HTTP startup-probe port comparison
for one `serving.knative.dev/v1` Service. The combined `check cncf --project
knative --service ...` path reads a private `0600` JSON file and derives the
fact independently of rule selection only when it contains one user container,
one explicit `http1` or `h2c` container port, and one HTTP startup probe with an
explicit `http1` or `h2c` named port. The embedded rule applies only to
`1.22.0` to `1.23.0`: a mismatch is scoped `BLOCKED`, and changing the probe
name to the declared container port name is scoped `PASS`. Both retain aggregate
`UNKNOWN`. An explicitly selected verified local CNCF store is authoritative
for external current and historical checks; a missing exact rule remains
`UNKNOWN` without embedded fallback. Current checks use verifier time, while
historical replay requires exact knowledge pins plus a raw Service digest.
Replay binds the minimized prepared observation rather than the original raw
Service bytes, so operators must retain the raw file and digest separately.
The old bounded source caller validates liveness and readiness probes
without calling startup-probe validation; this does not claim the old file has
no other StartupProbe reference or that v1.22 admitted every resource. Other
Service admission, API-server behavior, startup, traffic, runtime, and whole-
upgrade compatibility are not evaluated.

The TUF Updater observation comes from one caller-supplied private Python
source file. `check cncf --project the-update-framework-tuf --python-source
...` uses a Go lexical parser and reads the source only as data. It does not
import, execute, or require Python. Source outside the documented direct-import
and single-top-level-call subset remains UNKNOWN.

The adapter admits exactly one conservatively bound top-level direct
`tuf.ngclient.Updater` call using either documented unaliased import form and
the shared stable base call shape. It records only whether an explicit
`bootstrap` keyword is present. Missing keyword is scoped `BLOCKED` for exact
Updater `6.0.0` to `7.0.0`; explicit presence, including `None`, is scoped
`PASS`. `None` is useful only when the cached-root trust path is intended and
does not establish cache or trust safety. Aliases, rebinding, dynamic or
multiple calls, star arguments, seventh positional bootstrap, invalid or
ambiguous call shapes, syntax errors, and other version pairs do not become a
false result. They remain `UNKNOWN` or stop at the bounded input/setup error.
No result validates bootstrap values, root or cache contents, metadata,
updates, installed-package/process provenance, runtime behavior, or whole-
upgrade safety. External knowledge is authoritative with no embedded fallback;
historical replay binds minimized input and requires the raw source digest plus
all three knowledge pins.

The KFP Python SDK observation uses the same Go lexical source boundary. It
accepts exactly one ordinary synchronous function with either unaliased
`from kfp.components import create_component_from_func` and bare
`@create_component_from_func`, or unaliased `from kfp import dsl` and bare
`@dsl.component`. It records only which of those two authoring forms appears;
raw source bytes and their digest remain outside the minimized evaluator input.
For exact KFP `1.8.22` to `2.0.0`, the legacy form is scoped `BLOCKED` and the
`dsl.component` form is scoped `PASS` for this removed-API predicate. Aliases,
rebinding, decorator calls, mixed or multiple candidates, dynamic bindings,
async definitions, f-strings, escaped or prefixed string forms, inline suites,
nested blocks, and other supported-but-unrecognized source forms remain
`UNKNOWN`. Malformed lexical syntax stops without a semantic result. The
checker never imports or executes supplied source. Neither result validates
component inputs, outputs, dependencies, base image, compilation, backend,
installed-package/process provenance, runtime behavior, or whole-upgrade safety.
External knowledge is authoritative with no embedded fallback; historical
replay requires the raw source digest and all three knowledge pins. A replay
matches the minimized authoring-form observation, selected knowledge and saved
time, so retain the raw source and digest separately for original-byte identity.

The CRI-O observation comes from one caller-supplied private native CRI
`ImageStatusRequest` JSON file plus the explicit caller-declared
`named-reference-resolution` operation. The adapter reads only root
`image.image` and minimizes two facts: the operation intent and whether the
reference is short. Unrelated JSON fields remain local. Duplicate or
case-fold-colliding relevant keys, missing values, and unsupported reference
forms stay `UNKNOWN`; malformed JSON stops as an input error.

For exact CRI-O `1.34.0` to `1.35.0`, a strict short reference with an explicit
tag is scoped `BLOCKED`. A lowercase fully-qualified dotted DNS host, valid
repository path and explicit tag are scoped `PASS` for this one target
ArtifactStore guard. Digests, ports, IPs, `localhost`, transport prefixes,
missing tags, registry aliases and forms outside the documented length and
separator bounds remain `UNKNOWN`. A result does not resolve aliases, invent a
default registry, inspect ArtifactStore contents, establish which server branch
receives the request, contact a registry, or validate ordinary-image handling,
access, pulls, removal, runtime behavior or the whole upgrade.

An explicitly selected signed local CNCF store is authoritative with no
embedded fallback. Current external checking uses verifier time and rejects
`--now`. Historical replay requires the saved report, raw request digest and
all three knowledge pins. The report binds the minimized intent and reference
classification rather than original request bytes, so retain the private raw
file and digest separately when byte identity matters.

The Jaeger adapter accepts a private regular `0600` JSON declaration rather
than a Kubernetes resource. It requires an operator attestation that the input
is the direct official Jaeger-v2 invocation and exactly one local literal
`--config=VALUE` atom. This is the smallest accepted declaration:

```json
{"authority":"OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY","argv":["--config=/local/path.yaml"]}
```

```sh
umask 077
chmod 600 jaeger-declaration.json
prufyx prepare cncf --project jaeger --input jaeger-declaration.json \
  --from 1.76.0 --to 2.20.0 \
  --non-memory-storage-required true \
  --official-jaeger-distribution true --format input > jaeger-input.json
chmod 600 jaeger-input.json
```

The adapter derives only `component.jaeger.explicit_config_provided=true`.
The authority is an operator attestation, not executable, image, provider, or
runtime proof. The local path is not opened, retained, or reported; its
presence does not prove readability, valid configuration, backend selection,
startup, non-memory storage, or upgrade safety. The two CLI guards remain
manual operator declarations. Empty, split, repeated, wrapped, expanded,
provider, remote, malformed, or unresolved argument shapes stay `UNKNOWN`.

The Falco, Kuma, and SPIRE removed-option facts cover only declared proposed effective
option presence for their reviewed command surfaces. SPIRE
`removed_entry_ttl_flag_present=true` means the direct standard proposed
`spire-server entry create` invocation has an effective `-ttl` or `--ttl` option;
`false` means both spellings are definitely absent. It does not parse argv,
infer wrappers, shell expansion or delimiters, validate a replacement TTL,
inspect entries, or prove server runtime behavior. Missing, custom, ambiguous,
unresolved, or other-surface facts stay `UNKNOWN`.

The Dragonfly rules are two separate sibling claims for `manager_config` and
`scheduler_config`. They require an operator-declared current verbose debug
intent, proposed retain-debug intent, official upstream distribution, the
matching proposed configuration surface, and a proposed effective debug logger
state. A declared proposed `debug_logging_enabled=false` blocks the matching
claim; `true` passes that narrow predicate. A false or missing retain-debug
intent, custom distribution, other surface, wrappers, custom logger overrides,
unresolved defaults, or conflicting facts remain `UNKNOWN`. Current verbose
intent never infers proposed intent. This preview has no Dragonfly
configuration parser, default resolver, or runtime logging observation, and
the whole-upgrade assessment remains `UNKNOWN`.

The Cortex fact covers only declared presence of the exact
`querier.at-modifier-enabled` option in effective proposed arguments for the
official upstream `cortex` command. The option was already nonfunctional at
the reviewed current endpoint, so this rule checks input compatibility and
does not claim a query-behavior change. The Go native-input adapter admits
only one caller-supplied `apps/v1` workload container named `cortex`, the exact
reviewed target image, explicit `command: ["/bin/cortex"]`, and a narrow
literal argv subset. Missing or unresolved arguments, default entrypoints,
custom builds, other executables, and unreviewed endpoint pairs remain
`UNKNOWN`.

The Strimzi fact covers only rendered resources with `kind: Kafka` and
`apiVersion: kafka.strimzi.io/v1beta2`. The
`target_kafka_crd_admission_required=true` guard declares that the proposed
plan requires those resources to use the official 1.0.0 Kafka CRD
served-version and schema surface. It does not prove that the CRD is installed
or applied, or that API-server validation ran. An operator-image-only plan, a
retained old CRD, a custom target CRD, or missing or false target-admission
intent remains `UNKNOWN`. KafkaTopic, KafkaUser, stored-object migration,
conversion, reconciliation, and runtime are outside this rule. A false API
presence fact is only a scoped absence result; it does not validate a v1
resource.

The Falco and Kuma removed-option facts cover only declared proposed effective
argv presence for their reviewed command surfaces. The Falco fact's exact
old-option set is `-A`, `-b`,
`--print-base64`, `-S`, and `--snaplen`; the Kuma fact's set is
`--exclude-outbound-tcp-ports-for-uids` and
`--exclude-outbound-udp-ports-for-uids`. These are operator declarations about
effective options; this preview has no argv parser. `false` is a declaration
that the exact old set is definitely absent; it is not inferred from new flags,
current-side configuration, image metadata, defaults, wrappers, expansion, or
runtime state. Missing, custom, ambiguous, unresolved, or other-surface facts
remain `UNKNOWN`. Linkerd `mtls_identity_selector_empty=true` means exactly
one of `identities` or `identityRefs` is explicitly known empty and the other is
known absent; `false` means exactly one is explicitly known nonempty and the other is known absent.
Both, neither, unresolved, or unsupported selector declarations remain
`UNKNOWN`. The `schema_validation_required=true` fact declares operator intent
to validate a proposed MeshTLSAuthentication against the target CRD schema. The
rule does not parse a CRD, call API admission, migrate stored objects, or prove
a runtime.

The input authority and schema are explicit:

```json
{
  "schema": "prufyx.io/operator-declared-constraint-input/v1alpha1",
  "authority": "OPERATOR_DECLARED_MINIMIZED",
  "current": {"components": []},
  "proposed": {"components": []}
}
```

Facts are accepted only when their component and fact ID are present in the compiled embedded registry. A fact is declared, missing, unsupported, or conflicting. Missing, unsupported, and conflicting facts produce `UNKNOWN`; they are never interpreted as false. The current side and proposed side are separate, so configuration is never assumed to carry forward across an upgrade.

Use state tokens `declared`, `missing`, `unsupported`, or `conflict` exactly.
Only `declared` facts carry a `boolValue` or registered `enumValue`; other states
carry neither. Versions use numeric `major.minor.patch` without a `v` prefix,
range, prerelease or build suffix. The current and proposed component arrays
must be sorted by component identity, and facts by ID, with no duplicates.
An unsupported syntax is an invalid input; a well-formed unreviewed version pair
produces `UNKNOWN`. Keep the actual versions and request more coverage.

Here is a fully synthetic Helm post-renderer example. It demonstrates the input shape and does not represent a customer configuration or a runtime result:

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

Save the file with a private mode, then calculate its exact digest if you want the optional input binding:

```sh
umask 077
chmod 600 helm-input.json
shasum -a 256 helm-input.json
prufyx check cncf --project helm --input helm-input.json \
  --input-digest sha256:<digest-of-helm-input.json> \
  --now 2026-09-08T12:10:00Z --format json
```

The `--now` value is mandatory, canonical UTC, and whole-second precision. It makes evaluation replayable without reading the system clock. The fixed time above is for the synthetic example; use the actual current UTC time for a new real assessment. Do not backdate an assessment to bypass review expiry. Packaged reviews expire after 90 days under the maintainer policy; that interval does not establish an upstream support lifetime. A JSON report can be retained as another regular `0600` file:

```sh
umask 077
prufyx check cncf --project helm --input helm-input.json \
  --now 2026-09-08T12:10:00Z --format json > helm-report.json
chmod 600 helm-report.json
prufyx check cncf --project helm --input helm-input.json \
  --now 2026-09-08T12:10:00Z --replay-report helm-report.json
```

Replay compares the exact prior canonical report at the supplied original time. It proves local byte-for-byte reproducibility for that input, embedded pack, and timestamp. It does not establish current source freshness, signature status, non-revocation, live observation, or runtime reproduction.

Exit status is scoped to the selected source claims:

- `0`: every selected nonempty claim passed.
- `10`: at least one selected claim is `BLOCKED`.
- `11`: a claim is `UNKNOWN`, or the selected project has no generic rules.
- `2`: invalid command, timestamp, file admission, or input.
- `3`: integrity failure.

The report’s aggregate assessment remains `UNKNOWN` in every case because this command evaluates selected source constraints, not a whole upgrade. A `PASS` establishes only the cited predicate. A deprecated or retained no-op option is not a blocker merely because it is old; a blocker requires an actual packaged source constraint whose predicate is violated.

Two constraints illustrate why proposed intent matters:

- KEDA `2.16.0` to `2.17.0` checks a declared dependency on the removed direct
  External Scaler `tlsCertFile` transport behavior. Declare
  `component.keda.external_scaler_present=true` and whether
  `component.keda.legacy_tls_cert_file_required_for_transport` is required in
  the proposed plan. A raw `tlsCertFile` metadata field alone does not prove
  this dependency: the external scaler can still receive that metadata.
  A scoped `PASS` means only that the legacy direct behavior is not required;
  replacement credentials, TLS negotiation and scaler behavior are unverified.
- Jaeger `1.76.0` to `2.20.0` checks the official target's default in-memory
  configuration against a declared non-memory requirement. Both
  `component.jaeger.official_jaeger_distribution` and
  `component.jaeger.non_memory_storage_required` must be declared `true` on
  the proposed side. Declare `component.jaeger.explicit_config_provided=false`
  only when `--config` is definitely absent; that is the default-memory
  blocker. The local Jaeger preparer accepts one private `0600` JSON declaration
  with the exact direct-invocation authority and exactly one local literal
  `--config=VALUE` argv atom. It emits only `explicit_config_provided=true`;
  the two guards remain explicit operator flags. Empty, repeated, split,
  wrapped, expanded, provider, remote, ambiguous or unresolved selections stay
  missing or unsupported. A selected value does not prove location readability,
  config content, backend, credentials, startup, or runtime health. Current
  storage never establishes proposed intent.

KEDA has no automatic preparation adapter in this preview. Keep unknown facts
unknown. A missing or false applicability guard, custom distribution, or
unreviewed version pair produces `UNKNOWN`. These exact historical transitions
are coverage boundaries, not recommended target versions.

From the repository root, synthetic Falco and Kuma inputs are available as
[`falco-input.json`](../examples/cncf/falco-input.json) (0.41.0),
[`falco-042-input.json`](../examples/cncf/falco-042-input.json) (0.42.0), and
[`kuma-input.json`](../examples/cncf/kuma-input.json). Copy each to a private
local file before checking:

```sh
umask 077
cp cli/examples/cncf/falco-input.json falco-input.json
cp cli/examples/cncf/kuma-input.json kuma-input.json
chmod 600 falco-input.json kuma-input.json
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
prufyx check cncf --project falco --input falco-input.json \
  --now "$now" --format json > falco-report.json
falco_status=$?
prufyx check cncf --project kuma --input kuma-input.json \
  --now "$now" --format json > kuma-report.json
kuma_status=$?
chmod 600 falco-report.json kuma-report.json
printf 'Falco exit: %s; Kuma exit: %s\n' "$falco_status" "$kuma_status"
```

Each synthetic file declares the removed-flag fact as `true`, so a matching
embedded review produces a named `BLOCKED` claim and exit `10`; the report's
whole-upgrade assessment remains `UNKNOWN`. To model a scoped PASS, prepare a
separate minimized input that declares the exact old-flag fact as `false` and
keeps all distribution and execution-surface guards; do not use a new flag as
proof of absence. Missing facts, custom distributions, and other command
surfaces stay `UNKNOWN`. The examples are data-only declarations and do not
represent argv parsing, migration, startup, or runtime validation.

The current preview also includes two exact package/schema constraints in addition to the source constraints above:

- Fluentd `1.16.0` to `1.17.0`: declare proposed
  `component.fluentd.distribution=official_upstream` and the proposed
  `pkg:generic/ruby` component version. Ruby below `2.7.0` violates the cited
  package minimum. Missing Ruby or a custom distribution remains `UNKNOWN`;
  malformed versions such as `2.7` are invalid input. A scoped `PASS` covers
  only this Ruby minimum, with plugin and runtime compatibility unverified.
- Crossplane `1.20.0` to `2.0.0`: declare proposed
  `component.crossplane.distribution=official_upstream`,
  `component.crossplane.schema_validation_required=true`, and
  `component.crossplane.composition_mode` as `resources` or `pipeline`.
  `resources` violates the official target Composition CRD enum;
  `pipeline` satisfies only that enum constraint. The validation guard declares
  an intent to create or update against the target schema; it does not prove
  the installed schema. Missing facts, custom distributions, or bypassing that
  schema scope remain `UNKNOWN`. Stored-object migration, reconciliation and
  application startup are unverified.

Fluentd also has a `1.17.1` to `1.18.0` local preparation route for one paired
selected classic-config JSON literal. Its outer declaration has exactly five
fields: `current`, `proposed`, `selectedValueComplete`, `currentDefaultUsed`,
and `preserveLiteralTreatment`. All three Boolean declarations must be true.
The selected JSON values must be byte-identical, unless the proposed value is
the exact single-quote wrapper of the unchanged current value. The adapter
records only whether one simple unquoted `#{...}` marker is present; it does
not parse Fluentd configuration, Ruby, interpolation, plugins, or runtime.
Examples are in
[`examples/cncf/fluentd-literal-treatment`](../examples/cncf/fluentd-literal-treatment/README.md).

The earlier Fluentd Ruby-minimum facts are entered locally; the literal route
has the documented preparation adapter. The current rules use 123 registered
facts, so this binary requires its own compatible CNCF database store. Preserve
older stores and binaries for older reports. The embedded CNCF rule pack has 158
constraints across 54 rule projects and 842 rule-scoped cases; the separate
community-project pack has 32 constraints across 6 projects. Runtime
reproduction remains zero.

The fact registry and operators are compiled into this binary. Rules are embedded by default; `db import --profile cncf` can select a complete signed local rule revision for `check cncf --knowledge-db DIR`. External selection never blends with embedded rules. `catalog cncf` describes the embedded coverage only. Explicit [`db update`](knowledge-updates.md) can download a complete package before local import. There is no public Prufyx root, feed or automatic startup refresh. A new rule over existing canonical facts can be imported without a binary release. For a newly reviewed exact pair, the current binary can evaluate it when those facts are declared manually; new facts or operators require an engine update. Optional `prepare cncf` adapters support only their documented pairs, so extending raw-input preparation for a new pair can require a CLI update even when the facts and operators are unchanged. Both embedded and external CNCF rules must limit `reviewedAt` to `validUntil` to at most 90 days. That bound does not authenticate the declared review or establish an upstream support lifetime.

A contribution must provide an exact released current/target version pair, an official primary source pinned to a 40-character Git revision, the full source-file SHA-256 and exact line spans, minimized registered boolean or finite-enum facts, and positive, blocked, missing, and outside vectors. Missing, unsupported, ambiguous, custom-distribution, or unreviewed endpoint cases must remain `UNKNOWN`. Contributions must preserve the local-only and no-mutation boundary.

A mandatory intermediate version is a direct-path blocker. A current/final
input cannot prove that an intermediate upgrade happened, so those rules have
no PASS vector for the direct pair. Test their blocked, missing and outside
cases; evaluate each later hop separately against its own reviewed rules.
Sources and tests accompany a contribution; the CLI never downloads those
sources to authenticate a hash. Packaged maintainer review, operator
declarations and runtime evidence are separate authorities.

Start a metadata proposal with the [upstream evidence packet workflow](upstream-contributions.md). Its offline receipt is a candidate consistency check; a separate rule contribution still needs the source and vector review above.
