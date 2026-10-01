# Community project checks

`prufyx check project` is a separate, embedded-only source-rule preview for a
small maintainer-reviewed registry separate from the bundled CNCF Landscape
identity registry. It does not assert CNCF membership and does not use the
CNCF knowledge profile or store.

Every route documented below, including the Ceph and Argo Workflows workload
routes and the Grafana, Kibana, and Fluent Bit target-only pairs, is also
discoverable through `catalog checks` alongside MariaDB Operator; see
[Discovering embedded source-rule routes](community-checks.md#discovering-embedded-source-rule-routes).
`catalog checks` reports the exact typed `check project` command for each
bound identity without evaluating it.

From the repository root, build the preview with the validated offline
toolchain settings and keep its binary and private inputs outside the checkout:

```sh
set -eu
umask 077
PREVIEW_DIR="$(mktemp -d)"
trap 'rm -rf "$PREVIEW_DIR"' EXIT
test "$(go env GOVERSION)" = go1.26.8
(cd cli && GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o "$PREVIEW_DIR/prufyx-community" ./cmd/prufyx-community)
```

The closed community registry includes these native effective-configuration
checks:

- Grafana `10.4.0` → `11.0.0`: whether a proposed `grafana.ini` explicitly
  sets `[alerting] enabled=true`, which Grafana 11 rejects during settings
  loading. Passing this predicate does not prove that alert data was migrated.
- Kibana `8.18.0` → `9.0.0`: whether a proposed `kibana.yml` retains
  `xpack.reporting.roles.allow`, which Kibana 9 no longer supports. Passing
  this predicate does not validate feature privileges or reporting access.
- Fluent Bit `3.2.0` → `4.0.0`: whether a complete proposed classic
  configuration preserves an enabled OpenTelemetry `http2` setting after
  Fluent Bit changed its default from `on` to `off`. This requires the
  caller to declare that the current default was used and that preservation
  is intended. It checks only the enabled setting; protocol negotiation,
  TLS, connectivity, collector behavior, and whole-upgrade compatibility
  remain UNKNOWN. Fluent Bit is a neutral community-project identity; CNCF
  membership is not asserted.
- Fluent Bit `3.2.10`, `4.0.14`, `4.1.2`, `4.2.8`, or `5.0.10` → `5.1.2`:
  whether a complete selected OpenTelemetry output has `http2 on|force` when
  the caller explicitly requires HTTP/2 for that target output. Fluent Bit
  5.1.2 also allows HTTP/1.1, so `off` is blocked only under that declared
  target requirement. This does not infer an origin default or preservation
  intent.
- Grafana Loki `2.9.8` → `3.0.0`: whether the selected top-level `compactor`
  mapping in a proposed native Loki YAML document retains `shared_store` or
  `shared_store_key_prefix`, which the reviewed 3.0 compactor configuration
  removes. Passing this predicate does not validate Loki startup, storage,
  schema, index, retention, data migration, or data access.
- MariaDB `10.11.8` → `11.4.2`: whether the caller explicitly requires the
  removed InnoDB defragmentation behavior. The old source registers the
  feature; the target registers `innodb-defragment` as an ignored
  compatibility option that warns and does nothing. The rule requires
  `--upstream-distribution` and an explicit
  `--require-innodb-defragmentation true|false`. Option presence, absence, or
  value alone never blocks startup or authorizes a behavior requirement.

The MariaDB examples exercise the three scoped outcomes:

```sh
umask 077
cp cli/examples/projects/mariadb/broken.cnf "$PREVIEW_DIR/mariadb.cnf"
"$PREVIEW_DIR/prufyx-community" check project \
  --project mariadb \
  --effective-config "$PREVIEW_DIR/mariadb.cnf" \
  --from 10.11.8 --to 11.4.2 \
  --effective-config-complete --precedence-resolved \
  --upstream-distribution \
  --require-innodb-defragmentation true \
  --now 2026-09-12T12:00:00Z
```

`broken.cnf` is BLOCKED only with the explicit `true` behavior requirement.
`fixed.cnf` is a scoped PASS when checked with `false`, which records that the
removed behavior has been waived or replaced and verified separately; its
retained option demonstrates that deleting an ignored key does not restore the
feature. `unknown.cnf` stays UNKNOWN because its include graph is unresolved.
Omitting the requirement also stays UNKNOWN. Exact lowercase `[mariadb]`, `[mariadbd]`,
`[mysqld]`, and `[server]` groups are admitted; an exact `[client]` group is
ignored. Other groups, group suffixes, case variants, includes, option
prefixes, aliases, non-ASCII whitespace, and unsupported option shapes remain
UNKNOWN. Reports retain only the Boolean behavior requirement and distribution
guard plus content digests, never paths, raw option values, or private group
contents.

The Fluent Bit example files are native classic configuration snippets. Copy
one to a private file and declare the current default and preservation intent:

```sh
cp cli/examples/projects/fluent-bit/broken.conf "$PREVIEW_DIR/fluent-bit.conf"
"$PREVIEW_DIR/prufyx-community" check project \
  --project fluent-bit \
  --effective-config "$PREVIEW_DIR/fluent-bit.conf" \
  --from 3.2.0 --to 4.0.0 \
  --effective-config-complete --current-default-was-used \
  --preserve-http2-enabled \
  --now 2026-09-12T00:00:00Z
```

The bounded parser admits one `[OUTPUT]` section with an exact `Name
opentelemetry` row and selected `http2 on|off|force` or `grpc off` values.
It requires consistently space-indented key/value rows separated by an ASCII
space. Includes, environment substitutions, duplicate keys, case aliases,
tabs, Unicode whitespace, continuations, other sections, and unresolved
`grpc on|auto` forms remain UNKNOWN. Values for unrelated rows are discarded.
Use `fixed.conf` for a scoped PASS and `unknown.conf` for an unsupported
configuration shape; `broken.conf` is BLOCKED under the preservation intent.

For the separate v5.1.2 target-only route, use `latest-fixed.conf`,
`latest-blocked.conf`, or `latest-unknown.conf` with one exact listed origin,
`--to 5.1.2`, `--effective-config-complete`, and `--require-http2`. The target
source accepts `on`, `off`, and `force` and defaults to `off`; the route checks
only a caller-required HTTP/2 selection, never protocol negotiation or a
default carried from the origin.

The Loki check uses the same private-file and declaration boundary. From the
repository root, copy the fixed public example into the private directory and
check the exact reviewed transition:

```sh
umask 077
cp cli/examples/projects/loki/fixed.yml "$PREVIEW_DIR/loki-proposed.yml"
"$PREVIEW_DIR/prufyx-community" check project \
  --project loki \
  --effective-config "$PREVIEW_DIR/loki-proposed.yml" \
  --from 2.9.8 --to 3.0.0 \
  --effective-config-complete --precedence-resolved \
  --now 2026-09-12T00:00:00Z
```

The Loki parser accepts one plain YAML document with one selected top-level
`compactor` mapping. Duplicate keys, aliases, anchors, merge keys, custom
tags, multiple documents, nested or case-ambiguous reviewed keys, and
unresolved template or environment expressions remain UNKNOWN or fail input
admission. Present reviewed keys are classified only when their values are
literal YAML strings; null, Boolean, sequence, and mapping values remain
UNKNOWN instead of being attributed to this upgrade. Unrelated configuration
values are discarded. A scoped PASS means only that the two reviewed legacy
keys are absent from this caller-declared complete and precedence-resolved
selection.

- Grafana Loki `2.9.8` → `3.0.0`: whether one selected top-level
  `schema_config` period satisfies the structured-metadata constraint of
  `store: tsdb` and `schema: v13` when `allow_structured_metadata` is enabled.
  The native mode is selected explicitly with `--loki-schema-config`; it
  accepts only one period, stores `tsdb` or `boltdb-shipper`, schemas `v9`–`v13`,
  and canonical dates. A complete, precedence-resolved input with an explicit
  `allow_structured_metadata: false` is a scoped PASS for this one global
  constraint. An omitted allow setting remains UNKNOWN unless the exact pair
  is accompanied by `--use-reviewed-target-default`, which records a
  source-derived target default rather than a live observation. PASS/BLOCKED
  says nothing about OTLP, storage migration, retention, data access, or
  runtime startup. Multiple periods, aliases, tags, duplicate or near-key
  spellings, templates, and unsupported values remain UNKNOWN.

Copy a public structured-metadata example to a private file before checking:

```sh
umask 077
cp cli/examples/projects/loki/schema-structured-fixed.yml "$PREVIEW_DIR/loki-schema.yml"
"$PREVIEW_DIR/prufyx-community" check project \
  --project loki \
  --loki-schema-config "$PREVIEW_DIR/loki-schema.yml" \
  --from 2.9.8 --to 3.0.0 \
  --effective-config-complete --precedence-resolved \
  --now 2026-09-12T02:00:00Z
```

Use `schema-structured-broken.yml` for a scoped BLOCKED result and
`schema-structured-unknown.yml` for the deliberately unsupported multiple
period shape. The selected schema/store values are reduced to one Boolean
fact and do not enter the canonical input or report.

The Argo Workflows `3.5.0` → `3.6.0` check and five target-revalidation checks
from `3.4.18`, `3.5.15`, `3.6.19`, `3.7.18`, or `4.0.11` to `4.1.3` inspect
one caller-supplied native Kubernetes Deployment. Each selects the unique
`argo-server` container bound to the exact reviewed target image
(`quay.io/argoproj/argocli:v3.6.0` or `:v4.1.3`) and either explicit
`command: ["argo"]` or that exact image's reviewed `ENTRYPOINT ["argo"]`
default. A literal `server --basehref` option is BLOCKED because the reviewed
targets register `--base-href`; absence is a scoped argv PASS only when the
caller declares the selected argv complete. The later-origin checks revalidate
the target spelling and do not assert that every origin still accepts the old
spelling. They do not verify image bytes, deployment, cluster, or server runtime.

The Ceph Quincy `17.2.7` → Reef `18.2.0` preflight inspects one private,
caller-selected **current** native per-OSD `ceph osd metadata ID` JSON output
containing exact `id` and `osd_objectstore` fields. A matching `filestore`
backend is BLOCKED because
the reviewed Reef object-store factory rejects FileStore; `bluestore` is a
scoped PASS for this selected-current-object predicate. This input is not a
whole `ceph report`, OSD inventory, target deployment observation, or cluster
safety assessment. The reviewed Quincy selected-OSD command establishes the
numeric-id metadata-object projection; the reviewed Reef factory supplies the
target FileStore rejection.

Copy a public fixture to a private file before checking it:

```sh
umask 077
cp cli/examples/projects/grafana/broken.ini "$PREVIEW_DIR/grafana-proposed.ini"
"$PREVIEW_DIR/prufyx-community" check project \
  --project grafana \
  --effective-config "$PREVIEW_DIR/grafana-proposed.ini" \
  --from 10.4.0 --to 11.0.0 \
  --effective-config-complete --precedence-resolved \
  --now 2026-09-11T20:00:00Z
```

Input must be a regular `0600` file without symlinks. The completeness and
precedence flags are explicit caller declarations: use them only after the
file represents all effective settings, including environment and CLI
overrides. Without either declaration the relevant fact remains UNKNOWN.

For the workload check, copy a public example to a private file from the
repository root, then evaluate the same file locally:

```sh
umask 077
cp cli/examples/projects/argo-workflows/broken.json "$PREVIEW_DIR/argo-server-proposed.json"
"$PREVIEW_DIR/prufyx-community" check project \
  --project argo-workflows \
  --workload "$PREVIEW_DIR/argo-server-proposed.json" \
  --from 3.5.0 --to 3.6.0 \
  --workload-complete \
  --now 2026-09-11T21:00:00Z
```

The workload parser accepts only an `apps/v1` Deployment, the exact reviewed
image and command binding, a literal `server` argv, and empty or absent `env`
and `envFrom`. It recognizes `--basehref` and `--base-href`; unrelated options
are admitted only in literal self-contained `--lowercase-name=value` form.
Sidecars are discarded. Custom images, wrappers, bare unrelated options,
positional or dynamic values, duplicate selected names or inspected options,
argument-file markers, shell expansion, and `--` remain UNKNOWN. Raw workload
fields and argument values are discarded. An omitted `command` is labeled as
source-derived from the reviewed exact-image entrypoint, not an observed value.

For the `4.1.3` target, use `latest-broken.json` or `latest-fixed.json` and one
of the five exact origins, for example:

```sh
umask 077
cp cli/examples/projects/argo-workflows/latest-broken.json "$PREVIEW_DIR/argo-server-4.1.3.json"
"$PREVIEW_DIR/prufyx-community" check project \
  --project argo-workflows \
  --workload "$PREVIEW_DIR/argo-server-4.1.3.json" \
  --from 4.0.11 --to 4.1.3 --workload-complete \
  --now 2026-09-12T11:30:00Z
```

For the Ceph preflight, copy one selected metadata object to a private file and
bind its decimal OSD id explicitly:

```sh
umask 077
cp cli/examples/projects/ceph/filestore.json "$PREVIEW_DIR/ceph-osd-7-current.json"
"$PREVIEW_DIR/prufyx-community" check project \
  --project ceph \
  --selected-osd-metadata "$PREVIEW_DIR/ceph-osd-7-current.json" \
  --selected-osd-id 7 \
  --from 17.2.7 --to 18.2.0 \
  --selected-osd-metadata-complete \
  --now 2026-09-11T21:00:00Z
```

The completeness flag declares only that this selected per-OSD output contains
the selected current OSD identity and backend. The id must be an exact nonnegative
JSON integer within the reviewed command's signed 64-bit range and match
`--selected-osd-id`; only lowercase `filestore` and
`bluestore` are admitted. Missing, mismatched, ambiguous, or unsupported forms
remain UNKNOWN. Unrelated fields are discarded, and the id, backend value,
path, and other raw fields never enter the canonical input or report.

The same selected-OSD input path has exact target-only rules for Ceph `15.2.17`,
`16.2.15`, `17.2.9`, `18.2.8`, and `19.2.6` proposed to `20.2.4`.
Each rule binds the metadata shape at its exact origin and the target source
that rejects FileStore. Run every synthetic `BLOCKED`, `PASS`, and
`UNKNOWN` case with:

```sh
./prufyx-community community-preview example project-ceph-latest
```

The target-only result covers one explicitly selected current OSD. It does not
claim a supported direct route, migration, cluster-wide OSD inventory, health,
data safety, sequencing, startup, runtime behavior, or whole-upgrade safety.

Grafana input is native INI. The parser reads only the exact `alerting.enabled`
key and rejects duplicate relevant sections or keys. Kibana input is native
YAML in the documented dotted-key form or a plain nested mapping; JSON object
syntax is also accepted because it is a YAML subset. YAML aliases, anchors,
tags, merge keys, flow maps, and ambiguous relevant structures remain UNKNOWN.
Unrelated values are discarded, and raw configuration, paths, member names,
and values do not enter reports.

`prepare project` exposes the same minimizer and can emit the canonical
operator-declared input with `--format input`. `check project` evaluates that
input in memory. Both commands use packaged reviewed references only. External
updates, signed bundles, historical replay, network access, runtime checks,
and whole-upgrade conclusions are unavailable in this first neutral profile.
Unsupported project identities and conflicting knowledge/replay selectors are
rejected instead of falling back to CNCF behavior.

Project identity and rule evidence live in a closed data registry and rule
pack, while all checks reuse the existing typed constraint evaluator. The
pack can contain multiple uniquely identified rules for one project and exact
transition. Evaluation selects only rules matching the requested project and
endpoints, so another reviewed transition cannot turn a supported result into
UNKNOWN. An exact transition using one of the compiled Boolean facts can be
added as reviewed embedded metadata. A new native setting, parser grammar, or
fact type still requires a reviewed binary release. Signed external updates
for this neutral registry are not implemented.

Exit status is `0` for a scoped PASS, `10` for a scoped BLOCKED result, `11`
for UNKNOWN, `2` for invalid input, and `3` for integrity failure. The report's
aggregate remains UNKNOWN for every result.

## Latest Grafana and Kibana target routes

The embedded preview also has five exact Grafana origins (`12.2.10`, `12.3.11`,
`12.4.10`, `13.0.8`, and `13.1.5`) to `13.2.1`. It checks the same narrow
`[alerting] enabled=true` setting because the pinned target settings loader
still rejects it. This is target-only evidence: it does not claim that the
behavior was introduced in 13.2.1, validate plugin or alert migration, or
prove a direct multi-major upgrade safe.

```sh
cp cli/examples/projects/grafana/latest-broken.ini "$PREVIEW_DIR/grafana-13-proposed.ini"
"$PREVIEW_DIR/prufyx-community" check project \
  --project grafana --effective-config "$PREVIEW_DIR/grafana-13-proposed.ini" \
  --from 13.1.5 --to 13.2.1 \
  --effective-config-complete --precedence-resolved \
  --now 2026-09-12T09:24:22Z
```

Kibana has five exact origins (`9.0.8`, `9.1.10`, `9.2.8`, `9.3.8`, and
`9.4.6`) to `9.5.3`. Its status configuration defaults both
`status.allowAnonymous` and `status.statusPageBypassMonitorPrivilege` to
`false`; the reviewed route returns a redacted response to an authenticated
caller without the Elasticsearch `monitor` privilege. This check is active only
with the explicit `--full-status-without-monitor-required` intent and an
unambiguous complete, precedence-resolved configuration that establishes
`status.allowAnonymous: false` or its reviewed target default. Under that
intent, an omitted bypass setting is a scoped BLOCKED result and `true` is a
scoped PASS for this one setting. `status.allowAnonymous: true` is outside this
authenticated-caller predicate. Without that intent, with an incomplete,
ambiguous, nested, quoted, aliased, merged, sequence, or document-marked
configuration, a custom client/auth model, or another endpoint pair, the result
is UNKNOWN.

```sh
cp cli/examples/projects/kibana/latest-fixed.yml "$PREVIEW_DIR/kibana-9-proposed.yml"
"$PREVIEW_DIR/prufyx-community" check project \
  --project kibana --effective-config "$PREVIEW_DIR/kibana-9-proposed.yml" \
  --from 9.4.6 --to 9.5.3 \
  --effective-config-complete --precedence-resolved \
  --full-status-without-monitor-required --now 2026-09-12T09:24:22Z
```

The bypass is not a universal remediation. An operator can instead grant the
monitor privilege or adjust the calling client. Prufyx does not contact Kibana,
validate authentication or privilege assignments, invoke the status route, or
assert its runtime response.

The MariaDB Operator `26.3.0` → `26.6.0` route accepts one private,
caller-selected JSON resource with `apiVersion: k8s.mariadb.com/v1alpha1` and
`kind: MariaDB`. It is limited to a Galera resource: `spec.galera.enabled`
must be true, and a declared `spec.replication.enabled: true` leaves the
predicate UNKNOWN. Use `--resource-complete --pre-operator-update` to declare
that the selected resource is complete and the check is being made before the
operator update is planned:

```sh
prufyx check project \
  --project mariadb-operator --mariadb-resource ./mariadb-resource.json \
  --from 26.3.0 --to 26.6.0 \
  --resource-complete --pre-operator-update \
  --now 2026-09-13T09:00:00Z
```

`spec.updateStrategy.autoUpdateDataPlane: true` is a scoped PASS; explicit
false is BLOCKED because the retained 26.6.0 upgrade guide documents enabling
the data-plane update before updating the operator. Missing, null, non-Boolean,
wrong-type, incomplete, post-update, standalone, replication-only, and
unreviewed version-pair inputs remain UNKNOWN or fail private-file admission.
The route does not inspect a cluster, perform Kubernetes admission, run the
operator, execute Helm, or establish data-plane completion or whole-upgrade
safety. The MariaDB Operator identity is separate from the MariaDB Server
identity, and CNCF membership is not asserted.

The public synthetic examples in
[`examples/projects/mariadb-operator`](../examples/projects/mariadb-operator)
cover the same route without embedding private workload data. Copy each input
to a mode-0700 private directory before checking it. `broken.json` is the
explicit `autoUpdateDataPlane: false` case and exits 10, `fixed.json` is the
explicit `true` case and exits 0, and `unknown.json` omits the setting and exits
11. The aggregate compatibility assessment remains UNKNOWN for all three
scoped results. Each command must include `--resource-complete`,
`--pre-operator-update`, `--from 26.3.0`, and `--to 26.6.0`.
