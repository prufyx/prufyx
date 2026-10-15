# Extractor `helm.values`

Version 1.2.0. Compares a Helm chart's source at the first release of two
consecutive release lines and derives rules only for the upgrades Helm itself
refuses, plus two verdict-neutral notices (see [Notices](#notices)). It is deterministic, reads only upstream source pinned by full commit
SHA, and involves no model.

A run reads one repository, so the extractor is registered once per chart, as
`helm.values.<project>.<chart>`; every registration runs the same code and
carries the same version and code digest.

## Charts

The reviewed chart table is a data file compiled into the extractor,
`cli/internal/extract/helmvalues/targets.json` (schema
`prufyx.io/helm-values-targets/v1`), covered by the code digest: any change to
it is a new extractor version. Each entry names a catalog project and its
component, the repository and directory that hold the chart's source, the
chart's published identity (normalised chart repository URL and chart name),
the prefix of its release tags and the first release line a pair may start
from.

| Extractor id | Repository | Chart directory | Chart | Release tags | First pair from |
| --- | --- | --- | --- | --- | --- |
| `helm.values.cert-manager.cert-manager` | `github.com/cert-manager/cert-manager` | `deploy/charts/cert-manager` | `oci://quay.io/jetstack/charts` `cert-manager` | `vX.Y.Z` | 1.15 |
| `helm.values.external-secrets.external-secrets` | `github.com/external-secrets/external-secrets` | `deploy/charts/external-secrets` | `https://charts.external-secrets.io` `external-secrets` | `helm-chart-X.Y.Z` | 2.6 |
| `helm.values.istio.gateway` | `github.com/istio/istio` | `manifests/charts/gateway` | `https://istio-release.storage.googleapis.com/charts` `gateway` | `X.Y.Z` | 1.26 |
| `helm.values.keda.keda` | `github.com/kedacore/charts` | `keda` | `https://kedacore.github.io/charts` `keda` | `vX.Y.Z` | 2.15 |
| `helm.values.metallb.metallb` | `github.com/metallb/metallb` | `charts/metallb` | `https://metallb.github.io/metallb` `metallb` | `vX.Y.Z` | 0.11 |
| `helm.values.opentelemetry.opentelemetry-collector` | `github.com/open-telemetry/opentelemetry-helm-charts` | `charts/opentelemetry-collector` | `https://open-telemetry.github.io/opentelemetry-helm-charts` `opentelemetry-collector` | `opentelemetry-collector-X.Y.Z` | 0.169 |

Every chart in the table also has a reviewed row in the chart-source table
(`cli/internal/chartidentity/data/chart-sources.json`, see
[../chart-identity.md](../chart-identity.md)); `rulecheck` refuses a chart
rule without one, and a test keeps the two tables in step.

cert-manager and Istio keep a placeholder version in the chart's `Chart.yaml`
at their release tags and set the real one when they publish the chart, so
every pair of theirs is withheld today (see below).

## Release lines and pairs

A **line** is one `major.minor` with at least one final release tag
(`<prefix>X.Y.Z`; pre-releases never count). A **pair** is two consecutive
lines in version order, starting from the line in the table, named by the
first final release of each line (its **anchor**). Rules are anchor-only chart
rules: the subject is the chart (`subject.chart`), from the earlier anchor's
chart version to the later one's, and nothing else matches them.

At each anchor the extractor reads the chart directory: `Chart.yaml`,
`values.yaml`, `values.schema.json` when present, `requirements.yaml` when
present, the `Chart.yaml` of each vendored subchart under `charts/`, and every
file under `templates/`. The other final releases of both lines are read too
(without templates) and recorded in the proof; a release there that does not
read is recorded and never withholds the pair.

The pair is **withheld** (no rule; the manifest says why) when, at either
anchor, the chart directory or `Chart.yaml` or `values.yaml` is missing;
`Chart.yaml` names another chart or declares a chart version other than the
tag's (after removing one leading `v`; only `X.Y.Z`); a YAML file is outside
the strict subset (anchors, aliases, merge keys, custom tags, duplicate or
non-string or empty keys, a key holding a NUL byte, more than one document, or
a key YAML 1.1 reads as a boolean or null such as `on:`); or
`values.schema.json` is not one plain JSON object (duplicate or case-folded
member names are refused).

## What it derives

All three rules are about the later chart, compared with the earlier one.

**Kubernetes minimum** (`require_component_version`, reason
`HELM_CHART_KUBE_VERSION_UNMET`). When the later `kubeVersion` is a single
lower bound `>= X[.Y[.Z]]-0` (missing parts are 0) above the earlier one's,
the rule requires `pkg:github/kubernetes/kubernetes` at `X.Y.Z` or later on
the proposed side. The bound is checked against the proposed Kubernetes
version, so the rule assumes the cluster upgrade lands before the chart
upgrade. An earlier constraint of any other shape counts as no bound. No rule
is derived when the later constraint has an upper bound, `||`,
`~`, `^`, a wildcard, a range or an exact match (Helm also refuses versions
such a constraint excludes), or lacks the `-0` suffix (Helm then also refuses
cluster versions with a vendor suffix such as `1.30.2-gke.1`, which a declared
`X.Y.Z` cannot show).

**Newly required values** (`require_set_member`, reason
`HELM_VALUES_REQUIRED_KEY_UNSET`). The schema is walked from its root through
`properties` only. A key is listed when an object on the walk requires it, every
key above it has a non-empty mapping as its default, it has no default of its
own (a `null` default counts as one: Helm keeps it through the merge), and the earlier chart's defaults satisfied it (it was not
required, or had a default). Helm validates the merged values against the
schema, so an upgrade whose supplied values do not set every listed key is
refused.

**Keys the schema no longer admits** (`forbid_set_member`, reason
`HELM_VALUES_KEY_NOT_ALLOWED`). Every key path the earlier chart used (a
non-null default in its values, or a key its schema declares) is walked
through the later schema; when a closed object (`additionalProperties: false`
and no `patternProperties`) does not declare a key on the path, the shortest
such prefix is listed, unless the later defaults still hold it (even as
`null`) or the earlier schema already refused it.

Both set rules read `component.<project>.chart_<chart>_values_paths_set`: the
key paths (through mappings only) of the values supplied for the chart whose
value is not null, before the chart's defaults are merged, each written as one
member in the form described below. A declared set that is not complete never
passes. No rule has more than 64 members.

The set a consumer builds holds only members that some rule of the project
reading the fact names (the union of the members of all such rules, whatever
their evidence basis); every other key path is left out, so unrelated values
never change the evaluation input. A path no member can express is never in
the set. When the rules name more than 256 members together, or a rule reads
the fact other than through its set condition, the fact is marked
unsupported and none of these rules is decided. `prufyx scan` builds the set
this way from the values supplied with a declared chart hop (see
[../scan.md](../scan.md)).

## Values-path members

A key path is written as a set member in one of two forms, and every path has
exactly one member:

- **Plain**: when every key consists only of letters, digits, `_`, `/` and
  `-`, and the first key starts with a letter or digit, the member is the keys
  joined by `.`, for example `auth.token`.
- **Escaped**: for any other path, the member is `k..` followed by the keys
  joined by `..`. Inside a key, letters, digits, `/` and `-` stand for
  themselves and every other byte (UTF-8 bytes one by one, `_` and `.`
  included) is written as `_` and two upper-case hex digits. For example the
  key `nginx.ingress.kubernetes.io/proxy-body-size` under `annotations` is
  `k..annotations..nginx_2Eingress_2Ekubernetes_2Eio/proxy-body-size`, and the
  top-level key `_internal` is `k.._5Finternal`.

A plain member never contains `..` and an escaped member always does, so the
two forms cannot collide, and a member reads back to exactly one key path.
Both forms stay inside the set-member grammar. A rule only ever lists the
canonical member of a path: `rulecheck` refuses a member of a values-path set
fact that is not exactly what this encoding gives for some path (the escaped
form of a path the plain form can write, lower-case or incomplete escapes, an
escape of a letter, digit, `/` or `-`, or an empty key). A path whose member
would be longer than 128 bytes, or a schema key holding a NUL byte (which no
values file can set), cannot be named; it is recorded with the class
`unexpressible` and never listed. A path that version 1.0.0 listed keeps the
same member.

## What it never claims

- Anything under a key Helm fills from a subchart (a dependency name or alias,
  or the name of a vendored subchart) or under `global`. When `charts/` holds
  a packaged subchart whose file name is not `<dependency>-<version>.tgz`, no
  key of the chart is derived.
- Anything under a schema object that holds a keyword the walk does not read
  (`$ref`, `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`,
  `dependencies`, `unevaluatedProperties`, `propertyNames`, `enum`, `const`,
  a type other than `object`, and the like). Such objects are listed in the
  proof as opaque.
- That a supplied `null` for a mapping the chart defaults keeps the keys below
  it: Helm drops it, and a key the rule lists may then not be required. The
  rule assumes the chart's default mappings are kept.
- Anything when Helm runs with `--skip-schema-validation`, which bypasses
  both set rules (not the Kubernetes minimum).
- A required key whose default is `null` while its schema allows only another
  type. Helm refuses such an upgrade unless the key is set, but the key counts
  as defaulted (class `null-default`).
- A required key under a mapping that defaults to `{}`. Helm refuses such an
  upgrade too, but no rule is derived for it (class `empty-ancestor`).
- Anything about patch releases or other transitions than the anchor pair.
- That an upgrade is safe: a PASS from these rules only says that the
  supplied values meet these particular checks.

## Soft facts

The proof also records what changed that Helm does not refuse: default keys
the later chart removed, scalar defaults it changed, and `.Values` paths the
earlier templates referenced and the later ones do not. The template scan is
syntactic: it records each literal `.Values.a.b` or `$.Values.a.b` path, lists
the template files the parser refuses, and counts every construct through
which a template may read values it does not resolve (`index`, `tpl`, the
whole `.Values`, a variable or chain naming `Values`, the string `"Values"`,
and the root context used other than as the data of `include` or `template`
or the pipeline of `if` or `with`). None of these soft facts is a rule; two of
them become notices when they are proven, and the rest stay in the proof.

## Notices

A notice is a set notice on the values-path set fact: informational, never a
verdict. It never passes or blocks an upgrade, never changes an aggregate or
whether the scope is complete, and is counted apart from the rules that
decide. Its member lists are never printed as forbidden or required keys. A
soft fact that is not proven is only recorded.

**Keys no longer read** (`notice_set_member_present`, reason
`HELM_VALUES_KEY_NOT_REFERENCED`, rule id ending `.unread-values`). The
notice lists keys that the earlier chart's templates name literally and the
later chart's templates provably no longer read. It is shown whenever the
supplied values hold a listed key, even when the declared set is not
complete. A key is listed only when all of this holds at the later anchor:

- the chart has a `templates/` directory, every file in it parses, and it
  holds no symbolic link, submodule or other entry that is not a plain file
  (such an entry is listed as refused);
- the scan counts no `index`, `tpl`, whole-values or other unresolved access
  (see [Soft facts](#soft-facts));
- the chart declares no dependency and has no `charts/` entry, since a
  subchart's or library chart's templates render with values this scan does
  not read;
- no later template names the key, a key above it or a key below it;
- the later `values.schema.json`, if any, does not name the key: it does not
  require the key, a key above it or a key below it, does not declare the
  key under `properties` (or a key above it with a schema that is not an
  object), and holds no object on the way that the schema walk does not read
  (otherwise `schema`);
- the key is not under a subchart key or `global` at either anchor.

When any chart-wide condition fails, every key is recorded as `unproven` and
no notice is derived. The sources are the later `Chart.yaml` and up to seven
earlier template files that named the keys.

**Defaults that changed** (`notice_set_member_absent`, reason
`HELM_VALUES_DEFAULT_CHANGED`, rule id ending `.changed-defaults`). The
notice lists keys whose scalar default differs between the anchors as Helm
reads it. It is shown only over a complete values set that does not hold a
listed key, since only then does the release take the new default. A key is
listed only when:

- both defaults are scalars that every YAML reader reads the same way: a
  boolean, a plain decimal number (no exponent, sign other than `-`, leading
  zero or base prefix), or a string that cannot be read as a boolean, null or
  number (it does not start with a digit, `+`, `-` or `.`, and is not `y`,
  `n`, `yes`, `no`, `on`, `off`, `true`, `false`, `null` or `~` in any case);
  any other changed scalar is recorded as `ambiguous-scalar`, and two
  spellings of one number (`1` and `1.0`) as `same-value`;
- the key is not under a subchart key or `global`, and no packaged subchart
  is opaque at either anchor;
- each anchor's values schema, if any, declares the key or leaves it under an
  open object (otherwise `schema`).

When one key is listed and both defaults are short, the notice text names
the old and the new default. The sources are `values.yaml` at both anchors.
A removed default is never a notice.

What a notice does not say: that a key absent from it is read or unchanged,
or that a value supplied as `null`, or a scalar supplied where the chart
defaults a mapping, keeps the chart's default. Each notice lists at most 64
keys; over that, its keys are recorded as `over-bound`.

## Proof and completeness

For each derived pair the proof lists both anchors (version, `kubeVersion`,
subchart keys, every values key path, every required key, the template
references), the releases of both lines, the `kubeVersion` outcome, every
required key of the later schema with its class (`rule`, `default`,
`null-default`, `already-required`, `inactive-ancestor`, `empty-ancestor`, `subchart`,
`packaged-subchart`, `unexpressible`, `over-bound`), the opaque schema
objects, and every earlier key path with its class for the closed-object
check (declared and open keys are counted, the rest listed). `completeness`
states the counts, and every earlier key path has exactly one class. The
soft facts record, for each notice, every key it considered with its class
(`notice`, `unproven`, `still-read`, `schema`, `subchart`, `unexpressible`,
`over-bound` for keys no longer read; `notice`, `ambiguous-scalar`,
`same-value`, `subchart`, `packaged-subchart`, `schema`, `unexpressible`,
`over-bound` for changed defaults) and the outcome.

## Running and verifying

```
prufyx-maintainer extract run    --extractor helm.values.keda.keda --mirror-state DIR --out OUT [--derived-at 2026-10-11T00:00:00Z]
prufyx-maintainer extract verify --extractor helm.values.keda.keda --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor helm.values.keda.keda --out OUT --expected FILE
prufyx-maintainer extract inventory --extractor helm.values.keda.keda --mirror-state DIR --repo kedacore/charts --commit SHA
```

Outputs, vectors, validity and the code digest work as for the other
extractors (see [tooling.md](tooling.md)). It is a chart extractor: it runs
through `internal/extract/chartrun`, which stamps, checks and writes a run
exactly as the framework does and generates the vectors of chart rules, and
its code digest covers the non-test Go files of `internal/extract`,
`internal/extract/chartrun`, `internal/extract/helmvalues` and
`internal/helmvaluespath` (the shared values reader and member encoding), and
`targets.json`. No other extractor depends on `chartrun` or
`helmvaluespath`, so their code digests do not cover them and do not move
with them. The `oracle` file lists the expected outcome of each pair and
the rules the run must hold (`testdata/oracle-fixture.json` is the fixture's).
