# Custom-resource versions

Many projects ship CustomResourceDefinitions (CRDs). When a release stops
serving a version of one of its custom resources, every manifest that still
uses that version fails to apply after the upgrade. Prufyx records, for each
project that has such CRDs, which custom-resource versions your rendered
manifests use, and checks them against published rules about versions a
release no longer serves.

The rules come from the `crd.version-removal` extractor
([extractors/crd.version-removal.md](extractors/crd.version-removal.md)) and
reach users only through the knowledge gate. The embedded knowledge of this
release holds no such rule yet, so today every check below answers `UNKNOWN`
(exit 11) and says that no published rule reads the set.

## Projects

The projects, and the API groups their CRDs define, are a reviewed table
compiled into Prufyx. Each group is cited from the project's CRD manifest at a
pinned commit:

| Project | Fact | API groups |
| --- | --- | --- |
| `argo-cd` | `component.argo_cd.custom_resource_versions_set` | `argoproj.io` |
| `istio` | `component.istio.custom_resource_versions_set` | `extensions.istio.io`, `networking.istio.io`, `security.istio.io`, `telemetry.istio.io` |
| `strimzi` | `component.strimzi.custom_resource_versions_set` | `core.strimzi.io`, `kafka.strimzi.io` |

The extractor reads CRDs for these projects and for others whose sets are not
registered yet (cert-manager, Cilium, Crossplane, KEDA, Kuma, Kyverno,
Longhorn, Rook, Velero): their rules are refused by the knowledge gate until
the project and its API groups join this table. Adding a project to the table
is a reviewed code change.

`argoproj.io` is shared upstream: Argo CD, Argo Workflows, Argo Rollouts and
Argo Events all define CRDs in it. The catalog project `argo-cd` stands for the
whole Argo project, so the group is listed once, for `argo-cd`, and objects of
the other Argo components (a `Rollout`, a `Workflow`) join the `argo-cd` set.
That cannot cause a wrong answer while the rules name only Argo CD's own
kinds. If another project ever listed `argoproj.io` too, the group would become
shared in the table: every `argoproj.io` object would then belong to no set
and keep every set incomplete, so a removed Argo CD version would no longer
block. Prufyx would first have to assign such objects by group and kind.

## What is recorded

For one project and one upgrade (`--from`, `--to`), Prufyx reads your
rendered manifests (YAML or JSON, one or more documents, `v1` `List`s
flattened one level) and records the set of `group/version/Kind` of every
object whose API group the table lists for that project, for example
`kafka.strimzi.io/v1beta2/Kafka`. It is a set fact of the target side of the
upgrade.

- An API group is a **Kubernetes group** when it is the core group, has no dot
  (`apps`, `batch`) or ends in `.k8s.io`. Those objects are never part of a
  custom-resource set (scan checks them against Kubernetes knowledge).
- Every other group is a **custom-resource group**. An object of such a group
  joins a project's set only when the table lists its group for that project
  and for no other project. A group the table does not list (your own CRDs,
  `cert-manager.io`, `access.strimzi.io`, ...) or lists for two projects is
  never assigned to a project, by name, by suffix or otherwise.

## When the set is complete

A rule blocks when a version it names is in the set, whether or not the set is
complete. It passes only when the set is **complete** and holds none of the
versions it names. The set is complete only when all of these hold:

- you declare that the manifests are the complete set you apply
  (`--custom-resources-complete` for `check cncf`, `--resource-scope-complete`
  or `resourceScopeComplete: true` for `scan`);
- no list in the input is paginated;
- every object of a custom-resource group belongs to a group the table assigns
  to exactly one project. One object of an unknown group keeps every project's
  set incomplete, because it might be a resource of a project the table does
  not yet describe;
- every recorded `group/version/Kind` is at most 128 bytes.

When the documents cannot be read as one apply set (unrendered templates, a
document that cannot be parsed, a document that is not a Kubernetes object, or
an object of a kind other than a `List` that carries a top-level `items`
array: only `List` kinds are flattened, so its items are never read, and the
object itself is left out and never counts), the versions of the project's objects in the documents that were read are
recorded as an incomplete set: a listed version among them still blocks, and
nothing passes. A document that may not be rendered at all (inside a template
action of another document of its file, a conditional subchart or a test of a
raw Helm chart, a Helm test hook; see `scan.md`, "Gaps") is not read for this.
With no such object the set is not recorded. When the
input is empty, or when a project's objects use more than 256 different
`group/version/Kind` combinations, no set is recorded at all and every rule
stays `UNKNOWN`.

## `check cncf`

```sh
umask 077
cat > manifests.yaml <<'YAML'
apiVersion: kafka.strimzi.io/v1beta2
kind: Kafka
metadata:
  name: events
  namespace: kafka
---
apiVersion: kafka.strimzi.io/v1
kind: KafkaTopic
metadata:
  name: orders
  namespace: kafka
YAML
chmod 600 manifests.yaml
./prufyx check cncf --project strimzi --custom-resources manifests.yaml \
  --custom-resources-complete --from 0.51.0 --to 1.0.0 \
  --now 2026-10-04T00:00:00Z
```

With the knowledge of this release:

```
strimzi custom-resource version review
raw input digest: sha256:0d08002f5c498c9ce126e92389518917be4ff0df0130ad7ade4ac6229fb9d0fd
prepared input digest: sha256:90de632e6208586b85dfa4e1e72b80c05d7f885abad0c33910ec32981930e02a
custom-resource set: complete
no published rule reads the strimzi custom-resource version set for 0.51.0 -> 1.0.0; the result stays UNKNOWN
scope: only custom-resource versions named by published rules; no record yet shows those rules name every version the target release stops serving, so this mode never passes (exit 11 at best)
not checked: other custom-resource versions, other changes, stored objects and conversion
scoped result: UNKNOWN
aggregate: UNKNOWN (whole-upgrade compatibility: UNKNOWN; network used: false)
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--project argo-cd\|istio\|strimzi` | A project of the table. Any other project is a usage error. |
| `--custom-resources FILE` | One private file (mode 0600 or stricter, no symlink, at most 1 MiB) of rendered manifests. |
| `--custom-resources-digest SHA256` | Optional `sha256:` digest the file must have; a mismatch exits 3. |
| `--custom-resources-complete` | Declares that the file is the complete set of manifests you apply. Without it nothing passes. |
| `--from`, `--to` | The exact upgrade. |
| `--now RFC3339` | Evaluation time, canonical UTC with whole seconds. Required. |
| `--format human\|json` | Output format (default `human`). |
| `--show-passes` | Lists passed rules instead of counting them. |
| `--require-basis LIST` | Evidence bases whose rules are evaluated, as for every `check cncf` mode. |

Only rules over the project's custom-resource set are evaluated; the
project's other rules need other evidence and are neither run nor reported.
The mode reads embedded knowledge only: `--knowledge-db` and
`--replay-report` are usage errors here.

**This mode never exits 0.** Passing every published rule only says that none
of the versions those rules name is used. It does not show that the published
rules name every version the target release stops serving: a rule may be
withheld or not yet published, and a version that neither release serves, or a
kind that no CRD defines, is named by no rule at all. Until a reviewed
per-release-pair record shows that the published rules are complete for the
pair, the best answer is `UNKNOWN`. Exit codes: 10 a rule blocked, 11
otherwise (including when every rule passed), 2 usage, 3 integrity. With
`--format json` the claims (including `PASS` claims) are printed unchanged;
only the exit code is capped.

The same cap holds on every other route that can evaluate a rule over a
custom-resource version set (`component.<project>.custom_resource_versions_set`),
until that per-release-pair record exists:

- `check cncf --project P --input FILE`, where you write the set by hand,
  with embedded knowledge or with `--knowledge-db`, and its `--replay-report`
  replay: when any evaluated rule reads the set, the exit code is 11 at best,
  never 0. The claims are printed unchanged, and the human output adds the
  line `scope: a rule over a custom-resource version set never makes this
  check pass (exit 11 at best): ...`;
- `check batch`: a CNCF item with such a rule is `UNKNOWN`, never `PASS`, so
  the batch never exits 0 because of it;
- `scan` never reports these projects as covered (see below).

`assess --scope-input` evaluates only the attested community-project corpus,
which has no custom-resource version facts and cannot load a rule over a set,
so it never evaluates such a rule.

The line `custom-resource set:` says whether the set is complete and, if not,
why.

## `scan`

`prufyx scan` evaluates a targeted project of the table (for example
`--from strimzi=0.51.0 --to strimzi=1.0.0`) on one direct hop, over the same
manifests and with the same scope declaration as Kubernetes:

- a version that a published rule says the target no longer serves is a
  finding (`BLOCKED`, exit 10) located at the file, document and object;
- a rule that passes is listed as a passed check, never as coverage;
- the project is never reported as covered, so the answer is never `PASS`
  while it is targeted: no review yet states that the published rules are
  every custom-resource version the target release stops serving. The gap
  `COMPONENT_NOT_COVERED` says that only custom-resource versions were
  checked;
- a missing scope declaration (`DECLARATION_MISSING`), unrendered or unread
  documents, and objects of custom-resource groups no project of the table
  owns (`DOCUMENTS_NOT_EVALUATED`) are named gaps of the project.

A rule covers its exact release pair only: a direct upgrade that skips a
release is a different transition, which no rule decides.

## What is not checked

Installing or upgrading the CRDs themselves, stored objects and their storage
version, conversion webhooks, schema or field changes inside a version,
operators, and anything about objects of groups the table does not list.
