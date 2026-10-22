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
release holds such rules for some projects (the example below uses Strimzi).
For a pair without a published rule the check answers `UNKNOWN` (exit 11).

## Projects

The projects, and the API groups their CRDs define, are a reviewed table
compiled into Prufyx (`internal/customresources/table.json`). Each group is cited from the project's CRD manifest at a
pinned commit. A project is either a project of the CNCF landscape catalog
that Prufyx embeds (`CNCF`) or a project of the **community catalog**
(`community`), see below. The list of projects, with the fact and the API
groups of each, is generated from that file:
[generated/custom-resource-projects.md](generated/custom-resource-projects.md).

### Community catalog

A community project is a project outside the CNCF landscape catalog that
Prufyx embeds, listed here because it publishes versioned CRD manifests.
Prufyx asserts nothing about its CNCF status: some community projects are
subprojects of Kubernetes SIGs (Gateway API, Cluster API, Kueue, Node Feature
Discovery), others are vendor projects. Each community project carries its own
reviewed provenance: the upstream repository its component names and that
repository's licence, cited from the licence file at a full commit. The
community projects and their provenance are listed in
[generated/custom-resource-projects.md](generated/custom-resource-projects.md#community-catalog).

For a community project the custom-resource version set is registered and
its API groups are attributed to it (so its objects no longer keep other
projects' sets incomplete). The knowledge can carry rules for it, apart from
the CNCF projects': the rule pack has a pack schema level for the entries of a
community project, the knowledge database has a per-project target for it
(`knowledge/community/projects/<project>.v1.json`, listed in the same index,
which then has schema `v3`), and `check cncf --custom-resources` and `scan`
accept it, labelled everywhere as the community catalog (a note in every scan
output format, `catalog` in the JSON report and the inventory, a `catalog`
line in the `check cncf` output). The embedded knowledge holds no rule of a
community project yet; while it holds none, every route refuses the project
with the message below, and nothing else changes. A community rule may be
only a `forbid_set_member` rule over the project's own set fact; a community
project is never in the CNCF catalogue, its counts or the corpus
attestation. It can carry line reviews like a CNCF project: every row of the
table, whatever its catalog, is a member of the family of line reviews, and
its target attests when the target file sets `attest` (a target file of a
community project names `"catalog": "community"`). Its line attestations
are stored in the CNCF rule pack beside its rules, under the same proofs,
caps and expiry as any other record; coverage counts them in the separate
community total, never in the CNCF totals. The extractor derives its rules
for the maintainers, under the same rules as for CNCF projects (full commit
citations, whole-tree scan, withheld pairs).

The extractor reads the CRDs of every project of the table. The knowledge gate
refuses rules over the version set of a project that is not listed here, until
the project and its API groups join this table; adding a project to the table
is a reviewed code change. So far the extractor attests
release lines (the line reviews that `scan` reports) only for `argo-cd`,
`istio` and `strimzi`; for the other projects of the table the fact is
registered and rules over it are admitted, but no release line is attested yet.
An API group that a project shares with others is not listed: for example
the multicluster API group `multicluster.x-k8s.io` that Karmada and Antrea
both ship, the Cluster API provider groups (`bootstrap`, `controlplane`,
`addons`, `ipam` and `infrastructure.cluster.x-k8s.io`, which other providers
define CRDs in too), and `postgres-operator.crunchydata.com`, which the Percona
Operator for PostgreSQL ships as a fork of Crunchy Data's operator. `access.strimzi.io` is not listed either.

### Groups in Kubernetes namespaces

The Kubernetes project reserves `k8s.io`, `x-k8s.io` and `kubernetes.io` and
their subdomains for its own APIs and those of its SIG subprojects. A group in
these namespaces may be served by kube-apiserver, defined by one SIG
subproject's CRDs, or implemented by several projects, so the table lists such
a group only through a reviewed ownership record: the group, the one upstream
repository whose CRDs define it, the project of the table that is that
repository, and the reason. The table refuses a reserved group without a
record, a record for another project or repository, a group that two projects
list, and a record that no project lists. The reviewed records, with their
reasons, are listed in
[generated/custom-resource-projects.md](generated/custom-resource-projects.md#groups-in-reserved-namespaces).

Every other `*.k8s.io` group stays a Kubernetes group (for example
`snapshot.storage.k8s.io` and `topology.node.k8s.io`, which several projects
ship, and `scheduling.sigs.k8s.io`), and every other reserved group belongs to
no project.

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
  (`apps`, `batch`) or ends in `.k8s.io` and has no reviewed ownership record
  (above). Those objects are never part of a custom-resource set (scan checks
  them against Kubernetes knowledge). A `*.k8s.io` group with a record, such
  as `gateway.networking.k8s.io`, is a custom-resource group of its owner:
  scan does not check its objects against the list of APIs Kubernetes serves,
  unless that list names the group, in which case they are checked against it
  too.
- Every other group is a **custom-resource group**. An object of such a group
  joins a project's set only when the table lists its group for that project
  and for no other project. A group the table does not list (your own CRDs,
  `monitoring.coreos.com`, `access.strimzi.io`, ...) or lists for two projects is
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
  --now 2026-10-20T00:00:00Z
```

With the knowledge of this release:

```
BLOCKED  1 must fix · 0 undecided · 9 passed     strimzi 0.51.0 -> 1.0.0, 10 reviewed rules

MUST FIX (1)
  Strimzi 1.0.0 no longer serves version v1beta2 of Kafka (CustomResourceDefinition kafkas.kafka.strimzi.io), which 0.51.0 served
    forbidden members present: kafka.strimzi.io/v1beta2/Kafka
    fix: migrate stored Kafka objects to v1 and remove v1beta2 from status.storedVersions, then change apiVersion to kafka.strimzi.io/v1 before upgrading to 1.0.0

custom-resource set: complete
scope: only custom-resource versions named by published rules for this exact pair; check does not read line reviews, so this mode never passes (exit 11 at best); prufyx scan reports what a line review decides
not checked: other custom-resource versions, other changes, stored objects and conversion
Whole upgrade: not proven. This report evaluated only 10 reviewed rules.
2 cited upstream sources (show with -v). 9 passed rules (--show-passes). Knowledge: embedded cncf-2026-09-13.8. No network used.
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--project PROJECT` | A project of the table: a CNCF catalog project, or a community catalog project for which the embedded knowledge holds a rule (the output then names the community catalog). A community project without one, and any other project, is a usage error. |
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
kind that no CRD defines, is named by no rule at all. The record that shows
the published rules are complete for a release line is a line review (a line
attestation of the family `crd.custom_resource_versions`, see
[line-attestations.md](line-attestations.md)); `check` routes do not read
line reviews, so the best answer here is `UNKNOWN`. Exit codes: 10 a rule blocked, 11
otherwise (including when every rule passed), 2 usage, 3 integrity. With
`--format json` the claims (including `PASS` claims) are printed unchanged;
only the exit code is capped.

The same cap holds on every other route that can evaluate a rule over a
custom-resource version set (`component.<project>.custom_resource_versions_set`):

- `check cncf --project P --input FILE`, where you write the set by hand,
  with embedded knowledge or with `--knowledge-db`, and its `--replay-report`
  replay: when any evaluated rule reads the set, the exit code is 11 at best,
  never 0. The claims are printed unchanged, and the human output adds the
  line `scope: a rule over a custom-resource version set never makes this
  check pass (exit 11 at best): ...`;
- `check batch`: a CNCF item with such a rule is `UNKNOWN`, never `PASS`, so
  the batch never exits 0 because of it;
- `scan` never reports these projects as covered; it reads line reviews and
  then decides the custom-resource version family on a hop, and nothing else
  (see below).

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
  while it is targeted, with or without a line review: scan checks nothing
  else about the project. The gap `COMPONENT_NOT_COVERED` says that only
  custom-resource versions were checked;
- a missing scope declaration (`DECLARATION_MISSING`), unrendered or unread
  documents, and objects of custom-resource groups no project of the table
  owns (`DOCUMENTS_NOT_EVALUATED`) are named gaps of the project.

A rule covers its exact release pair, or the whole lines its range names; a
direct upgrade outside them is a different transition, which no rule decides.

### Line reviews of custom-resource versions

A line review states that the rules it lists are every rule of the family
`crd.custom_resource_versions` for one project and release line, and names
every release of that line and of the line before it that its derivation
read. The `crd.version-removal` extractor (2.1.0 and later) derives one for a
line when it read every release of both lines completely, scanned the whole
repository at each, found its rules hold for both whole lines, and found no
definition removed; only projects of the table above are reviewed.

With a current review of the target line, scan decides the family on the hop
when all of these hold:

- the hop goes from a release of the previous minor line of the same major
  to a release of the reviewed line, and the review read both exact releases
  (a release published after the review is not covered: the gap
  `LINE_NOT_ATTESTED` names it);
- the review's evidence basis is one `--require-basis` admits;
- the manifests' set for the project is complete (`--resource-scope-complete`,
  every object of a custom-resource group attributed);
- every listed rule decided the hop, and every rule of the family on that
  line that overlaps the hop is listed;
- every rule that applies to the hop decided it, listed or not.

The hop then carries a family result, `PASS` or `BLOCKED`, in JSON
(`hops[].families[]`, with the family, the line, the basis and the family's
scope) and in the human and Markdown output. The family result is the
decision: `hops[].attestation` names the review the scan found for the target
line even when it did not apply, so a JSON consumer reads `families[]`, not the
presence of `attestation`.

```
  strimzi 0.50.1 -> 0.51.0: PASS within crd.custom_resource_versions only (line 0.51 attested complete, mechanical evidence): no manifest uses a version that strimzi 0.51.0 stops serving
    scope: the custom-resource versions (group/version/Kind) that the project's own CustomResourceDefinitions serve; not schemas, conversion, stored versions, other projects' CustomResourceDefinitions or anything else about the project; nothing else about strimzi is checked
```

A family result never makes the hop `COVERED`, the project covered, or the
scan pass: the answer stays `UNKNOWN` (exit 11), or `BLOCKED` (exit 10) when a
listed rule blocks. A review that exists but does not apply (not current,
basis left out, a hop that skips or stays within a line, a release the review
did not read, a listed rule that does not decide the hop, an unlisted rule)
is a named `LINE_NOT_ATTESTED` gap of the hop. Without a review of the target
line, the hop is evaluated as before.

## Guarding the table and the targets

The table (`internal/customresources/table.json`) and the version targets
(`internal/extract/crdversions/target-*.json`) decide whether a custom resource
version can be attested. Removing a row or narrowing a target turns an answer
of `UNKNOWN` into a pass, so a change to them is checked by
`prufyx-maintainer target-check` (`make targets-check`, `make
targets-check-citations`), which does not depend on the knowledge gate.

`target-check offline [--base-ref <git revision>]` needs no network:

- every cited source is a `github.com` blob URL whose ref is a full 40-digit
  commit (never a tag or a branch), with a plain repository path, in the
  project's own repository (or, for a target that moves its definitions, the
  repository it names);
- no group is claimed by two projects, a target's pins are full commits, and a
  target agrees with its table row (catalog, repository, component, fact
  project);
- every table project has a target file or a reason in `noTarget` of
  `internal/customresources/guard.json`, and a `noTarget` entry for a project
  that has a target is refused.

With `--base-ref`, the same files at that revision are compared with the
working tree. A removed project, a removed group, a removed ownership record, a
removed target, and a narrowed target (a higher `minFrom`, a dropped tag
prefix, a dropped or changed path, a path made optional, a dropped attestation,
channel or remote pin, a new or weakened exclusion) and a changed identity (a
project's or target's component, repository, catalog or fact project, the
repository of a group source or licence source, the owner or repository of an
ownership record) each need an entry in `removals` of
`guard.json` that the same change adds: its `kind` (`project`, `group`,
`reserved`, `target`, `target-narrowed`, `identity`), `project`, `detail` (the group, the
record name, or the narrowing as the check prints it, such as `minFrom:1.16`) and
a `seq` and a `reason` of 12 to 300 characters. The list only grows. `seq`
counts the entries of the same kind, project and detail from 0: removing
something again after it was restored needs the next number. An entry that is
already at the base revision does not justify a later removal, an entry that
matches no change is refused, and an entry that was deleted is refused, so an
approval cannot be placed ahead of the change or used twice. A base revision
git cannot resolve is an error, not a pass.

`target-check citations` is the network check: every table source and each
community licence source is a commit of its repository (a tag object is
refused) that is a tag commit or in the default branch history, and its path
exists at that commit; each pinned commit of a remote target holds the
`kustomization.yaml` its directory names. It runs the revision, reachability
and fetch checks of `prufyx-maintainer rule verify-citations`. No source
declares a content digest today; a digest, when one is added, is compared like
a rule's `contentDigest`. Exit codes: 0 pass, 1 a finding, 2 a usage or I/O
error.

## What is not checked

Installing or upgrading the CRDs themselves, stored objects and their storage
version, conversion webhooks, schema or field changes inside a version,
operators, and anything about objects of groups the table does not list.
