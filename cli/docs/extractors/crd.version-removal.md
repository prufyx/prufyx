# Extractor `crd.version-removal`

Version 2.1.0. Derives `forbid_set_member` rules for custom-resource
versions that a project's release line no longer serves, from the
CustomResourceDefinition manifests the project ships in its repository. It is
deterministic, reads only upstream source pinned by full commit SHA, and
involves no model.

A run reads one repository, so the extractor is registered once per project,
as `crd.version-removal.<project>`; every registration runs the same code and
carries the same version and code digest.

## Projects and paths

The reviewed source table is a data file compiled into the extractor,
`cli/internal/extract/crdversions/targets.json` (schema
`prufyx.io/crd-version-targets/v1`). It is part of the code digest that every
`crd.version-removal.<project>` id shares: any change to it is a new extractor
version, and rules derived by the previous version no longer re-derive. Each
entry names a catalog project, its repository, the prefixes of its release
tags, the first release line a pair may start from, the paths that hold its
rendered CRD manifests, and the reviewed exclusions of the full-tree scan
(below), each with the reason it was accepted and, for chart templates that are
copies of the listed definitions, the flag `copies` that makes the scan check
that claim.

An entry of a project outside the CNCF landscape catalog carries
`"catalog": "community"` (an entry without the field is a CNCF catalog
project; `"cncf"` is not spelled out). Such a project must be a community
project of the reviewed custom-resource table, with the same repository and
name, and neither its slug nor its component may be a CNCF catalog one (see
[../custom-resources.md](../custom-resources.md)). A community target never
attests: the loader refuses `"attest": true` for it, because its line reviews
have no knowledge target yet. Its runs follow every other rule of this
extractor (full-commit citations, full-tree scan, withheld pairs). The
community targets:

| Extractor id | Repository | Release tags | First pair from | CRD manifests |
| --- | --- | --- | --- | --- |
| `crd.version-removal.cluster-api` | `github.com/kubernetes-sigs/cluster-api` | `vX.Y.Z` | 1.9 | YAML files directly in `bootstrap/kubeadm/config/crd/bases`, `cmd/clusterctl/config/crd/bases`, `controlplane/kubeadm/config/crd/bases`, and `config/crd/bases` (to 1.13) or `core/config/crd/bases` (from 1.14) |
| `crd.version-removal.eck-operator` | `github.com/elastic/cloud-on-k8s` | `vX.Y.Z` | 3.0 | `config/crds/v1/all-crds.yaml` |
| `crd.version-removal.gateway-api` | `github.com/kubernetes-sigs/gateway-api` | `vX.Y.Z` | 1.1 | YAML files directly in `config/crd/standard` (the standard channel) |
| `crd.version-removal.kong-ingress-controller` | `github.com/kong/kubernetes-ingress-controller` | `vX.Y.Z` | 3.0 | YAML files directly in `config/crd/bases` |
| `crd.version-removal.kueue` | `github.com/kubernetes-sigs/kueue` | `vX.Y.Z` | 0.15 | YAML files directly in `config/components/crd/bases`, and in `config/components/crd/alpha/bases` when it exists |
| `crd.version-removal.mongodb-kubernetes` | `github.com/mongodb/mongodb-kubernetes` | `X.Y.Z` | 1.8 | YAML files directly in `config/crd/bases` |
| `crd.version-removal.node-feature-discovery` | `github.com/kubernetes-sigs/node-feature-discovery` | `vX.Y.Z` | 0.14 | `deployment/base/nfd-crds/nfd-api-crds.yaml` |
| `crd.version-removal.percona-postgresql-operator` | `github.com/percona/percona-postgresql-operator` | `vX.Y.Z` | 2.6 | YAML files directly in `config/crd/bases` |
| `crd.version-removal.prometheus-operator` | `github.com/prometheus-operator/prometheus-operator` | `vX.Y.Z` | 0.89 | YAML files directly in `example/prometheus-operator-crd` |
| `crd.version-removal.rancher` | `github.com/rancher/rancher` | `vX.Y.Z` | 2.10 | YAML files directly in `pkg/crds/yaml/generated` |

The CNCF catalog targets (the table lists the first ones; `prufyx-maintainer
extract list` lists all):

| Extractor id | Repository | Release tags | First pair from | CRD manifests |
| --- | --- | --- | --- | --- |
| `crd.version-removal.argo-cd` | `github.com/argoproj/argo-cd` | `vX.Y.Z` | 3.0 | YAML files directly in `manifests/crds` |
| `crd.version-removal.cert-manager` | `github.com/cert-manager/cert-manager` | `vX.Y.Z` | 1.16 | YAML files directly in `deploy/crds` |
| `crd.version-removal.cilium` | `github.com/cilium/cilium` | `vX.Y.Z` | 1.15 | YAML files directly in `pkg/k8s/apis/cilium.io/client/crds/v2` and `.../v2alpha1` |
| `crd.version-removal.crossplane` | `github.com/crossplane/crossplane` | `vX.Y.Z` | 1.20 | YAML files directly in `cluster/crds` |
| `crd.version-removal.istio` | `github.com/istio/istio` | `X.Y.Z` | 1.26 | `manifests/charts/base/files/crd-all.gen.yaml` |
| `crd.version-removal.keda` | `github.com/kedacore/keda` | `vX.Y.Z` | 2.16 | YAML files directly in `config/crd/bases` |
| `crd.version-removal.kuma` | `github.com/kumahq/kuma` | `vX.Y.Z`, then `X.Y.Z` | 2.9 | YAML files directly in `deployments/charts/kuma/crds` |
| `crd.version-removal.kyverno` | `github.com/kyverno/kyverno` | `vX.Y.Z` | 1.14 | YAML files anywhere under `config/crds` |
| `crd.version-removal.longhorn` | `github.com/longhorn/longhorn` | `vX.Y.Z` | 1.8 | `deploy/longhorn.yaml` |
| `crd.version-removal.rook` | `github.com/rook/rook` | `vX.Y.Z` | 1.16 | `deploy/examples/crds.yaml` |
| `crd.version-removal.strimzi` | `github.com/strimzi/strimzi-kafka-operator` | `X.Y.Z` | 0.49 | files named `XXX-Crd-*.yaml` in `install/cluster-operator`, and in `install/access-operator` when it exists |
| `crd.version-removal.velero` | `github.com/velero-io/velero` | `vX.Y.Z` | 1.13 | YAML files directly in `config/crd/v1/bases` and `config/crd/v2alpha1/bases` |

In a listed directory, a file whose name contains `crd` (in any case) but
does not match the pattern makes the inventory incomplete: it may hold a
definition the extractor would not read. A listed path must exist at every
release unless it is marked optional (Strimzi's `install/access-operator`).

Only the custom-resource version sets of `argo-cd`, `istio` and `strimzi` are
registered today (see [../custom-resources.md](../custom-resources.md)). The
rules derived for the other projects are correct candidates, but the knowledge
gate refuses them until their set and API groups are added to the reviewed
custom-resource table in a change of their own.

## Release lines and pairs

A **line** is one `major.minor` of a project with at least one final release
tag (`<prefix>X.Y.Z`; release candidates never count). When a release is tagged
under both prefixes of a project they must name one commit, or every pair of
that line is withheld. A **pair** is two consecutive lines in version order (so
a major release follows the last minor of the previous major, and a skipped
minor number is skipped), starting from the line in the table; it is named by
the first final release of each line (normally `X.Y.0`), which is the rule's
anchor transition. A repository with an unacknowledged tag alarm yields no
pairs.

For each pair the extractor reads **every final release of both lines**.

## What it reads at each release

Through the offline factory mirror (or a fixture tree), never the network.

- **CRD manifests.** Every listed file, and every matching file in a listed
  directory, is read in full and decoded in a strict YAML subset: anchors,
  aliases, merge keys, custom tags, non-string, empty or duplicate keys are
  refused, as are documents nested deeper than 128 levels, over 4 000 000
  nodes, over 1 024 documents, or files over 8 MiB. Template syntax (`{{`)
  makes the file unreadable. Documents of other kinds are counted and
  otherwise ignored.
- **Each `apiextensions.k8s.io/v1` CustomResourceDefinition**: its name,
  group, kind, plural and scope, and for every entry of `spec.versions` the
  name, `served` and `storage` flags and the lines of the entry and of its two
  flags.
- **The whole repository tree (full-tree scan).** Every directory is listed
  (none is skipped), and every file outside the listed paths of these kinds is
  read: `*.yaml`, `*.yml`, `*.json` and files named `Kustomization`; template,
  jsonnet and cue sources (`*.tmpl`, `*.tpl`, `*.gotmpl`, `*.jsonnet`,
  `*.libsonnet`, `*.cue`, `*.j2`, `*.jinja`, `*.jinja2`); and Go sources whose
  path contains `crd` (in any case), except `_test.go` files. A packaged Helm
  chart (`*.tgz` in a directory named `charts`) is not read and is recorded as
  unsupported. YAML and JSON files that contain the word
  `CustomResourceDefinition` anywhere, Helm `Chart.yaml` files and
  kustomizations are decoded in the strict subset; a definition is found
  whatever its YAML form (block or flow style, the value of `kind` on the next
  line). Each file is placed in one of three **locations**: the open tree; a
  **default-excluded directory** (a path segment named `test`, `tests`,
  `testdata`, `_testdata`, `e2e`, `example`, `examples`, `vendor` or
  `third_party`), whose content a project does not normally install; or a
  **reviewed exclusion** of the table. Each file with CRD-like content, and each
  file that names another repository's definitions, is classified:

  | Class | Meaning |
  | --- | --- |
  | `copy` | every definition in it is in the inventory with the same versions and `served` flags |
  | `schema-patch` | a kustomization whose only mentions of the kind are patch targets, each patch a JSON 6902 list whose every operation path lies under `/spec/versions/N/schema/` or metadata labels and annotations |
  | `conflict` | it defines a CRD of the inventory with other versions or `served` flags |
  | `extra` | it defines a CRD that is not in the inventory |
  | `reference` | it holds the kind as a value (a nested object, a field, a manifest embedded in a string) but defines none at the top level, and is not a schema-only kustomization; a file that only mentions the word in a comment or a description is not a finding |
  | `unread` | it is templated, not strictly decodable or over the bounds and holds the kind as the value of a `kind` key (on the same line or the next); or a submodule |
  | `unsupported` | a template, jsonnet or cue source that holds the word, Go code that builds a definition as a composite literal (`CustomResourceDefinition{ObjectMeta: ...}`, or of its spec, names or versions), or a packaged Helm chart |
  | `external` | a Helm `Chart.yaml` with a dependency whose `repository` is another repository (`https://`, `oci://`, an alias such as `@repo`; not a local `file://` path or none), or a kustomization with a remote resource, component or base (a URL, `github.com/...`, `git@...`, `?ref=`) |
  | `excluded` | a file under a reviewed exclusion that does not declare copies, whose content is recorded (path, sha256, the definitions it holds) |
  | `excluded-unread` | the same, when its content could not be read |
  | `exclusion-void` | a reviewed exclusion that an install surface refers to at this release (see below); it blocks attestation |

  The effect depends on the class and the location:

  - `copy` and `schema-patch`: none, anywhere.
  - `conflict` in the open tree: the pair is withheld when the release is a
    pair's first release; otherwise the pair's rules hold for the anchor pair
    only.
  - `unread` or `unsupported` in the open tree, and `conflict`, `unread` or
    `unsupported` among declared copies: at the later line's first release the
    pair's rules are withheld (a version they forbid may still be served
    there); at another release of the later line the rules hold for the anchor
    pair only.
  - every other class in the open tree or among declared copies, and every
    class but `copy` and `schema-patch` under a default-excluded directory:
    the pair is not attestable.
  - `excluded` and `excluded-unread`: recorded; the pair stays attestable. An
    `excluded-unread` file keeps a definition from being established as gone,
    unless it also lies in a default-excluded directory (a test-fixture entry
    such as `test/e2e/manifests/`).
  - A reviewed exclusion with `copies` (chart templates of the listed
    definitions) is checked: each file's template directives are removed (a
    line that holds only a directive is dropped, a key whose whole value is an
    expression followed by more indented lines keeps those lines, any other
    expression becomes a placeholder, and an expression left open across lines
    makes the file unread) and the result must define only listed
    CRDs with the same versions and `served` flags. A file that serves other
    versions is a `conflict`, one that defines another CRD is `extra`, and one
    that cannot be read is `unread`.

  **Reviewed exclusions carry evidence and are guarded.** Every entry of the
  table names its repository, the path (a directory prefix ending in `/`, one
  file or a pattern), the reason the files are not installed and the evidence a
  reviewer read, and the claim must hold at every release of the window. An
  entry that is not a declared copy may not lie under a chart, deploy,
  deployment, install or installation directory, below a `config/crd` or
  `config/crds` directory, or below a top-level `manifests` directory (the
  loader refuses it), and never covers a listed path. At each release the
  **install-surface guard** checks the part of the claim a program can: an
  entry with files at the release is void for that release when
  - the entry lies under a Helm chart (a directory with a `Chart.yaml`);
  - a kustomization (resources, bases, components, patches, generators, any
    path-like word, followed from every kustomization outside the excluded
    paths through the kustomizations they name) or a Helm `Chart.yaml` or
    `requirements.yaml` (local `file://` dependencies) refers to a path under
    it;
  - a Makefile command line of a target that is not a test target
    (`test`, `e2e`, `lint`, `check`, `verify`, `conformance`, `integration`,
    `bench`, `smoke`, `fuzz`, `coverage`, `unit`) runs `kubectl`, `kustomize`,
    `helm` or a similar tool on a path under it, directly or through a
    variable;
  - a document (`*.md`, `*.mdx`, `*.rst`, `*.adoc`, `*.txt`, outside `vendor`,
    `third_party` and `node_modules`) has a command line that runs such a tool
    on a path under it;
  - a Go package in a directory above it embeds a file under it (`//go:embed`).

  A void entry is treated like a default-excluded directory at that release,
  with the location `void: <entry>`: its files are classified (Go sources
  under it are read too), block attestation and never withhold a pair or
  narrow its rules, but an opaque file there still keeps a definition from
  being established as gone. A finding of class `exclusion-void` names the
  referrer, so the release, and every pair that reads it, is not attestable. Not followed: symbolic links, shell scripts, CI configuration and
  Go code that opens a path at run time. Declared copies are not guarded: they
  are install surfaces by nature and are checked file by file instead.

  A file with the same git blob id (and kind) as one already read is not read
  again; what the scan concludes from the bytes never depends on the path they
  were read at, so the result is the same at any read concurrency.

## What it claims

A version is **no longer served** in the later line when some release of the
earlier line lists it with `served: true` and no release of the later line
serves it (it is absent, or listed with `served: false`). For each CRD with
such versions the extractor emits one rule:

- id `<project>.crd-version-removal.<crd name>.<from>-to-<to>` (the anchors),
  where the CRD name has each `-` written as `--` and each `.` as `-`, and the
  versions have dots as hyphens; two rules of one pair that would still share
  an id withhold the pair;
- operator `forbid_set_member` over the proposed-side set fact
  `component.<project>.custom_resource_versions_set` (for Argo CD
  `component.argo_cd....`), whose members are `group/version/Kind`; the rule
  forbids the versions no longer served;
- subject: the project's catalog component and the anchor transition, and —
  when the rule holds for both whole lines (below) — a **range** over them:
  - consecutive minor lines `M.m-1 -> M.m`: from `[M.(m-1).0, M.m.0)`, to
    `[M.m.0, M.(m+1).0)`, bounds `PREVIOUS_MINOR_LINE`, `REMOVED_IN_RELEASE`
    (twice) and `TARGET_SERIES`, so the engine knows the release boundary;
  - a new major or skipped minor numbers: each whole line, bounds
    `UPGRADE_FROM_SERIES` (twice) and `TARGET_SERIES` (twice);
- next action: `change apiVersion of <Kind> to <group>/<version> before
  upgrading to <To>`, naming the highest version the later anchor serves, or
  `migrate <Kind> objects before upgrading to <To>` when it serves none. When a
  removed version was the CRD's storage version at any release read (see
  `storageHistory`), objects may still be stored in it and it stays in the
  CRD's `status.storedVersions`, and an API server refuses a definition that
  drops a stored version; the next action then says so first: `migrate stored
  <Kind> objects to <version> and remove <removed versions> from
  status.storedVersions, then change apiVersion to <group>/<version> before
  upgrading to <To>` (or the same without a replacement version);
- sources (each with the whole-file sha256 of the bytes read):
  `crd-versions-<release>`, the lines of the removed version entries at the
  earlier anchor (or, for a version only a later earlier-line release served,
  at the highest such release); and either `crd-<to>`, the whole CRD file at
  the later anchor when a version is absent from it, or
  `served-false-<version>-<to>`, the `served: false` line of each version the
  later anchor still lists. Every range bound cites one of them.

A rule holds for **both whole lines** only when every release of both lines
was read completely, no release holds a conflicting copy, every CRD keeps its
group and kind, no version that some earlier-line release serves is served by
some later-line releases and not by others, no release of the later line drops
a definition its first release holds, and no release of the later line holds an
unread or unsupported CRD source (or a declared copy serving other versions). Otherwise the pair's rules are
derived from the two anchors only, carry no range, and match only the anchor
transition. (Cilium 1.20.2 serves CiliumNodeConfig `v2alpha1` again after 1.20.0
and 1.20.1 dropped it, so that rule holds for 1.19.0 -> 1.20.0 only.)

A CRD that the earlier line defines and the later anchor defines nowhere — not
under the listed paths, and with a complete scan in which no file defines it
and every CRD-like file outside the default-excluded directories (and outside the reviewed exclusions that do not lie in one) was read — is recorded under `definitionsRemoved` and is
**not** a rule: whether the old definition is kept (`kubectl apply`, Helm
`crds/`) or deleted with every object of it (Helm templates, Argo CD or Flux
pruning) depends on the install method and is not established. Otherwise the
definition may have moved, and the pair is withheld. A CRD that the later
anchor defines and a later release of its line defines nowhere is recorded the
same way (with the releases that lack it); the pair's rules then hold for the
anchor pair only.

Each rule's test vectors (blocked, pass-complete, unknown-incomplete) are
evaluated through the engine before anything is written.

## Proof recorded in the manifest

For every pair, `manifest.json` records under `pairs[].proof`:

- `target` and `factId`;
- `from` and `to`, the complete inventory of each anchor: `tag`, `commit`,
  `complete`, `problem` (when incomplete), `paths` (each listed path: `file`,
  `directory` or `missing`, files read and directory entries ignored), `files`
  (path, `sha256:` digest of the whole file, size, lines, documents, CRDs,
  other documents), `crds` (each with `name`, `group`, `kind`, `plural`,
  `scope`, `path`, `document`, `startLine`, `versionsLine`, `storageVersion` and
  `versions`, each with `name`, `served`, `storage`, `startLine`, `endLine`,
  `servedLine`, `storageLine`) and `scan` (`complete`, `problem`, `files` read
  and how many of them lie under a default-excluded directory
  (`defaultFiles`) or a reviewed exclusion (`excludedFiles`), the default
  segments and reviewed entries that hold a file (`exclusions`), the kinds of
  files the scan does not read (`notRead`), the `copies`, and every other
  finding with `path`, `sha256`, `class`, `location`, `crds`, the members its
  definitions serve (`served`) and `detail`);
- `lines`: for each of `from` and `to`, the `line` and each release (`tag`,
  `commit`, `complete`, `problem`, `crds`, the served members `added` and
  `dropped` relative to the line's first release, `scanClean` and
  `scanFindings`); `lineWide`, and `notLineWide`, why the rules hold for the
  anchor pair only;
- `removals`: each version no longer served (`crd`, `member`, `version`,
  `reason` `absent` or `unserved`, `fromTag`, `fromPath`, `fromStartLine`,
  `fromEndLine`, `toPath`, `toServedLine`, 0 when absent, and `wasStorage`);
- `storageChanges`: each CRD whose storage version differs between the anchors
  (`crd`, `from`, `to`);
- `definitionsRemoved`: each CRD a release of the later line defines nowhere
  (`crd`, the `members` served before, `fromTag` and `fromPath` of the latest
  release before that defines it, and `absentAt`, the later-line releases
  without it);
- `storageHistory`: for each CRD, every storage version it has at the releases
  read;
- `unlistedRemovals`: each version that a definition outside the listed paths
  (an `extra` file, such as Rook's `deploy/examples/csi-operator.yaml`) serves in
  the earlier line and that no file of the later line serves (`member`,
  `fromTag`, `path`); recorded, never a rule;
- `completeness`: `declared` (every listed path read completely at every
  release of both lines), `scan` (the full-tree scan clean at every release),
  `lineWide`, `hop` (`previous-minor` for `M.(m-1) -> M.m`, `major` or
  `skipped-minor`), `attestable` (declared, scan and line-wide, a
  `previous-minor` hop, and no removed definition) and the `reasons` when not.

`completeness.attestable` is the account a line attestation of the later line
rests on (see below). It means
complete for the repository's own files at every release of both lines, as the
scan reads them: CRDs that come from other repositories (Helm chart
dependencies, remote kustomize resources) make the pair not attestable when the
scan sees them, and CRDs from release assets, from sources the scan does not
read (`notRead`) or installed by code at run time are not established.

## Line attestations

From version 2.1.0 the extractor attests lines for the fact family
`crd.custom_resource_versions` (see [../line-attestations.md](../line-attestations.md)).
For a derived pair it writes one attestation of the later line exactly when:

- `completeness.attestable` holds (every release of both lines read
  completely, a clean full-tree scan at each, rules over both whole lines, no
  removed definition);
- the later line is the next minor line of the same major (a new major or a
  skipped minor number is not attested: the family's hop shape is one minor
  line);
- the target has `"attest": true` in `targets.json`, which a test pins to the
  CNCF catalog projects of the custom-resource table (the projects whose set
  fact is registered and whose line reviews the family admits): today Argo
  CD, Istio and Strimzi. A community target never attests.

The attestation lists exactly the pair's rules (empty for a quiet line),
names in `releases` every final release of both lines with the commit its tag
pointed at, and cites one CustomResourceDefinition manifest at each first
release. It has the rules' provenance and lease. Otherwise the manifest records
`"attestation": {"status": "not-attested", "reason": ...}` for the pair.
`run` writes the attestations to `attestations.json`, which `verify` covers;
the knowledge gate admits one only by re-deriving it byte for byte.

These field names are stable within major version 2.

## What it never claims

- A removal when either anchor cannot be read completely (any listed path
  missing that is not optional, a listed directory without a matching file, a
  templated or not strictly decodable file, a `List` document, a CRD of an API
  version other than `apiextensions.k8s.io/v1` or incomplete — no versions,
  flags that are not booleans, not exactly one storage version, a name that is
  not `<plural>.<group>` — two documents defining the same CRD or kind, more
  than 512 CRDs or 64 versions of one CRD), when a CRD changes group or kind,
  when an anchor holds a conflicting copy, or when a definition disappears
  without a clean scan. The pair is then withheld: no rule, and the manifest
  says why.
- Anything about storage versions (recorded only, and named in the next
  action), stored objects, conversion webhooks, schema or field changes inside
  a version, kustomize patches other than schema-only JSON 6902 patches, CRDs
  that are only shipped templated (Helm charts) or only as release assets, or
  CRDs other than those under the listed paths.
- Anything about the definitions of another repository: a Helm chart
  dependency or remote kustomize resource is found, never read.
- That a repository holds no other definition where the scan does not look:
  files of other kinds, Go sources whose path does not contain `crd` (or that
  build a definition in another way than a composite literal), symbolic links,
  or CRDs that a program generates or installs at run time.
- Anything about a removed definition (recorded only).
- That an upgrade is safe: a PASS from these rules only says that a complete
  declared set of custom-resource versions holds none of the versions no
  longer served.

`component.<project>.custom_resource_versions_set` is registered for the
projects of the custom-resource table, and `check cncf --custom-resources` and
`scan` declare it from rendered manifests (see
[../custom-resources.md](../custom-resources.md)). No rule is shipped yet. They
are the first set rules of the CNCF pack, so the first change that publishes
any of them raises the pack's schema level as well; the knowledge gate never
admits a schema change on its own, so that change is reviewed.

## Running and verifying

```
prufyx-maintainer extract run    --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT [--derived-at 2026-10-04T00:00:00Z] [--concurrency N]
prufyx-maintainer extract verify --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor crd.version-removal.strimzi --out OUT --expected FILE
```

`run` writes `candidates.json`, `vectors.json`, `manifest.json` and `reads/`,
as for every extractor; `--concurrency` only bounds parallel reads during the
scan. The mirror must hold every file the scan reads at every release of the
lines; a run that misses one names it under `--wants-out` and exits 3.
`verify` re-derives from the pinned bytes with the recorded `derivedAt` and
fails unless every output file is byte-identical. The code digest is sha256
over the sorted lines `<dir>/<file> NUL <sha256> LF` of the non-test Go files
and the reviewed `*.json` data files a source set embeds next to its code, of
`internal/extract` and `internal/extract/crdversions` (so `targets.json` is
covered); the manifest lists them.

`oracle` compares a run with an expected-results file:

```json
{
  "removals": [{"from": "0.51.0", "to": "1.0.0", "member": "kafka.strimzi.io/v1beta2/Kafka", "reason": "absent"}],
  "rules": [{"name": "a reviewed rule", "from": "0.51.0", "to": "1.0.0", "members": ["kafka.strimzi.io/v1beta2/Kafka"]}],
  "storageChanges": [{"from": "0.51.0", "to": "1.0.0", "crd": "kafkas.kafka.strimzi.io", "fromStorage": "v1beta2", "toStorage": "v1"}],
  "pairs": [{"from": "1.0.0", "to": "1.1.0", "status": "derived", "removals": 0, "lineWide": true, "attestable": true}]
}
```

Every listed removal must be derived with the same reason and forbidden by a
rule; every rule's members must be forbidden on its transition; every listed
storage change must be recorded; every listed pair must have the given status
and, when given, number of removals, `lineWide` and `attestable`. When removals
(or storage changes) are listed, any other one the run derives is reported as
`EXTRA`. The exit code is 1 when there is any disagreement.

## Changes from version 2.0.0

Version 2.1.0 adds the line attestations above and the `attest` member of
`targets.json`. Rules, vectors and candidates are unchanged except for the
extractor version and code digest.

## Changes from version 1

Version 1.0.0 read only the two `X.Y.0` tags of a pair, had no range and no
full-tree scan, kept its three targets in Go, withheld every pair in which a
CRD left the listed paths, and refused Argo CD's definitions (nested deeper
than 32 levels). Version 2.0.0 reads every release of both lines, adds the
range, the scan, optional and recursive paths, two tag prefixes, the data-file
target table and nine projects; its rules have new evidence (version and code
digest) and ranges, so rules of version 1 do not re-derive.
