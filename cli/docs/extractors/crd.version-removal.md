# Extractor `crd.version-removal`

Version 2.0.0. Derives `forbid_set_member` rules for custom-resource
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
rendered CRD manifests, and the parts of the repository the full-tree scan
(below) skips, each with the reason it was accepted.

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
- **The whole repository tree (full-tree scan).** Every `*.yaml`, `*.yml` and
  `*.json` file outside the listed paths is read and searched for the
  `CustomResourceDefinition` kind, except in directories named `test`, `tests`,
  `testdata`, `_testdata`, `e2e`, `example`, `examples`, `vendor` or
  `third_party` (a listed path inside one, such as Rook's
  `deploy/examples/crds.yaml`, is still read) and in the reviewed exclusions
  of the table. Each file that names the kind is classified:

  | Class | Meaning | Effect |
  | --- | --- | --- |
  | `copy` | every definition in it is in the inventory with the same versions and `served` flags | none |
  | `schema-patch` | a kustomization whose only mentions of the kind are patch targets, each patch a JSON 6902 list whose every operation path lies under `/spec/versions/N/schema/` or metadata labels and annotations | none |
  | `conflict` | it defines a CRD of the inventory with other versions or `served` flags | the pair is withheld when the release is a pair's first release; otherwise the pair's rules hold for the anchor pair only |
  | `extra` | it defines a CRD that is not in the inventory | the pair is not attestable |
  | `reference` | it names the kind but defines none (and is not a schema-only kustomization) | the pair is not attestable |
  | `unread` | templated, not strictly decodable, over the bounds, or a submodule | the pair is not attestable |

  A file with the same git blob id as one already read is not read again.

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
  `migrate <Kind> objects before upgrading to <To>` when it serves none;
- sources (each with the whole-file sha256 of the bytes read):
  `crd-versions-<release>`, the lines of the removed version entries at the
  earlier anchor (or, for a version only a later earlier-line release served,
  at the highest such release); and either `crd-<to>`, the whole CRD file at
  the later anchor when a version is absent from it, or
  `served-false-<version>-<to>`, the `served: false` line of each version the
  later anchor still lists. Every range bound cites one of them.

A rule holds for **both whole lines** only when every release of both lines
was read completely, no release holds a conflicting copy, every CRD keeps its
group and kind, and no version that some earlier-line release serves is served
by some later-line releases and not by others. Otherwise the pair's rules are
derived from the two anchors only, carry no range, and match only the anchor
transition. (Cilium 1.20.2 serves CiliumNodeConfig `v2alpha1` again after 1.20.0
and 1.20.1 dropped it, so that rule holds for 1.19.0 -> 1.20.0 only.)

A CRD that the earlier line defines and the later anchor defines nowhere — not
under the listed paths, with a clean full-tree scan — is recorded under
`definitionsRemoved` and is **not** a rule: applying the later release's
manifests does not delete a definition, so an upgraded cluster keeps serving
its versions. Without a clean scan the definition may have moved, and the pair
is withheld.

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
  `servedLine`, `storageLine`) and `scan` (`complete`, `problem`, `files` read,
  `excludedFiles`, `skippedDirectories`, the `exclusions` that skipped
  something, the `copies`, and every other finding with `path`, `sha256`,
  `class`, `crds` and `detail`);
- `lines`: for each of `from` and `to`, the `line` and each release (`tag`,
  `commit`, `complete`, `problem`, `crds`, the served members `added` and
  `dropped` relative to the line's first release, `scanClean` and
  `scanFindings`); `lineWide`, and `notLineWide`, why the rules hold for the
  anchor pair only;
- `removals`: each version no longer served (`crd`, `member`, `version`,
  `reason` `absent` or `unserved`, `fromTag`, `fromPath`, `fromStartLine`,
  `fromEndLine`, `toPath`, `toServedLine`, 0 when absent);
- `storageChanges`: each CRD whose storage version differs between the anchors
  (`crd`, `from`, `to`);
- `definitionsRemoved`: each CRD the later anchor defines nowhere (`crd`, the
  `members` the earlier line served, `fromTag`, `fromPath`);
- `completeness`: `declared` (every listed path read completely at every
  release of both lines), `scan` (the full-tree scan clean at every release),
  `lineWide`, `attestable` (all three, and no removed definition) and the
  `reasons` when not.

`completeness.attestable` is the account a line attestation of the later line
would rest on; this version records it and emits no attestation.

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
- Anything about storage versions (recorded only), stored objects, conversion
  webhooks or storage migration, schema or field changes inside a version,
  kustomize patches other than schema-only JSON 6902 patches, CRDs that are
  only shipped templated (Helm charts) or only as release assets, or CRDs other
  than those under the listed paths.
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

## Changes from version 1

Version 1.0.0 read only the two `X.Y.0` tags of a pair, had no range and no
full-tree scan, kept its three targets in Go, withheld every pair in which a
CRD left the listed paths, and refused Argo CD's definitions (nested deeper
than 32 levels). Version 2.0.0 reads every release of both lines, adds the
range, the scan, optional and recursive paths, two tag prefixes, the data-file
target table and nine projects; its rules have new evidence (version and code
digest) and ranges, so rules of version 1 do not re-derive.
