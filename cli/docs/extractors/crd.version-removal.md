# Extractor `crd.version-removal`

Version 1.0.0. Derives `forbid_set_member` rules for custom-resource
versions that a project's release no longer serves, from the
CustomResourceDefinition manifests the project ships in its repository. It is
deterministic, reads only upstream source pinned by full commit SHA, and
involves no model.

A run reads one repository, so the extractor is registered once per project,
as `crd.version-removal.<project>`; every registration runs the same code and
carries the same version and code digest.

## Projects and paths

The reviewed source table is part of the extractor code. Each entry names a
catalog project, its repository, the release tags that form pairs and the
paths that hold its rendered CRD manifests:

| Extractor id | Repository | Final release tags | First pair from | CRD manifests |
| --- | --- | --- | --- | --- |
| `crd.version-removal.argo-cd` | `github.com/argoproj/argo-cd` | `vX.Y.0` | 2.14.0 | every `*.yaml`/`*.yml` file directly in `manifests/crds` |
| `crd.version-removal.istio` | `github.com/istio/istio` | `X.Y.0` | 1.24.0 | `manifests/charts/base/files/crd-all.gen.yaml` |
| `crd.version-removal.strimzi` | `github.com/strimzi/strimzi-kafka-operator` | `X.Y.0` | 0.51.0 | files named `NNN-Crd-*.yaml` directly in `install/cluster-operator` |

Rules of other projects are not derived. Adding or changing an entry is a
code change and requires a new extractor version.

## What it reads

Through the offline factory mirror (or a fixture tree), never the network.

- **Pairs.** The project's final release tags `<prefix>X.Y.0` that the mirror
  records with a commit, sorted by version; each tag paired with the next one
  (so `0.51.0 -> 1.0.0` is a pair when no `0.52.0` exists), starting from the
  release in the table. Release candidates and patch releases never form a
  pair. A repository with an unacknowledged tag alarm yields no pairs.
- **CRD manifests at both tags.** Every listed file, and every matching file
  directly in a listed directory, is read in full and decoded with the strict
  YAML subset used for component configuration: anchors, aliases, merge
  keys, custom tags, non-string or duplicate keys, nesting deeper than 32
  levels and oversized documents are refused. Documents of other kinds (a
  kustomization, for example) are counted and otherwise ignored.
- **Each `apiextensions.k8s.io/v1` CustomResourceDefinition**: its name,
  group, kind, plural and scope, and for every entry of `spec.versions` the
  name, `served` and `storage` flags and the lines of the entry and of its
  two flags.

## What it claims

A version is **no longer served** in release `To` when the earlier release
`From` lists it with `served: true` and the later release either does not
list it or lists it with `served: false` (the API server stops serving it
either way). For each CRD with such versions the extractor emits one rule:

- id `<project>.crd-version-removal.<crd name, dots as hyphens>.<from>-to-<to>`
  (versions with dots as hyphens);
- operator `forbid_set_member` over the proposed-side set fact
  `component.<project>.custom_resource_versions_set` (for Argo CD
  `component.argo_cd....`), whose members are `group/version/Kind`, for
  example `kafka.strimzi.io/v1beta2/Kafka`; the rule forbids the versions no
  longer served;
- subject: the project's catalog component, the anchor transition
  `From -> To` only (no range);
- next action: `change apiVersion of <Kind> to <group>/<version> before
  upgrading to <To>`, naming the highest version the later release serves,
  or `migrate <Kind> objects before upgrading to <To>` when it serves none;
- sources (each with the whole-file sha256 of the bytes read):
  `crd-versions-<from>`, the lines of the removed version entries at the
  earlier tag (first to last); and either `crd-<to>`, the whole CRD file at
  the later tag when a version is absent from it, or
  `served-false-<version>-<to>`, the `served: false` line of each version the
  later tag still lists.

Each rule's test vectors (blocked, pass-complete, unknown-incomplete) are
evaluated through the engine before anything is written.

## Proof recorded in the manifest

For every pair, `manifest.json` records under `pairs[].proof`:

- `target` and `factId`;
- `from` and `to`, the complete inventory of each tag: `tag`, `commit`,
  `complete`, `problem` (when incomplete), `paths` (each listed path, whether
  it is a file or a directory, how many files were read and how many
  directory entries were ignored), `files` (path, `sha256:` digest of the
  whole file, size, lines, documents, CRDs, other documents) and `crds`;
  each CRD with `name`, `group`, `kind`, `plural`, `scope`, `path`,
  `document` (1-based), `startLine`, `versionsLine`, `storageVersion` and
  `versions` (each with `name`, `served`, `storage`, `startLine`, `endLine`,
  `servedLine`, `storageLine`); CRDs are sorted by name, versions keep the
  manifest's order;
- `removals`: each version no longer served (`crd`, `member`, `version`,
  `reason` `absent` or `unserved`, `fromPath`, `fromStartLine`,
  `fromEndLine`, `toPath`, `toServedLine`, 0 when absent);
- `storageChanges`: each CRD whose storage version differs between the tags
  (`crd`, `from`, `to`).

These field names are stable within major version 1.

## What it never claims

- A removal when any listed path is missing at either tag, a listed
  directory holds no matching file, a file contains template syntax (`{{`),
  a file is not decodable in the strict subset or exceeds 4 MiB, a document
  is a `List`, a CRD is `apiextensions.k8s.io/v1beta1` (or any version other
  than `v1`) or is incomplete (no versions, flags that are not booleans, not
  exactly one storage version, a name that is not `<plural>.<group>`), two
  documents define the same CRD or kind, a tag has more than 512 CRDs or a CRD
  more than 64 versions, or a CRD of the earlier tag is not under the listed
  paths at the later one (a removed definition cannot be told from a moved
  one). The pair is then withheld: no rule, and the manifest says why.
- Anything about storage versions: a storage version that changes while the
  old version stays served is recorded in the proof only. Stored objects,
  conversion webhooks and storage migration are not checked.
- Anything about schema or field changes inside a version, about CRDs that
  are only shipped templated (Helm charts) or only as release assets, or
  about CRDs other than those under the listed paths.
- That an upgrade is safe: a PASS from these rules only says that a complete
  declared set of custom-resource versions holds none of the versions no
  longer served.

No adapter declares `component.<project>.custom_resource_versions_set` yet,
and the fact is not in the published fact registry, so these rules cannot be
added to the published pack and any input without the fact is UNKNOWN.

## Running and verifying

```
prufyx-maintainer extract run    --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT [--derived-at 2026-10-04T00:00:00Z]
prufyx-maintainer extract verify --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor crd.version-removal.strimzi --out OUT --expected FILE
```

`run` writes `candidates.json`, `vectors.json`, `manifest.json` and
`reads/`, as for every extractor. `verify` re-derives from the pinned bytes
with the recorded `derivedAt` and fails unless every output file is
byte-identical. The code digest is sha256 over the sorted lines
`<dir>/<file> NUL <sha256> LF` of the non-test Go files of `internal/extract`
and `internal/extract/crdversions`; the manifest lists them.

`oracle` compares a run with an expected-results file:

```json
{
  "removals": [{"from": "0.51.0", "to": "1.0.0", "member": "kafka.strimzi.io/v1beta2/Kafka", "reason": "absent"}],
  "rules": [{"name": "a reviewed rule", "from": "0.51.0", "to": "1.0.0", "members": ["kafka.strimzi.io/v1beta2/Kafka"]}],
  "storageChanges": [{"from": "0.51.0", "to": "1.0.0", "crd": "kafkas.kafka.strimzi.io", "fromStorage": "v1beta2", "toStorage": "v1"}]
}
```

Every listed removal must be derived with the same reason and forbidden by a
rule; every rule's members must be forbidden on its transition; every listed
storage change must be recorded. When removals (or storage changes) are
listed, any other one the run derives is reported as `EXTRA`. The exit code
is 1 when there is any disagreement.
