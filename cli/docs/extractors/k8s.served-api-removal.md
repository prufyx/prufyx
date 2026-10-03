# Extractor `k8s.served-api-removal`

Version 1.0.0. Derives `forbid_predicate_value` rules for Kubernetes API
versions that a minor release stops serving. It is deterministic, reads only
upstream source pinned by full commit SHA, parses Go with `go/parser` (nothing
is compiled or executed), and involves no model.

## What it reads

Repository `github.com/kubernetes/kubernetes`, through the offline factory
mirror (or a fixture tree), never the network. The mirror must hold the file
contents at the tag commits (the pairs below), including the large OpenAPI
specification.

- **Pairs.** Every `v1.(L-1).0 -> v1.L.0` where both tags are recorded with
  their commit and `L-1` is at least 19. Only final `.0` tags match
  `^v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.0$`.
  **Boundary:** `v1.19.0` is the first release tag whose tree holds
  `staging/src/k8s.io/api/**/zz_generated.prerelease-lifecycle.go`; `v1.18.0`
  holds none (and neither do `v1.15.0` to `v1.17.0`). The first evaluated pair
  is therefore `v1.19.0 -> v1.20.0`; earlier lines are not emitted. A tag whose
  tree yields no lifecycle file withholds its pair.
- **Lifecycle files at the earlier tag.** Every
  `zz_generated.prerelease-lifecycle.go` in a version directory (`v1`,
  `v1beta1`, `v2alpha1`, ...) one level below a group directory of
  `staging/src/k8s.io/api`, plus the version directories of
  `staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions` and
  `staging/src/k8s.io/kube-aggregator/pkg/apis/apiregistration`. Each is
  parsed with `go/parser`; every `APILifecycleRemoved` method must have the
  generated form (pointer receiver, no parameters, a single `return` of two
  integer literals) and the package name must equal the version directory. The
  API group is the string literal of `GroupName` in the `register.go` beside
  the file.
- **OpenAPI specification at both tags.** `api/openapi-spec/swagger.json`;
  the set of group/version/kinds is read from `x-kubernetes-group-version-kind`
  of every definition.

## What it claims

A **removal** of line `L` is a (group, version, kind) whose
`APILifecycleRemoved()` returns `1, L`. A `...List` kind follows its item kind
(an upstream List method that names another release than its item kind is
recorded in the manifest and not trusted). Alpha versions (`vNalphaM`) are not
served by default and are neither cross-checked nor emitted; they are only
counted in the manifest.

Each pair is **cross-checked against the specifications**, in both directions:

- every removal must be in the specification at the earlier tag and absent at
  the later tag;
- every non-alpha kind that is in the earlier specification and gone from the
  later one must be a removal of the line. Only `DeleteOptions`, `WatchEvent`,
  `Eviction` and `EphemeralContainers`, which carry no lifecycle method and are
  registered and re-registered independently of API versions, are exempt.

Any disagreement, any unparseable or missing lifecycle file, `register.go` or
specification, a missing source directory, or a tag with no lifecycle files
**withholds the whole pair**: no rule, and the manifest names the first
disagreement and records them all.

A declared removal that neither specification lists (review envelopes such as
`AdmissionReview` and `ConversionReview`, `JobTemplate`, aggregated-discovery
types) is not a served resource: it is recorded under `unobserved` and never
emitted.

For every removed (group, version) the manifest records, per line: the kinds,
the List kinds, the lifecycle file and the lines of every removed method,
the stable and beta versions of the group served at the later tag for all of
the removed kinds (`replacements`), and the adapter fact for each kind. Quiet
lines carry an empty removal list, so a later per-line attestation can be
derived from the manifest.

## Rules

One rule per removed (group, version) and **adapter fact**: the Kubernetes
manifest adapter derives a boolean fact per reviewed removal
(`component.kubernetes.<name>_removed_gvk_present`), and a rule needs exactly
one. Where a group version splits across facts (networking `Ingress` and
`IngressClass`, policy `PodDisruptionBudget` and `PodSecurityPolicy`), it
yields one rule per fact, id `...<group>-<version>-<fact name>...`. A removal
whose kinds the adapter produces no fact for is **recorded and not turned into
a rule** (the extractor never invents a fact); the manifest lists the kinds
under `noFactKinds`.

Rule shape follows the reviewed API-removal rules: `forbid_predicate_value`
over the fact being `true` on the proposed side, anchor `1.(L-1).0 ->
1.L.0`, range `from [1.(L-1).0, 1.L.0)` and `to [1.L.0, 1.(L+1).0)` with
bounds `PREVIOUS_MINOR_LINE`, `REMOVED_IN_RELEASE` (twice) and `TARGET_SERIES`,
reason code `KUBERNETES_SERVED_API_REMOVED`, evidence basis `mechanical` with
the extractor identity. Sources (three): the lifecycle method lines at the
earlier tag (`lifecycle-<group>-<version>-<from>`, which every bound cites) and
the whole specification at each tag (`openapi-<from>`, `openapi-<to>`).

## What it never claims

- Anything about alpha versions, resources served by aggregated or custom
  API servers, CRDs, or removals not declared with a lifecycle method.
- That a manifest using a removed version was ever valid, or that an upgrade
  is safe: a PASS only says the target apply set holds none of the removed
  kinds at that version.
- Patch releases or transitions other than the anchor pair and its range.

## Running and verifying

```
prufyx-maintainer extract run    --extractor k8s.served-api-removal --mirror-state DIR --out OUT [--derived-at 2026-10-03T00:00:00Z]
prufyx-maintainer extract verify --extractor k8s.served-api-removal --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor k8s.served-api-removal --out OUT --expected EXPECTED.json
```

`oracle` compares the run with an expected list of removals
(`{"removals": [{"line": "1.25", "group": "batch", "version": "v1beta1",
"kinds": ["CronJob"]}]}`) and reports `MISSING`, `WITHHELD`, `KINDS`, `NOFACT`,
`NORULE` and `EXTRA` differences. The output files, canonical encoding and
code digest are those of every extractor (see `internal/extract`).
