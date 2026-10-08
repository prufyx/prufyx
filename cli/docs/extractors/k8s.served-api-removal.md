# Extractor `k8s.served-api-removal`

Version 1.3.0. Derives `forbid_predicate_value` rules for Kubernetes API
versions that a minor release stops serving. It is deterministic, reads only
upstream source pinned by full commit SHA, parses Go with `go/parser` (nothing
is compiled or executed), and involves no model. It also attests every line
it derives completely (see "Line attestations" below).

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
lines carry an empty removal list.

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

## Next-action text

Each rule's next action (what `scan` and `check` print as the fix) names the
removed kinds and the version to migrate to, then tells the reader to
reassess the complete target apply set and to validate admission, CRDs, stored
objects, runtime clients and API-server configuration separately. For example
CronJob: "Migrate the named CronJob manifests to batch/v1. Reassess the
complete target apply set. Validate admission, CRDs, stored objects, runtime
clients, and API-server configuration separately."

The text comes from a reviewed table keyed by group, version and kind
(`hints.go`), written from the upstream deprecation guide and the next actions
of the reviewed API-removal rules. It is not read at run time, so it is the same
on every run and needs no network. The table holds, per kind: the target API
(for flow control 1.26 both `v1beta2` and `v1beta3`; for PodSecurityPolicy no
target, only "remove it, and migrate to Pod Security Admission or a 3rd party
admission webhook"), and where the text has room one short note about the
change the guide stresses (for example Ingress `pathType` is required,
HorizontalPodAutoscaler `target.averageUtilization`, PodDisruptionBudget empty
selector, webhook `failurePolicy`). A next action is limited to 256 bytes, so the
note is dropped first when the kind list is long. A removal whose kind is not in the table
(a kind added by a later Kubernetes release before the table is reviewed) gets
the generic text: migrate to the newest version the target serves for all of
the kinds, or remove the manifests when there is none. Adding a kind to the
adapter table without a hint is caught by a test.

**Citations (since 1.3.0).** Every table entry for a kind the guide covers
carries a citation: the guide's URL, its revision
(`kubernetes/website@9f1af2971c32124bff0a1f42255ba5a2f3c8a16f`, file
`content/en/docs/reference/using-api/deprecation-guide.md`) and the first and
last line of the passage that holds the removal statement, the target API and
the note. A test checks each one against a pinned copy of that file
(`testdata/deprecation-guide.md`, SHA-256 `96f34a49...4f61`): the lines exist,
and contain the removed API version, the kind, the target API (and the
alternative, for flow control `v1beta1` through a second citation) and the note
keywords. The kinds removed after the guide's revision (`SelfSubjectReview`,
`ValidatingAdmissionPolicy`, `ValidatingAdmissionPolicyBinding`, `IPAddress`,
`ServiceCIDR`, `VolumeAttributesClass`) are not in the guide, so they carry no
citation and keep the generic text of the stable version of the group; a test
lists them and proves the guide does not mention them. The extractor reads no
guide at run time; the citations are data for review.

## Line attestations

Version 1.1.0 adds a [line attestation](../line-attestations.md) for every
derived pair: for component `pkg:github/kubernetes/kubernetes`, line `1.L` and
fact family `kubernetes.removed_served_gvk`, the rules of that pair are all
the rules (none for a quiet line). The attestation has basis `mechanical`,
the run's extractor identity, `derivedAt`, `reviewedAt` and `validUntil`, and
cites the whole specification at both tags (`openapi-<from>`, `openapi-<to>`).

No attestation is emitted for a withheld pair, or for a line where a removal
has no adapter fact (its kinds are under `noFactKinds`), since that removal
has no rule. Each pair in the manifest records the outcome under
`attestation` (`status` `attested` or `not-attested`, `line`, `families` and,
when not attested, `reason`). The attestations are written to
`attestations.json`, in canonical order (the file is not written when no line
is attested), and are renewed by running the extractor again; `extract
verify` re-derives them byte for byte. Every rule the extractor emits ranges
over the whole previous minor line and the whole target line, so each
listed rule matches every upgrade into the attested line.

Version 1.1.0 changes no rule: only the extractor identity in each rule's
evidence differs from 1.0.0 (`evidence.extractor.version`, and
`evidence.extractor.codeDigest`, which changes with any change to the
extractor's code).

Version 1.2.0 changes only the next-action text of each rule (see "Next-action
text") and, with it, the extractor identity in each rule's evidence. Rule ids,
constraints, ranges, facts, sources and attestations are unchanged.

## What it never claims

- Anything about alpha versions, resources served by aggregated or custom
  API servers, CRDs, or removals not declared with a lifecycle method.
- That a manifest using a removed version was ever valid, or that an upgrade
  is safe: a PASS only says the target apply set holds none of the removed
  kinds at that version.
- Patch releases or transitions other than the anchor pair and its range.

## Running and verifying

```
prufyx-maintainer extract run    --extractor k8s.served-api-removal --mirror-state DIR --out OUT [--derived-at 2026-10-03T00:00:00Z] [--lease-days 80]
prufyx-maintainer extract verify --extractor k8s.served-api-removal --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor k8s.served-api-removal --out OUT --expected EXPECTED.json
```

`--lease-days` sets how long the derived rules stay valid (1-365, default 90). A rule's validity may not exceed 90 days from its review, so the run refuses larger values.

`oracle` compares the run with an expected list of removals
(`{"removals": [{"line": "1.25", "group": "batch", "version": "v1beta1",
"kinds": ["CronJob"]}]}`) and reports `MISSING`, `WITHHELD`, `KINDS`, `NOFACT`,
`NORULE` and `EXTRA` differences. The output files, canonical encoding and
code digest are those of every extractor (see `internal/extract`), plus
`attestations.json`.
