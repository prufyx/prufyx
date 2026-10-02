# Extractor `k8s.feature-gate-removal`

Version 1.0.0. Derives `forbid_set_member` rules for Kubernetes feature gates
that a minor release no longer declares. It is deterministic, reads only
upstream source pinned by full commit SHA, and involves no model.

## What it reads

Repository `github.com/kubernetes/kubernetes`, through the offline factory
mirror (or a fixture tree), never the network.

- **Pairs.** Every `vX.(Y-1).0 -> vX.Y.0` where both tags are recorded by the
  mirror with their commit, for major 1 and target minor 23 or later. Only
  final `.0` tags match `^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.0$`; release
  candidates and patch releases never form a pair. A repository with an
  unacknowledged tag alarm yields no pairs.
- **Declared gates at the earlier tag.** The keys of every feature-spec map
  literal (`map[featuregate.Feature]featuregate.FeatureSpec`,
  `...VersionedSpecs`, and client-go's own `Feature` maps), resolved through
  constants to their string names, in the declaration directories:
  `pkg/features`, `staging/src/k8s.io/<repo>/pkg/features`,
  `staging/src/k8s.io/client-go/features`,
  `staging/src/k8s.io/component-base/<area>/features` and
  `staging/src/k8s.io/component-base/logs/api/v1`. This covers every registry
  format from 1.22 (unversioned specs, generic API server gates relisted in
  `pkg/features`) through 1.31/1.32 (versioned specs in a separate file) to
  1.33 and later (versioned specs only, dependency maps).
- **Every gate name at the later tag.** A full walk of `pkg/`, `staging/`,
  `cmd/` and `plugin/` (skipping `vendor`, `testdata`, `_*` and `.*`
  directories and `_test.go` files), parsing every Go file with `go/parser`
  and collecting the resolved keys of every feature-spec map literal, every
  constant declared with a feature-gate type and every string literal
  converted to one.
- **Cross-checks at the later tag.** Upstream's generated feature lists
  (`test/featuregates_linter/test_data/*feature_list.yaml`,
  `test/compatibility_lifecycle/reference/*feature_list.yaml`) where present:
  every listed gate must be in the walk (the lists name a gate by its Go
  identifier, so an identifier of a resolved key also counts). The
  feature-gate implementation
  (`staging/src/k8s.io/component-base/featuregate/feature_gate.go`) must
  contain the `unrecognized feature gate` error.

## What it claims

A gate is **removed** in `X.Y.0` when it is declared at `vX.(Y-1).0` and its
name appears nowhere in the walk at `vX.Y.0`. For each pair with removals it
emits one rule per component (kube-apiserver, kube-controller-manager,
kube-scheduler, kubelet, kube-proxy) over the component's
`component.kubernetes.<component>_feature_gates_set` fact, forbidding the
removed gates (at most 64 per rule, and at most three declaring files per
rule; larger sets are split in name order into rules `.1`, `.2`, ...).

All five components share one feature-gate registry, so a gate absent from
the whole source tree is accepted by none of them: a component given it
refuses to start. A rule therefore applies to every component even where the
gate was only ever meaningful to one of them.

Each rule is the anchor transition `X.(Y-1).0 -> X.Y.0` only (no range) and
cites, at most seven sources:

- `gate-declarations-<from>-<a|b|c>`: the declaration lines of the forbidden
  gates at the earlier tag (first to last declaration in that file);
- `gate-registry-<to>-<a|b|c>`: the same file at the later tag, whole file;
- `unrecognized-gate-<to>`: the line of the unrecognised-gate error.

Every source carries the whole-file sha256 of the bytes actually read. The
complete name lists, the files walked (`reads/<commit>.tsv`), the tree ids of
the walk roots and the declaration and registration line of every removed
gate are in the run manifest.

## What it never claims

- That a gate is removed when any file of the later tag could not be read or
  parsed, a map key cannot be resolved to a static name, a generated list
  names a gate the walk did not find, the unrecognised-gate error is not
  found, or the earlier registry has an unresolved key. The pair is then
  withheld: no rule, and the manifest says why.
- Anything about locked gates (still declared, rejecting only the non-default
  value), gate semantics or defaults, or patch releases and other
  transitions than the anchor pair.
- Anything about kubeadm's own feature gates, or about vendor builds that
  carry other gates.
- That an upgrade is safe: a PASS from these rules only says that a complete
  feature-gate set holds none of the removed gates.

## Running and verifying

```
prufyx-maintainer extract run    --extractor k8s.feature-gate-removal --mirror-state DIR --out OUT [--derived-at 2026-10-02T00:00:00Z]
prufyx-maintainer extract verify --extractor k8s.feature-gate-removal --mirror-state DIR --out OUT
```

`run` writes `candidates.json` (pack entries), `vectors.json` (for each rule
a blocked, a pass-complete and an unknown-incomplete engine input with the
verdict it must give; all are evaluated through the engine before writing),
`manifest.json` and `reads/`. Every candidate passes `rulecheck` and carries
`basis: mechanical`, the extractor id, version and code digest, and
`derivedAt` (also its `reviewedAt`; validity 90 days). `verify` re-derives
from the pinned bytes with the recorded `derivedAt` and fails unless every
output file is byte-identical. The code digest is sha256 over the sorted
lines `<dir>/<file> NUL <sha256> LF` of the non-test Go files of
`internal/extract` and `internal/extract/k8sfeaturegates`; the manifest lists
them.

The mirror must hold the blobs of the walked files at every tag; a blob that
is not local withholds the pair. Any change to the output requires a new
extractor version.
