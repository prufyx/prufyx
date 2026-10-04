# Consensus verifier test corpus

Everything in this directory is synthetic and original, written for these
tests. No file contains or is derived from upstream release notes or upstream
source code. Names such as `SilentDial`, `RetiredKnob` or
`gizmos.example.io/v1beta1`, the pull request numbers, the commit ids, the
people and the release numbers (v1.40.0, v1.41.0) are invented.

## Layout

- `base/` is a fixture tree (the layout `extract --fixture` reads) of a
  fictional `github.com/kubernetes/kubernetes` with two releases:
  - `v1.40.0` (commit `...14000`) and `v1.41.0` (commit `...14100`), each with
    a minimal feature-gate registry (`pkg/features/kube_features.go` and
    `staging/src/k8s.io/component-base/featuregate/feature_gate.go`, written in
    the shape the feature-gate extractor reads) and an OpenAPI specification
    (`api/openapi-spec/swagger.json`) declaring a few kinds;
  - `history.json`, the commit graph between them, whose subjects carry pull
    requests #140001-#140010 in the range and #139990 before it, plus two
    commits after `v1.41.0`: `...14101`, the head of branch `release-1.41`,
    and `...14199`, which is on no branch.

  Removed between the two releases: the gates `CloakedLever`, `EchoSwitch`,
  `MirrorFlag`, `NestedToggle`, `OldPortal`, `RetiredKnob`, `SilentDial`,
  `TwinGateA`, `TwinGateB` and the API versions `gizmos.example.io/v1beta1`,
  `widgets.example.io/v1beta2`, `legacy.example.io/v1alpha1`. `StableThing`,
  `AlphaWidgets`, `LegacyGizmoMode`, `apps/v1` and `batch/v1` remain.
- `cases/<id>/` are injection cases and `controls/<id>/` positive controls.
  Each holds `CHANGELOG-1.41.md`, the later release's release notes, and
  `case.json`: a description, the claims, the expected verdict and reason, and
  for cases the attack category. A case may name a `tamper` the test applies
  to the otherwise correctly pinned bundle.

The tests copy `base/`, add a case's release notes at
`CHANGELOG/CHANGELOG-1.41.md` of the later release, pin them as a correct
pipeline would, and run the verifier. Every case must verify nothing, for the
reason it states; every control must verify.

Most cases claim a gate that really was removed (`SilentDial`) and cite a
pull request of the range, so that the one defence the case is about is all
that stands between the claim and a verified verdict.
