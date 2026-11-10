### Changed

- The KubeVela CRD extractor target now carries the reviewed generation declaration (`config/crd/kustomization.yaml`) and the sha256-pinned `references/cli/adopt-templates/default.cue` exclusion, as data only. No rule, record or attestation changes in this change; the effect on the derived data follows from the factory derive and lands as a separate data change.
