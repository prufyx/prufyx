### Changed

- The `crd.version-removal` extractor now attests release lines for `openkruise` (lines 1.8 and 1.9 are decidable) and carries one reviewed exclusion, the end-to-end test helper `tools/hack/csi-driver-host-path/` (VolumeSnapshot CRDs of the external-snapshotter for a test cluster). The lines 1.5 to 1.7 stay undecided: their vendor directory still holds Kubernetes test manifests that the Go install-surface guard cannot rule out.
