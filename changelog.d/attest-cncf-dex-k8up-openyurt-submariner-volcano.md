### Changed

- The `crd.version-removal` extractor now attests release lines for `dex`, `k8up`, `openyurt`, `submariner` and `volcano`. A dry run against the factory mirror derives the line attestations of the last five minor lines of `dex`, `k8up` and `volcano`, the 1.4 to 1.6 lines of `openyurt` and the 0.23 and 0.24 lines of `submariner`; no derived rule shares an id with a published rule.
