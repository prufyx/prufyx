### Changed

- The `crd.version-removal` extractor now attests release lines for `dex`, `k8up`, `openyurt`, `submariner` and `volcano`. A dry run against the factory mirror derives the line attestations of the 2.42 to 2.46 lines of `dex`, the 2.12 to 2.16 lines of `k8up`, the 1.11 to 1.15 lines of `volcano`, the 1.4 to 1.6 lines of `openyurt` and the 0.23 and 0.24 lines of `submariner`; no derived rule shares an id with a published rule.
