### Added

- The reviewed CNCF pack now carries three Kyverno rules for the 1.10.7 to 1.13.4 hop: CleanupPolicy, ClusterCleanupPolicy and PolicyException at `kyverno.io/v2alpha1` are no longer served by 1.13.4. A scan of that hop with one of those versions declared in the target apply set answers `BLOCKED` instead of `UNKNOWN`; without a declaration the hop is never a `PASS`.
