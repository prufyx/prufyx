### Added

- Added reviewed upgrade-path policy records (sequential minor) for Cilium, Longhorn and Crossplane, each citing the upstream docs statement at a pinned commit. A multi-version upgrade of these apps now plans one hop per minor line and stays UNKNOWN until each hop is covered; nothing is PASS. Docs read 2026-11-18 for releases up to Cilium 1.20, Longhorn 1.13 and Crossplane 2.4; a new minor beyond that range needs a re-review. The records are data only and need the owner approval signature.
