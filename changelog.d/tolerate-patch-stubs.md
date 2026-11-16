### Added

- The target draft generator accepts `--tolerate-patch-stubs` (default off, needs `--skip-patch-fragments`; backtest option `tolerateStubs`): a kustomize CRD patch stub with null timestamp or status, `$(VAR)` strings or an older apiVersion is set aside only when a closed allowlist holds and exactly one full definition of its identity exists at the tag; anything else keeps the typed stop.
