### Added

- `scripts/qa-auto/` is an independent check that runs after every data or knowledge merge on main. It compares the served CRD versions at real upstream tags and the Kubernetes API surface of each minor with what `prufyx scan` and `prufyx plan` report, probes removed built-in APIs and live CRD dumps on a throwaway kind cluster, and raises an alarm on any wrong PASS.
