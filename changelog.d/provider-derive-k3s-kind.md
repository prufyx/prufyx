### Added

- Maintainer tooling: pure extractors that turn committed release excerpts of k3s and kind into provider-version to Kubernetes-version mapping rows. Only final releases map, pre-releases and releases without a stated mapping stay unknown, kind rows are marked non-production, and any unparsable or conflicting input fails closed with a typed drift error and no output. Not wired into any pack or scan yet.
