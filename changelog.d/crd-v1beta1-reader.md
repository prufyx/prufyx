### Changed

- The CRD version extractor (2.10.0) now reads a listed `apiextensions.k8s.io/v1beta1` definition as a source when it states `spec.versions` with boolean `served` and `storage` on every entry (and `spec.version`, when given, names the first entry). Its record carries `sourceApiVersion` and the cited lines. The `spec.version`-only form and every other incomplete v1beta1 shape stay withheld with the earlier reason; v1 records are unchanged.
