### Changed

- The `crd.version-removal` extractor now attests release lines for `kyverno` and `mariadb-operator`, and reads the CRDs of `kubeswift` from its first release line with CRDs (0.1) instead of 0.15. `mariadb-operator` reads the `vX.Y.Z` release tags; the bare `X.Y.Z` tags are separate chart tags at other commits. The line 25.8 of `mariadb-operator` stays withheld: its tags `v25.08.0` and `v25.8.0` spell the minor both padded and canonical.
