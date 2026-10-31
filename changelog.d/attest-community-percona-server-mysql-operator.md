### Changed

- The `crd.version-removal` extractor now attests release lines for `percona-server-mysql-operator`. The target excludes the `e2e-tests/` kuttl suite, which holds assertion files that name CustomResourceDefinition objects but no installed definition. A dry run against the factory mirror derives the line attestations of 0.12, 1.1, 1.2 and 1.3 (the 0.12 to 1.0 hop is a major hop and stays unattested) and three new rules for the v1alpha1 versions removed in 0.12; no derived rule shares an id with a published rule.
