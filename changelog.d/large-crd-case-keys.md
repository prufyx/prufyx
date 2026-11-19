### Fixed
- A CustomResourceDefinition whose schema declares two properties that differ only in letter case (the Prometheus operator CRDs declare proxyURL and proxyUrl) is no longer refused as invalid YAML, so a rendered kube-prometheus-stack chart is read. The case-folded duplicate check still applies to every other mapping, and exact duplicates are still refused.
- A file that parses but is refused by a structural rule or a bound is reported as not valid within the supported subset; only a file the YAML reader cannot parse because of template syntax is reported as unrendered templates.
