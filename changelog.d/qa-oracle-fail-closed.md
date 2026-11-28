### Fixed

- QA gate, CRD oracle: a `List` document, a document that is not a mapping, another `apiextensions.k8s.io` document that is not a CustomResourceDefinition, a definition that is neither `apiextensions.k8s.io/v1` nor a complete `v1beta1` one with a `spec.versions` list, or a definition repeated by name, by group and kind, or by version is now an error instead of being skipped or merged.
- QA gate, live probe: a definition set that cannot be applied or established is now an error instead of a skip.
- QA gate, rules oracle: a rule counts as reached only when the report holds its own `BLOCKED` claim (a withdrawn rule: its own withdrawn claim). In pull-request mode every changed rule that the head still ships, or every rule when the change cannot be narrowed, must be reached; otherwise it is an error. A head rule file that is unreadable or repeats a rule id is an error.
