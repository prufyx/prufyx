### Fixed

- `prufyx scan` now lists every custom resource of the input in a `CUSTOM RESOURCES` section and in the JSON `customResources` array: evaluated (BLOCKED or NO_FINDING, never a pass) or NOT_EVALUATED with a typed reason (`CR_COMPONENT_VERSION_UNKNOWN`, `CR_PAIR_NOT_COVERED`, `CR_KIND_NOT_IN_KNOWLEDGE`) and the next action. Previously a scan given only a component pair, such as cert-manager, said nothing about its custom resources. Verdict and exit codes are unchanged.
