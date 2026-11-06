### Added

- A new example, `examples/old-to-latest/`, shows `prufyx plan` over a long Kubernetes route (1.29.15 to 1.36.0): every hop is COVERED once the complete apply set and the lowest kubelet version are declared, and the plan stays UNKNOWN because hop actions and node rolls are not checked. The docs explain why a single kubelet declaration cannot span 1.29 to 1.37.0 and how to plan that route in legs. A golden test pins the hop statuses.
