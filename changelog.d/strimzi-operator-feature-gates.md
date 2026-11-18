### Added

- `check cncf --project strimzi --strimzi-operator-deployment FILE` (and `prepare cncf`) reads the feature gate names set in `STRIMZI_FEATURE_GATES` of one rendered Cluster Operator Deployment and reports `BLOCKED` when the `UseKRaft` gate is set for the `0.41.0` to `0.44.0` transition (the `0.44.0` operator rejects it). An absent variable, `envFrom`, an unknown gate or an unreadable value stays `UNKNOWN`; no other environment value is read.
