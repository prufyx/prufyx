### Added

- QA gate, rules oracle: upstream minimum source versions (etcd 3.6, Harbor 2.15, Cilium 1.19) are checked on every run of the rules suite. An upgrade from an older source that passes with every checked condition declared safe is a wrong PASS; an inconclusive probe is an error.
