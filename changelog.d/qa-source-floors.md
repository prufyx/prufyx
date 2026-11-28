### Added

- QA gate, rules oracle: minimum source versions (etcd 3.6, Harbor 2.15, Cilium 1.19, Contour 1.20) are checked on every run of the rules suite. A rule that can PASS and covers an older source for one of these lines is a wrong PASS, and so is a probed upgrade from an older source that passes with every checked condition declared safe. An unreadable rule or an inconclusive probe is an error. The Cilium minimum is derived from upstream text that names no version.
