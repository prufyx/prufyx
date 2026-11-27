### Added

- Add `prufyx-maintainer flag-removal-verify`, a report-only check of command line flags claimed removed between two release lines: it reads every final release of both lines against the lines snapshot and pinned tags, requires the registration at the older line, sweeps the newer trees and their go.sum-verified modules, checks parser strictness, and refuses on any gap. It writes no rule or fact, and a passing name is not a proof of removal: no execution probe is run.
