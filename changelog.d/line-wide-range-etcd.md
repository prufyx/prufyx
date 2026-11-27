### Changed

- One more reviewed rule that covered one exact version pair now covers a reviewed range: etcd 3.6.14 or later in the 3.6 line to any 3.7 release (the 23 removed experimental flags). The 3.7 upgrade guide requires the running cluster to be v3.6.11 or later; the rule does not decide any source release before 3.6.14. The widening is backed by a read of the cited files at every release tag of both lines, recorded in the rule evidence and the pull request. The rule keeps its configuration predicate, and a version outside the range is not decided by it.
