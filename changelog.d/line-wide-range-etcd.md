### Changed

- One more reviewed rule that covered one exact version pair now covers the whole release line on both sides: etcd 3.6 to 3.7 (the 23 removed experimental flags). The widening is backed by a read of the cited files at every release tag of both lines, recorded in the rule evidence and the pull request. The rule keeps its configuration predicate, and a version outside the two lines is not decided by it.
