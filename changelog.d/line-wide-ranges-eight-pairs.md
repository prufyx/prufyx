### Changed

- Seven reviewed rules that covered one exact version pair now cover the whole release line on both sides: falco 0.40 to 0.41, spire 1.10 to 1.11 and 1.13 to 1.14, distribution 2.8 to 3.0, python-tuf 6.0 to 7.0, and openfga 1.13 to 1.14 and 1.17 to 1.18. Each widening is backed by a read of the cited file at every release tag of both lines, recorded in the rule's evidence. The rules keep their configuration predicates, and any version outside the two lines stays UNKNOWN.

### Removed

- The etcd 3.5.17 to 3.6.0 rule about removed v2/proxy flags is withdrawn: the upstream 3.6 upgrade guide requires every 3.5 member to run a later patch release first. Transitions from 3.5 into 3.6 are not decided by it and report UNKNOWN, including the cases it used to report as blocked.
