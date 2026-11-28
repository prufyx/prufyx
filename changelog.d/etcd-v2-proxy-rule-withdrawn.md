### Fixed

- The etcd 3.5.17 to 3.6.0 rule about removed v2/proxy flags is withdrawn. The upstream 3.6 upgrade guide requires every 3.5 member to run 3.5.32 or later before the upgrade, so the scoped PASS this rule gave from 3.5.17 was wrong. That transition now reports UNKNOWN, including the case it used to report as blocked.
