### Fixed

- The Ceph rules about a selected FileStore OSD for 15.2.17, 16.2.15 and 17.2.9 to 20.2.4 are withdrawn. The upstream Tentacle upgrade notes require a cluster older than Reef to be upgraded to Reef (18.2.z) or Squid (19.2.z) first, so the scoped PASS these rules gave was wrong. Those transitions now report UNKNOWN, including the case they used to report as blocked.
