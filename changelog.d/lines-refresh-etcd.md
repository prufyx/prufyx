### Fixed

- The release-line snapshot is re-pinned as lines-2026-11-27.json so that etcd carries 3.5.36, 3.6.17 and 3.7.4, the newest final releases of their lines, read from the upstream tag listing with `coverage lines-from-tags`. Only the etcd entry differs from the previous pin; capturedOn and pinnedOn are unchanged, so the evaluation clock is unchanged, and the README coverage numbers are unchanged.
