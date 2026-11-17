### Fixed

- The release-line snapshot is re-pinned as lines-2026-11-17.json so that longhorn carries 1.12.2 and openkruise carries 1.9.3, the newest final releases of their lines, read from the upstream tag listings with `coverage lines-from-tags`. Line attestations for longhorn 1.12 and 1.13 and for openkruise 1.8 to 1.9 count only when their releases equal the snapshot's releases exactly; with the older pin they did not match. Only the longhorn and openkruise entries differ from the previous pin; capturedOn and pinnedOn are unchanged, so the evaluation clock is unchanged.
