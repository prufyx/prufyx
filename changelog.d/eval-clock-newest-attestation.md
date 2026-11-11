### Fixed

- The coverage evaluation clock of a tree now also follows the newest `derivedAt` or `reviewedAt` of its line attestations (never the wall clock), so a renewed or new attestation made after the snapshot was pinned counts as decided instead of failing the coverage floor on the clock alone. The merge gate refuses an attestation dated after its own time, and the README block names the clock when it is an attestation's time.
