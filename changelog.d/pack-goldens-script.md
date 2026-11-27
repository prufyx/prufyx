### Fixed

- `make regenerate-pack-goldens` runs again: it no longer requires a pack digest pin that the tests do not have. It prints the pack digest at HEAD and in the working tree, and does not start when HEAD has no pack or a golden directory has uncommitted changes.
