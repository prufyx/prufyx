### Added

- The release notes list what works in the release, each with the command that shows it, and what is not yet, each with its reason. Both lists are generated from `cli/docs/release-features.json`; the release-docs check refuses a feature that has no existing evidence or no demo command on the CI smoke list, and a hand-written coverage claim in the notes.
