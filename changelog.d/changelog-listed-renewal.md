### Added

- `prufyx-maintainer changelog-renewal` renews due `changelog.listed_entries` records from two byte-identical derivations, moving only their three times and, from a newer build of the same extractor, its version and code digest.
- The knowledge gate refuses a changed `changelog.listed_entries` record whose derivation time is not later than before and, at the same extractor build with the same releases, any change that is not a time-only renewal.
