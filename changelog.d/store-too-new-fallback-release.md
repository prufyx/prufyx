### Fixed

- A local knowledge store that is signed by the pinned root but needs a newer prufyx (its `minClientVersion` is above this build) now falls back to the embedded knowledge with the "newer prufyx needed" warning on release builds too, instead of failing `scan` and `check cncf` with exit 3 (integrity failure). A store that fails verification is still an integrity failure with no fallback.
