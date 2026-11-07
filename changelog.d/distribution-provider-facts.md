### Added

- Distribution records in a knowledge pack can now carry optional `lifecycle` (announced support dates with an explicit precision and an opt-in flag next to any extended-support date), `channels` and `deprecations` lists, checked by the same strict validator and evidence rules as the rest of the record. They are advisory only, no shipped pack uses them, and no scan reads them yet.
