### Changed

- The reviewed changelog target rows of `prufyx-maintainer changelog entries` are now data in a closed-schema file (`targets.json`, schema `prufyx.io/changelog-targets/v1`) instead of Go code. Styles are names that map to fixed expressions in code, never free regular expressions; a table that does not match the schema is not loaded and every component is refused. The file is part of the extractor code digest. The six existing rows behave exactly as before.
