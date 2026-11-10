### Added

- `prufyx-maintainer approval sign --rules-file FILE` signs the approvals of many rules in one run: the owner confirms the exact list once (on the terminal, or with `--expect-count` and `--expect-list-digest`), the key is read once, and either every record is written or none. `--dry-run` prints the list and its digest without reading a key. Each record is the one `approval sign` writes for that rule alone.
