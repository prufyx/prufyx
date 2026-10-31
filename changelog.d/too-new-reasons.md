### Fixed

- `scan` and `check cncf` with an explicit `--knowledge-db` that holds a database this prufyx build cannot read (signed by the pinned root, but too new) now exit `15` with a "too new for this prufyx" message (upgrade prufyx or drop `--knowledge-db`) instead of reporting an integrity failure with exit `3`. Tampered databases still exit `3`.
