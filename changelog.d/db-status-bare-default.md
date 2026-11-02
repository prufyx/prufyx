### Changed

- `prufyx db status` without `--profile` now reports the default knowledge store (the one `db update` installs into) instead of exiting 2. When no store is installed it prints the age of the knowledge built into the binary (earliest active rule end date, expiry note) before the "no verified knowledge database is selected; checks use the embedded knowledge" line (exit 11).
