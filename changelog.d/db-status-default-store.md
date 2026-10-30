### Fixed

- `prufyx db status --profile cncf-projects` without `--db-root` now inspects the default store that `prufyx db update` installs into, instead of exiting 2 with "invalid database status arguments".
