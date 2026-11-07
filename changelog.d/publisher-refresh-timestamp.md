### Added

- `knowledge-publish release` splits role expiries (targets and snapshot up to 21 days, timestamp up to 14 days) and in CI mode refuses before signing on any digest mismatch, a missing `--expires`, a replayed run attempt or an unverifiable previous package; new `refresh-timestamp`, `live-state`, `deploy-guard` and `content-digest` subcommands keep a package fresh with the timestamp key alone and check publish state.
