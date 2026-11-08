### Added

- `knowledge-publish release` splits role expiries (targets and snapshot up to 21 days, timestamp up to 14 days) and under the explicit `--ci` flag (never implied by `GITHUB_ACTIONS` or `CI`) refuses before signing on any digest mismatch, a missing `--expires`, a replayed run attempt or an unverifiable previous package; new `refresh-timestamp`, `live-state`, `deploy-guard` and `content-digest` subcommands keep a package fresh with the timestamp key alone and check publish state.
- `knowledge-publish content-digest` and the `release` result now report `evidenceExpiresAt` (the evidence bundle expiry, canonical UTC), so a release plan can be capped by it; an absent or non-canonical evidence expiry is refused.
