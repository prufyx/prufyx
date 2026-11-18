### Added

- `prufyx-maintainer qa-report` generates `cli/docs/generated/qa-e2e.json` and `qa-e2e.md`, a display-only report of Prufyx runs against real upgrades on kind clusters (result versus oracle per check, with reason codes and digests). It reads the run results through a closed schema, copies only allowlisted fields, and `--check` fails when the committed files are stale. It changes no verdict.
