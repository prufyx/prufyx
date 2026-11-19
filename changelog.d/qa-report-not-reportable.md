### Added

- `prufyx-maintainer qa-report` accepts an explicit per-run opt-out (a `NOT-REPORTED.json` marker with a closed reason code, or `"reportable": false` in `RESULT.json`). Marked runs are not parsed and are listed by run id in the report header; unmarked runs of unknown shape are still refused.
- `prufyx-maintainer qa-report --list-refusals --results-dir DIR` prints every refusal of every run (fixed messages and schema key names only, never input values) and writes nothing.
