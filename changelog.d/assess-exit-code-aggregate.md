### Fixed

- `prufyx assess --scope-input` now exits with the aggregate: `0` for `SCOPE_COMPLETE_PASS`, `10` for `BLOCKED`, `11` for `UNKNOWN`. It previously exited `0` for every aggregate, so a BLOCKED or UNKNOWN assessment looked like a pass. This is a behaviour change for CI that keyed on exit `0`. Without `--scope-input` the exit stays `0`; collection failures keep their codes (partial collection exits `6`).
