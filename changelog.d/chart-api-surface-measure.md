### Added

- `prufyx-maintainer chart-api-surface` reads a pinned chart archive statically and writes a measurement ledger of every apiVersion and kind the chart can produce, with file and line, a conditional flag per entry and typed withheld codes for shapes it cannot list. An optional per-line check against the Kubernetes served-API lists reports would-block, would-pass or withheld. It is a measurement only: it writes no rule, no attestation and no verdict.
