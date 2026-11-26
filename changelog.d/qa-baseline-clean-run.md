### Fixed
- Nightly QA: stored count baselines and the stored oracle digest now move only on a green full run with no skipped suite. An alarmed or partial run keeps the previous values, including on the first run with no stored status.
- Nightly QA: an inconclusive run with nothing relevant changed no longer marks the commit as checked, so it is checked again.
