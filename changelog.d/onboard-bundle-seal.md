### Added

- `prufyx-maintainer onboard-bundle seal DIR` writes the bundle receipt (per-file digests and `bundleSha256`) with the same digest function the validator uses, so no digest is written by hand. The receipt is an integrity record of the file bytes only, not provenance. Seal refuses a bundle with any other finding, a field over 2000 characters, a non-ASCII character outside quotes, or more than 512 KiB in total, and replaces a stale receipt only with `--force-reseal`, printing what changed.
