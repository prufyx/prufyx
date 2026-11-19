### Added
- `prufyx version` now reports `knowledgeRootDigest` (JSON) and `knowledge root <digest>` (human): the pinned initial root of the official `cncf-projects` knowledge feed, read from the compiled-in pin that `db update` verifies with, so it cannot drift from verification. `trustRootDigest` is unchanged: it is the release-signing slot and stays `UNPINNED` in beta builds.
