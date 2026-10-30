### Added

- `prufyx db update` now pins the official knowledge feed to its signing root (`sha256:11eff27032c4a3db126d030ae860e881e8e0dd1e7c37fcc4f10ef5fde70a326a`). With no flags it fetches the signed knowledge database from the official feed and refuses any package not signed from that root. See `cli/docs/knowledge-updates.md`.
