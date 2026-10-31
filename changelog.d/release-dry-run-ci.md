### Added (workflows)

- A release dry run now runs in CI on pull requests that touch the release workflow, its documentation or the files the packages carry: it executes the release build, package and checksum steps with a dry-run tag, with no secret, tag or upload, and checks the archives, a byte-identical rebuild, `.deb`/`.rpm` identical across two host names, the package binary against the archive binary, `SHA256SUMS` and the freshness gate.
