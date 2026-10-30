### Added (workflows)

- The knowledge publish workflow now verifies every new package with the oldest supported client before it uploads it (`cli/knowledge/oldest-supported-client.txt`). If that client cannot be built or refuses the package, the run fails and the feed keeps serving the last package. See `cli/docs/knowledge-publisher.md`.
