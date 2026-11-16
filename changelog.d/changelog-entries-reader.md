### Added

- A pinned changelog entry reader (inert library): for a reviewed target and a release tag it reads the changelog file at that tag's own commit, finds the tag's single entry, proves its section bounds and that every line is a heading, a blank, a link definition or inside one digested item, and withholds anything else with a typed reason. It is not an extractor, makes no attestation and is not wired into any command.
