### Added

- `prufyx-maintainer release-docs check` refuses release notes, CHANGELOG entries and README text whose generated blocks differ from their regeneration or that carry a hand-typed number or coverage claim; CI runs it for every unpublished release notes file and the release workflow runs it as a job every other job needs.
