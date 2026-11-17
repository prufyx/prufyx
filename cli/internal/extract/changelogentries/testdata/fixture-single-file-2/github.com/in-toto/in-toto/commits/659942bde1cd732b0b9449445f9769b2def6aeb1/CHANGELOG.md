# Changelog

## v3.0.0

This release, most notably, marks stable securesystemslib v1.0.0 as minimum
requirement, and, as a consequence, removes the recently deprecated CLI/API arguments (see below).

### Changed
Update securesystemslib v1.0.0 (#740)

### Removed
Remove deprecated CLI/API arguments and legacy securesystemslib integration (#739)

## v2.3.0

### Added
* in-toto-verify CLI: `--inspection-timeout` arg (#695)

### Changed
* Improve Dependabot config (#701)
* Constrain securesystemslib dependency to <0.32.0 in preparation for future
  securesystemslib API changes (#726)

### Removed
* Obsolete six dependency in debian/control (#687)
