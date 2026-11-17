# Changelog

## v3.1.0

This release includes version bumpbs, as well as upgraded debian support , and
ruff support

### Changed
* Code style to use ruff, includes update to codebase to conform (#837, #840)
* Refresh debian dependencies and build rules (#898)
* ports sslib hash function into in-toto due to sslib deprecation (#861)
* Documentation updates, both on pipeline (#779) and contents (#751, #760, 
                                                               #758, #818)
* Add pass through for in-toto run command line return (#868)

## v3.0.0

This release, most notably, marks stable securesystemslib v1.0.0 as minimum
requirement, and, as a consequence, removes the recently deprecated CLI/API arguments (see below).

### Changed
Update securesystemslib v1.0.0 (#740)

### Removed
Remove deprecated CLI/API arguments and legacy securesystemslib integration (#739)
