# Changelog

## v2.0.0

This release includes breaking changes such as the removal of the user_settings
module and changes to exceptions raised during artifact recording. Additionally,
it incorporates changes for issues captured in security advisories
[GHSA-p86f-xmg6-9q4x](https://github.com/in-toto/docs/security/advisories/GHSA-p86f-xmg6-9q4x),
[GHSA-jjgp-whrp-gq8m](https://github.com/in-toto/in-toto/security/advisories/GHSA-jjgp-whrp-gq8m),
and
[GHSA-wc64-c5rv-32pf](https://github.com/in-toto/in-toto/security/advisories/GHSA-wc64-c5rv-32pf),
the last of which has been assigned
[CVE-2023-32076](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32076).

### Added
* Generic interface for ITE-4 resolvers (#584)
* ITE-4 resolver for OSTree repositories (#585)
* Warning when `--bits` is used with non RSA keys in `in-toto-keygen` (#588)
* Support for GitHub's security reporting feature (#567)
* Tool to check local artifacts against in-toto link metadata
  (#589, GHSA-p86f-xmg6-9q4x)
* Testing in CI for Python 3.11 (#594)

### Changed
* Recording of file hashes to use ITE-4 file resolver (#584)
* Exceptions returned to Python defaults when recording file artifacts (#592)
* Documentation about in-toto governance to reflect project changes (#591)
* Code style to use black + isort, includes update to codebase to conform (#593)
* Verification documentation to reflect how PGP trust model is used
  (GHSA-jjgp-whrp-gq8m)

### Removed
* Support for user_settings module that enabled configuring in-toto via RC files
  and environment variables (GHSA-wc64-c5rv-32pf)

## v1.4.0

### Added
* Support for DSSE in metadata generation tools (#503, #577)
* Ability to set command, byproducts, environment in the in_toto_record APIs (#564)

### Changed
* Various dependency updates and dependabot changes
* Simplified link threshold check (#573)
