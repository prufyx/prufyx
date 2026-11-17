# Changelog

## v2.2.0
__NOTE:__  This release, fully integrates the new [securesystemslib Signer API
](https://python-securesystemslib.readthedocs.io/en/latest/signer.html).
Most notably, runlib API methods receive a new optional argument to sign
the resulting metadata with a securesystemslib  `Signer` (see securesystemslib
for available implementations). In addition, the in-toto CLI provides new
arguments to read consistent standard key file formats for signing (PEM/PKCS8)
and signature verification (PEM/subjectPublicKeyInfo).

Related legacy key arguments are deprecated and will be removed in the next
major release. securesystemslib provides a script to [migrate key files
](https://github.com/secure-systems-lab/securesystemslib#legacy-key-migration).

### Added
- in-toto-run/record CLI: `--signing-key` arg (#649, #651)
- in-toto-verify CLI: `--verification-keys` arg (#652)
- runlib API: `signer` arg (#612)
- Release automation with PyPI Trusted Publishers (#674)

### Changed
- Update key file formats in internal in-toto-sign CLI (#654)
- Refactor model methods to use modern Signer API (#653, #660)
- Refactor model and input validation (#665)
- Misc CI improvements (#635, #636, #637, #650)
- Misc docs improvements (#641, #664)
- Misc test improvements (#655, #656, #668)

### Deprecated
- in-toto-run/record CLI: `-k`, `--key` arg (#649, #651)
- in-toto-verify CLI: `-k`, `--layout-keys` arg (#674)
- runlib API: `signing_key` arg (#612)
- model API: `Metablock.sign()` method (#659)

### Removed
- Python 3.7 support (#634)
- in-toto-keygen CLI (#657)

## v2.1.1

### Changed
* Default type for CLI arg `--run-timeout` to avoid type mismatch (#626)
* Dependency update (#627)
