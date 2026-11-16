### Changed

- The CRD version-removal scan records a Helm template partial that names the CustomResourceDefinition kind only inside literal `fail` messages as a finding that does not block attestation, instead of an unsupported source. Any other use of the name keeps the file unsupported.
