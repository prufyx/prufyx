### Changed
- Raise the Longhorn CRD target floor to 1.9: the 1.8 to 1.9 hop cannot be attested because the CRD manifests of those releases sit in a chart-templated file the extractor does not read; the 1.9 to 1.13 hops attest. This configuration change publishes no compatibility records.
