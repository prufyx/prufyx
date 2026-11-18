### Changed
- Raise the Longhorn CRD target floor to 1.10: the 1.9 to 1.10 hop cannot be attested because the full-tree scan finds unread files under `chart/templates/` at v1.9.0, v1.9.1 and v1.9.2; the 1.10 to 1.13 hops attest. This configuration change publishes no compatibility records.
