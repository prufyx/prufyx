### Changed
- Raise the Longhorn CRD target floor to 1.9: the 1.8 to 1.9 hop cannot be attested because the chart-copy check cannot read the templated chart file `chart/templates/crds.yaml` at v1.9.0 (the listed `deploy/longhorn.yaml` itself is read); the 1.9 to 1.13 hops attest. This configuration change publishes no compatibility records.
