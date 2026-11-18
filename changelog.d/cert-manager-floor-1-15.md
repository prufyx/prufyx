### Changed
- Lower the cert-manager CRD target floor to 1.15: the 1.15 to 1.16 hop now attests at the upstream tags (full-tree scan clean at v1.15.x and v1.16.x). Floors below 1.15 stay out: at v1.14.x and earlier the tree holds a test-only definition under `pkg/webhook/handlers/testdata/` that no reviewed exclusion covers. This configuration change publishes no compatibility records.
