### Added

- `prufyx-maintainer approval verify --onboarding-signature` checks only the signature of an onboarding batch and prints the artifact paths and digests it commits to. It grants no admission.
- The QA batch gate accepts a new CRD version target repository when a signed onboarding batch added by the same change commits to the target file, with the signature verified by the maintainer tool built from the base tree.
