### Added
- Added a bounded source check for Antrea's four multicluster installation modes. Line attestation refuses changed source recipes, unknown modes and mode-specific API removals even when another mode retains the API.
- Added a source-bound installed-dependency check for the two pinned multicluster service APIs without assigning their shared group to Antrea.
