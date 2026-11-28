### Changed

- The knowledge gate refuses an automated reattestation statement unless the base holds a signed owner exception for every record it renews (record, base digest, expiry). `approval carry-exception` signs one.
- The weekly workflow that carried reviewed dates forward with an automation key is removed.

### Added (workflows)

- A scheduled workflow that renews due custom-resource records only by deriving them again on two separate runners and requiring byte-identical results. It opens at most one pull request, only when the repository owner has switched it on, and never merges.
