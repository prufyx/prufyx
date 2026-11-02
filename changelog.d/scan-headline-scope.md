### Changed

- `prufyx scan` PASS headline now names its scope: `PASS FOR THE DECLARED SCOPE (Kubernetes API versions in the supplied manifests only; not a whole-upgrade pass)`. Supplied documents of custom resources or kinds outside the Kubernetes API groups are listed under "Scope limits" (JSON `omissions`) as not evaluated.
