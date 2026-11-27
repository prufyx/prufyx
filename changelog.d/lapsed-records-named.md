### Fixed

- `plan --to C=newest-covered` now names a newer release line that the knowledge mentions but cannot choose, for example because its list expired or was removed, as a `LINE_NOT_ATTESTED` gap.
- A `helm.sh/chart` label named like a project is no longer ignored when there is no usable chart source for it: beside an app version label it is a `VERSION_CONFLICT`, and the version has to be declared with `--from`.
