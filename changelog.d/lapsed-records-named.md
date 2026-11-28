### Fixed

- `plan --to C=newest-covered` now names a newer release line that the knowledge mentions but cannot choose, for example because its list expired or was removed, as a `LINE_NOT_ATTESTED` gap.
- A `helm.sh/chart` label of a reviewed chart is no longer ignored when the chart source expired or was withdrawn: beside an app version label it is a `VERSION_CONFLICT`, and the version has to be declared with `--from`.
