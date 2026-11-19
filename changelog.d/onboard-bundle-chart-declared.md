### Added
- `prufyx-maintainer onboard-bundle build` takes optional `--chart-path` and `--chart-version` (given together) so a project without CRDs can declare the chart that is its evidence. Both are declared, never derived; the path must be a file the verified snapshot holds, or a directory containing one, at a built tag. They are stored in the optional `project.json` field `chart` (new optional field in the bundle schema; bundles without it stay valid) and are only a hint: they never set a verdict or coverage.

### Fixed
- `onboard-bundle build`: the scan note for tags ignored by `--tag-prefix` is now clipped to the 300-character schema limit even when a single tag name or the prefix is very long.
