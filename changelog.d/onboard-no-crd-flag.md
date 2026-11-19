### Changed
- `prufyx-maintainer onboard-bundle build` now refuses when no CRD paths are declared and `--no-crds` is not given, so "no CRDs" is always an explicit declaration. With `--tag-prefix` and no `--tags`, tags outside the prefix (for example chart-release tags) are ignored; an explicit `--tags` list that conflicts with the prefix is still refused, with a clearer message. 
