### Documentation

- The maintainer onboarding docs now start with a routing paragraph (check whether the project is bundled, which form to use, what follows an invite), say to pass `--slug`, explain a sync without changelog bytes, name the steps that are not automated yet, and the Go check in the build block prints what is needed and found and accepts any Go 1.26 patch release.
- Onboarding bundle README: a table of where each bundle field comes from, the scan-notes class list (checked against the schema by a test), a note that a hand-written target draft is only a hint, how the release window picks releases, and how `--changelog-paths` works for per-minor changelog files.

### Fixed

- `prufyx-maintainer project <subcommand> --help` (and `-h`) now prints the usage and exits 0 instead of exiting 2 with a generic error.
- Docs: projects without CRDs are in scope (chart families, permanent gap for projects with no cluster API surface), what `--no-crds` changes, and tag-prefix guidance for repositories that publish chart-release tags.
