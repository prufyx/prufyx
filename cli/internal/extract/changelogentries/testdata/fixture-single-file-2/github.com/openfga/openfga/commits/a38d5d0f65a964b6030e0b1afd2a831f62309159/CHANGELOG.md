# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Try to keep listed changes to a concise bulleted list of simple explanations of changes. Aim for the amount of information needed so that readers can understand where they would look in the codebase to investigate the changes' implementation, or where they would look in the documentation to understand how to make use of the change in practice - better yet, link directly to the docs and provide detailed information there. Only elaborate if doing so is required to avoid breaking changes or experimental features from ruining someone's day.

## [Unreleased]

## [1.22.0] - 2026-10-06
### Added
- Added read-replica (primary/secondary) support to the MySQL datastore backend, matching the existing PostgreSQL behaviour. Configure a secondary connection via `--datastore-secondary-uri` (or `OPENFGA_DATASTORE_SECONDARY_URI`); all reads except those requesting `HIGHER_CONSISTENCY` are routed to the replica while all writes remain on the primary. `GetStore`, `ListStores`, `ReadAssertions`, `ReadAuthorizationModel`, `ReadAuthorizationModels`, `FindLatestAuthorizationModel`, and `ReadChanges` always hit the replica when configured regardless of requested consistency — callers should be aware of read-after-write risk on a lagging replica. See `pkg/storage/mysql/mysql.go`. **Breaking:** `mysql.NewWithDB` gained a required `secondaryDB *sql.DB` parameter (pass `nil` if no replica is configured); `sqlcommon.ReadAuthorizationModel` and `sqlcommon.FindLatestAuthorizationModel` were removed and moved to per-backend implementations. [#3290](https://github.com/openfga/openfga/pull/3290) Thanks [@chiragsoni-eternal](https://github.com/chiragsoni-eternal) for the contribution!

### Changed
- Various dependency updates. Minimum go version updated to `1.26.0`. [#3329](https://github.com/openfga/openfga/pull/3329), [#3328](https://github.com/openfga/openfga/pull/3328), [#3324](https://github.com/openfga/openfga/pull/3324)

### Fixed
- `ReadUserTuple` now returns the tuple's timestamp for the Postgres, MySQL, and SQLite datastores; it previously returned a zero timestamp because the query did not select `inserted_at`. [#3194](https://github.com/openfga/openfga/pull/3194) Thanks [@nikolauspschuetz](https://github.com/nikolauspschuetz) for the contribution!

### Security
- Updated google.golang.org/grpc to v1.83.2 to resolve [GO-2026-6443](https://pkg.go.dev/vuln/GO-2026-6443). [#3317](https://github.com/openfga/openfga/pull/3317)

## [1.21.0] - 2026-09-20
### Added
- Added "Dynamic Conditions" as a new experimental feature. [#3313](https://github.com/openfga/openfga/pull/3313)
