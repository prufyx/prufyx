# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Try to keep listed changes to a concise bulleted list of simple explanations of changes. Aim for the amount of information needed so that readers can understand where they would look in the codebase to investigate the changes' implementation, or where they would look in the documentation to understand how to make use of the change in practice - better yet, link directly to the docs and provide detailed information there. Only elaborate if doing so is required to avoid breaking changes or experimental features from ruining someone's day.

## [Unreleased]

## [1.17.0] - 2026-06-02
### Added
- Added a configurable trace sampler via `trace.sampler` (`OPENFGA_TRACE_SAMPLER` / `OTEL_TRACES_SAMPLER`), supporting the standard OpenTelemetry strategies `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, and `parentbased_traceidratio`. This lets OpenFGA honor upstream parent sampling decisions when running as a downstream service. Defaults to `traceidratio` to preserve existing behavior. [#3072](https://github.com/openfga/openfga/pull/3072) Thanks [@armujahid](https://github.com/armujahid)!

### Changed
- Redesigned cache key generation to use TLV (type-length-value) binary encoding, eliminating collision risk from string concatenation and adding per-process hash seeding to prevent hash-flooding attacks. [#3148](https://github.com/openfga/openfga/pull/3148)

## [1.16.1] - 2026-05-28
### Changed
- Added workflow-level `concurrency.group` and `cancel-in-progress` for PR-related workflow runs to reduce wasted effort. [#3140](https://github.com/openfga/openfga/pull/3140)

### Fixed
- Fixed experimental `weighted_graph_check` incorrectly falling back to the standard algorithm on deadline/cancellation/throttle-timeout errors; these are now returned directly. Also fixed `weighted_graph_check` emitting metrics under the wrong method label when used as the primary algorithm. [#3141](https://github.com/openfga/openfga/pull/3141)
- Fixed a bug in experimental `weighted_graph_check` where the `weight2` strategy could return false denies when contextual tuples were present, because their concatenation with datastore results violated the sort assumption of the pruning optimization. [#3145](https://github.com/openfga/openfga/pull/3145)

### Security
- Update grpc-health-probe to `v0.4.50` to address multiple CVEs in the go std lib. [#3146](https://github.com/openfga/openfga/pull/3146)
