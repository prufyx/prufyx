# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

NOTE: As semantic versioning states all 0.y.z releases can contain breaking changes in API (flags, grpc API, any backward compatibility)

We use *breaking :warning:* to mark changes that are not backward compatible (relates only to v0.y.z releases.)

## Unreleased

### Fixed

### Added

### Changed

### Removed

## [v0.33.0](https://github.com/thanos-io/thanos/tree/release-0.33) - 18.12.2023

### Fixed

- [#6817](https://github.com/thanos-io/thanos/pull/6817) Store Gateway: fix `matchersToPostingGroups` label values variable got shadowed bug.

### Added
- [#6891](https://github.com/thanos-io/thanos/pull/6891) Objstore: Bump `objstore` which adds support for Azure Workload Identity.
- [#6605](https://github.com/thanos-io/thanos/pull/6605) Query Frontend: Support vertical sharding binary expression with metric name when no matching labels specified.
- [#6308](https://github.com/thanos-io/thanos/pull/6308) Ruler: Support configuration flag that allows customizing template for alert message.
- [#6760](https://github.com/thanos-io/thanos/pull/6760) Query Frontend: Added TLS support in `--query-frontend.downstream-tripper-config` and `--query-frontend.downstream-tripper-config-file`
- [#6749](https://github.com/thanos-io/thanos/pull/6749) Store Gateway: Added `thanos_store_index_cache_fetch_duration_seconds` histogram for tracking latency of fetching data from index cache.
- [#6690](https://github.com/thanos-io/thanos/pull/6690) Store: *breaking :warning:* Add tenant label to relevant exported metrics. Note that this change may cause some pre-existing dashboard queries to be incorrect due to the added label.
- [#6530](https://github.com/thanos-io/thanos/pull/6530) / [#6690](https://github.com/thanos-io/thanos/pull/6690) Query: Add command line arguments for configuring tenants and forward tenant information to Store Gateway.
- [#6765](https://github.com/thanos-io/thanos/pull/6765) Index Cache: Add `enabled_items` to index cache config to selectively cache configured items. Available item types are `Postings`, `Series` and `ExpandedPostings`.
- [#6773](https://github.com/thanos-io/thanos/pull/6773) Index Cache: Add `ttl` to control the ttl to store items in remote index caches like memcached and redis.
- [#6794](https://github.com/thanos-io/thanos/pull/6794) Query: *breaking :warning:* Add tenant label to relevant exported metrics. Note that this change may cause some pre-existing custom dashboard queries to be incorrect due to the added label.

### Changed

- [#6698](https://github.com/thanos-io/thanos/pull/6608) Receive: Change write log level from warn to info.
- [#6753](https://github.com/thanos-io/thanos/pull/6753) mixin(Rule): *breaking :warning:* Fixed the mixin rules with duplicate names and updated the promtool version from v0.37.0 to v0.47.0
- [#6772](https://github.com/thanos-io/thanos/pull/6772) *: Bump prometheus to v0.47.2-0.20231006112807-a5a4eab679cc
- [#6794](https://github.com/thanos-io/thanos/pull/6794) Receive: the exported HTTP metrics now uses the specified default tenant for requests where no tenants are found.

### Removed

- [#6686](https://github.com/thanos-io/thanos/pull/6686) Remove deprecated `--log.request.decision` flag. We now use `--request.logging-config` to set logging decisions.

## [v0.32.5](https://github.com/thanos-io/thanos/tree/release-0.32) - 18.10.2023
