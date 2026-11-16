# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

NOTE: As semantic versioning states all 0.y.z releases can contain breaking changes in API (flags, grpc API, any backward compatibility)

We use *breaking :warning:* to mark changes that are not backward compatible (relates only to v0.y.z releases.)

## Unreleased

### Added

### Changed

### Removed

### Fixed

## [v0.38.0] https://github.com/thanos-io/thanos/tree/release-0.38) - 03.04.2025

### Fixed
- [#8091](https://github.com/thanos-io/thanos/pull/8091) *: Add POST into allowed CORS methods header
- [#8046](https://github.com/thanos-io/thanos/pull/8046) Query-Frontend: Fix query statistic reporting for range queries when caching is enabled.
- [#7978](https://github.com/thanos-io/thanos/pull/7978) Receive: Fix deadlock during local writes when `split-tenant-label-name` is used
- [#8016](https://github.com/thanos-io/thanos/pull/8016) Query Frontend: Fix @ modifier not being applied correctly on sub queries.

### Added

- [#7907](https://github.com/thanos-io/thanos/pull/7907) Receive: Add `--receive.grpc-service-config` flag to configure gRPC service config for the receivers.
- [#7961](https://github.com/thanos-io/thanos/pull/7961) Store Gateway: Add `--store.posting-group-max-keys` flag to mark posting group as lazy if it exceeds number of keys limit. Added `thanos_bucket_store_lazy_expanded_posting_groups_total` for total number of lazy posting groups and corresponding reasons.
- [#8000](https://github.com/thanos-io/thanos/pull/8000) Query: Bump promql-engine, pass partial response through options
- [#7353](https://github.com/thanos-io/thanos/pull/7353) [#8045](https://github.com/thanos-io/thanos/pull/8045) Receiver/StoreGateway: Add `--matcher-cache-size` option to enable caching for regex matchers in series calls.
- [#8017](https://github.com/thanos-io/thanos/pull/8017) Store Gateway: Use native histogram for binary reader load and download duration and fixed download duration metric. #8017
- [#8131](https://github.com/thanos-io/thanos/pull/8131) Store Gateway: Optimize regex matchers for .* and .+. #8131
- [#7808](https://github.com/thanos-io/thanos/pull/7808) Query: Support chain deduplication algorithm.
- [#8158](https://github.com/thanos-io/thanos/pull/8158) Rule: Add support for query offset.
- [#8110](https://github.com/thanos-io/thanos/pull/8110) Compact: implement native histogram downsampling.
- [#7996](https://github.com/thanos-io/thanos/pull/7996) Receive: Add OTLP endpoint.

### Changed

- [#7890](https://github.com/thanos-io/thanos/pull/7890) Query,Ruler: *breaking :warning:* deprecated `--store.sd-file` and `--store.sd-interval` to be replaced with `--endpoint.sd-config` and `--endpoint-sd-config-reload-interval`; removed legacy flags to pass endpoints `--store`, `--metadata`, `--rule`, `--exemplar`.
- [#7012](https://github.com/thanos-io/thanos/pull/7012) Query: Automatically adjust `max_source_resolution` based on promql query to avoid querying data from higher resolution resulting empty results.
- [#8118](https://github.com/thanos-io/thanos/pull/8118) Query: Bumped promql-engine
- [#8135](https://github.com/thanos-io/thanos/pull/8135) Query: respect partial response in distributed engine
- [#8181](https://github.com/thanos-io/thanos/pull/8181) Deps: bump promql engine

### Removed

## [v0.37.2](https://github.com/thanos-io/thanos/tree/release-0.37) - 11.12.2024

### Fixed

- [#7970](https://github.com/thanos-io/thanos/pull/7970) Sidecar: Respect min-time setting.
- [#7962](https://github.com/thanos-io/thanos/pull/7962) Store: Fix potential deadlock in hedging request.
- [#8175](https://github.com/thanos-io/thanos/pull/8175) Query: fix endpointset setup

### Added

### Changed

### Removed

## [v0.37.1](https://github.com/thanos-io/thanos/tree/release-0.37) - 04.12.2024

### Fixed

- [#7674](https://github.com/thanos-io/thanos/pull/7674) Query-frontend: Fix connection to Redis cluster with TLS.
- [#7945](https://github.com/thanos-io/thanos/pull/7945) Receive: Capnproto - use segment from existing message.
- [#7941](https://github.com/thanos-io/thanos/pull/7941) Receive: Fix race condition when adding multiple new tenants, see [issue-7892](https://github.com/thanos-io/thanos/issues/7892).
- [#7954](https://github.com/thanos-io/thanos/pull/7954) Sidecar: Ensure limit param is positive for compatibility with older Prometheus.
- [#7953](https://github.com/thanos-io/thanos/pull/7953) Query: Update promql-engine for subquery avg fix.

### Added

### Changed

### Removed
