# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

NOTE: As semantic versioning states all 0.y.z releases can contain breaking changes in API (flags, grpc API, any backward compatibility)

We use *breaking :warning:* to mark changes that are not backward compatible (relates only to v0.y.z releases.)

## [v0.37.0](https://github.com/thanos-io/thanos/tree/release-0.37) - 25.11.2024

### Fixed

- [#7511](https://github.com/thanos-io/thanos/pull/7511) Query Frontend: fix doubled gzip compression for response body.
- [#7592](https://github.com/thanos-io/thanos/pull/7592) Ruler: Only increment `thanos_rule_evaluation_with_warnings_total` metric for non PromQL warnings.
- [#7614](https://github.com/thanos-io/thanos/pull/7614) *: fix debug log formatting.
- [#7492](https://github.com/thanos-io/thanos/pull/7492) Compactor: update filtered blocks list before second downsample pass.
- [#7658](https://github.com/thanos-io/thanos/pull/7658) Store: Fix panic because too small buffer in pool.
- [#7643](https://github.com/thanos-io/thanos/pull/7643) Receive: fix thanos_receive_write_{timeseries,samples} stats
- [#7644](https://github.com/thanos-io/thanos/pull/7644) fix(ui): add null check to find overlapping blocks logic
- [#7814](https://github.com/thanos-io/thanos/pull/7814) Store: label_values: if matchers contain **name**=="something", do not add <labelname> != "" to fetch less postings.
- [#7679](https://github.com/thanos-io/thanos/pull/7679) Query: respect store.limit.* flags when evaluating queries
- [#7821](https://github.com/thanos-io/thanos/pull/7821) Query/Receive: Fix coroutine leak introduced in https://github.com/thanos-io/thanos/pull/7796.
- [#7843](https://github.com/thanos-io/thanos/pull/7843) Query Frontend: fix slow query logging for non-query endpoints.
- [#7852](https://github.com/thanos-io/thanos/pull/7852) Query Frontend: pass "stats" parameter forward to queriers and fix Prometheus stats merging.
- [#7832](https://github.com/thanos-io/thanos/pull/7832) Query Frontend: Fix cache keys for dynamic split intervals.
- [#7885](https://github.com/thanos-io/thanos/pull/7885) Store: Return chunks to the pool after completing a Series call.
- [#7893](https://github.com/thanos-io/thanos/pull/7893) Sidecar: Fix retrieval of external labels for Prometheus v3.0.0.
- [#7903](https://github.com/thanos-io/thanos/pull/7903) Query: Fix panic on regex store matchers.
- [#7915](https://github.com/thanos-io/thanos/pull/7915) Store: Close block series client at the end to not reuse chunk buffer

### Added

- [#7763](https://github.com/thanos-io/thanos/pull/7763) Ruler: use native histograms for client latency metrics.
- [#7609](https://github.com/thanos-io/thanos/pull/7609) API: Add limit param to metadata APIs (series, label names, label values).
- [#7429](https://github.com/thanos-io/thanos/pull/7429): Reloader: introduce `TolerateEnvVarExpansionErrors` to allow suppressing errors when expanding environment variables in the configuration file. When set, this will ensure that the reloader won't consider the operation to fail when an unset environment variable is encountered. Note that all unset environment variables are left as is, whereas all set environment variables are expanded as usual.
- [#7560](https://github.com/thanos-io/thanos/pull/7560) Query: Added the possibility of filtering rules by rule_name, rule_group or file to HTTP api.
- [#7652](https://github.com/thanos-io/thanos/pull/7652) Store: Implement metadata API limit in stores.
- [#7659](https://github.com/thanos-io/thanos/pull/7659) Receive: Add support for replication using [Cap'n Proto](https://capnproto.org/). This protocol has a lower CPU and memory footprint, which leads to a reduction in resource usage in Receivers. Before enabling it, make sure that all receivers are updated to a version which supports this replication method.
- [#7853](https://github.com/thanos-io/thanos/pull/7853) UI: Add support for selecting graph time range with mouse drag.
- [#7855](https://github.com/thanos-io/thanos/pull/7855) Compcat/Query: Add support for comma separated replica labels.
- [#7654](https://github.com/thanos-io/thanos/pull/7654) *: Add '--grpc-server-tls-min-version' flag to allow user to specify TLS version, otherwise default to TLS 1.3
- [#7854](https://github.com/thanos-io/thanos/pull/7854) Query Frontend: Add `--query-frontend.force-query-stats` flag to force collection of query statistics from upstream queriers.
- [#7860](https://github.com/thanos-io/thanos/pull/7860) Store: Support hedged requests
- [#7924](https://github.com/thanos-io/thanos/pull/7924) *: Upgrade promql-engine to `v0.0.0-20241106100125-097e6e9f425a` and objstore to `v0.0.0-20241111205755-d1dd89d41f97`
- [#7835](https://github.com/thanos-io/thanos/pull/7835) Ruler: Add ability to do concurrent rule evaluations
- [#7722](https://github.com/thanos-io/thanos/pull/7722) Query: Add partition labels flag to partition leaf querier in distributed mode

### Changed

- [#7494](https://github.com/thanos-io/thanos/pull/7494) Ruler: remove trailing period from SRV records returned by discovery `dnsnosrva` lookups
- [#7567](https://github.com/thanos-io/thanos/pull/7565) Query: Use thanos resolver for endpoint groups.
- [#7741](https://github.com/thanos-io/thanos/pull/7741) Deps: Bump Objstore to `v0.0.0-20240913074259-63feed0da069`
- [#7813](https://github.com/thanos-io/thanos/pull/7813) Receive: enable initial TSDB compaction time randomization
- [#7820](https://github.com/thanos-io/thanos/pull/7820) Sidecar: Use prometheus metrics for min timestamp
- [#7886](https://github.com/thanos-io/thanos/pull/7886) Discovery: Preserve results from other resolve calls
- [#7745](https://github.com/thanos-io/thanos/pull/7745) *: Build with Prometheus stringlabels tags
- [#7669](https://github.com/thanos-io/thanos/pull/7669) Receive: Change quorum calculation for rf=2

### Removed

- [#7704](https://github.com/thanos-io/thanos/pull/7704) *: *breaking :warning:* remove Store gRPC Info function. This has been deprecated for 3 years, its time to remove it.
- [#7793](https://github.com/thanos-io/thanos/pull/7793) Receive: Disable dedup proxy in multi-tsdb
- [#7678](https://github.com/thanos-io/thanos/pull/7678) Query: Skip formatting strings if debug logging is disabled

## [v0.36.1](https://github.com/thanos-io/thanos/tree/release-0.36)

### Fixed

- [#7634](https://github.com/thanos-io/thanos/pull/7634) Rule: fix Query and Alertmanager TLS configurations with CA only.
- [#7618](https://github.com/thanos-io/thanos/pull/7618) Proxy: Query goroutine leak when store.response-timeout is set

### Added

### Changed

### Removed

## [v0.36.0](https://github.com/thanos-io/thanos/tree/release-0.36)

### Fixed

- [#7326](https://github.com/thanos-io/thanos/pull/7326) Query: fixing exemplars proxy when querying stores with multiple tenants.
- [#7403](https://github.com/thanos-io/thanos/pull/7403) Sidecar: fix startup sequence
- [#7484](https://github.com/thanos-io/thanos/pull/7484) Proxy: fix panic in lazy response set
- [#7493](https://github.com/thanos-io/thanos/pull/7493) *: fix server grpc histograms

### Added

- [#7317](https://github.com/thanos-io/thanos/pull/7317) Tracing: allow specifying resource attributes for the OTLP configuration.
- [#7367](https://github.com/thanos-io/thanos/pull/7367) Store Gateway: log request ID in request logs.
- [#7361](https://github.com/thanos-io/thanos/pull/7361) Query: *breaking :warning:* pass query stats from remote execution from server to client. We changed the protobuf of the QueryAPI, if you use `query.mode=distributed` you need to update your client (upper level Queriers) first, before updating leaf Queriers (servers).
- [#7363](https://github.com/thanos-io/thanos/pull/7363) Query-frontend: set value of remote_user field in Slow Query Logs from HTTP header
- [#7335](https://github.com/thanos-io/thanos/pull/7335) Dependency: Update minio-go to v7.0.70 which includes support for EKS Pod Identity.
- [#7477](https://github.com/thanos-io/thanos/pull/7477) *: Bump objstore to `20240622095743-1afe5d4bc3cd`

### Changed

- [#7334](https://github.com/thanos-io/thanos/pull/7334) Compactor: do not vertically compact downsampled blocks. Such cases are now marked with `no-compact-mark.json`. Fixes panic `panic: unexpected seriesToChunkEncoder lack of iterations`.
- [#7393](https://github.com/thanos-io/thanos/pull/7393) *: *breaking :warning:* Using native histograms for grpc middleware metrics. Metrics `grpc_client_handling_seconds` and `grpc_server_handling_seconds` will now be native histograms, if you have enabled native histogram scraping you will need to update your PromQL expressions to use the new metric names.

### Removed

## [v0.35.1](https://github.com/thanos-io/thanos/tree/release-0.35) - 28.05.2024

### Fixed

- [#7323](https://github.com/thanos-io/thanos/pull/7323) Sidecar: wait for prometheus on startup
- [#6948](https://github.com/thanos-io/thanos/pull/6948) Receive: fix goroutines leak during series requests to thanos store api.
- [#7382](https://github.com/thanos-io/thanos/pull/7382) *: Ensure objstore flag values are masked & disable debug/pprof/cmdline
- [#7392](https://github.com/thanos-io/thanos/pull/7392) Query: fix broken min, max for pre 0.34.1 sidecars
- [#7373](https://github.com/thanos-io/thanos/pull/7373) Receive: Fix stats for remote write
- [#7318](https://github.com/thanos-io/thanos/pull/7318) Compactor: Recover from panic to log block ID

### Added

### Changed

### Removed
