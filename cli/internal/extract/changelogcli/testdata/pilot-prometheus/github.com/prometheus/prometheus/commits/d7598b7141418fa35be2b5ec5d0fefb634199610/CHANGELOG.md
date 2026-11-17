# Changelog

## 3.14.0 / 2026-08-17

- [CHANGE] API: Deprecate the `stats` query parameter of `/api/v1/query` and `/api/v1/query_range` for values other than `true` and `all`. Other values still enable basic statistics but now return a deprecation warning; they will be rejected in the next major release. #19124
- [CHANGE] API: `/api/v1/status/config` now correctly shows `separator: ""` and `replacement: ""` in relabel configs when explicitly set to empty, instead of omitting them. #18653
- [CHANGE] Discovery/Hetzner: Drop the `__meta_hetzner_datacenter` label for `hcloud` targets, following its removal from the Hetzner Cloud API. #19269
- [CHANGE] PromQL: Enable duration expressions by default. The `promql-duration-expr` feature flag is now a no-op. #19033
- [CHANGE] PromQL: Promote `first_over_time` to stable. It no longer requires the `promql-experimental-functions` feature flag. #19093
- [FEATURE] Discovery: Add Oracle Cloud Infrastructure compute service discovery (`oci_sd_configs`). #18919
- [FEATURE] PromQL: Add experimental `start_timestamp(instant-vector)` function returning the start timestamp of each sample in the given vector. Requires the `use-start-timestamps` feature flag. #19089
- [FEATURE] PromQL: Allow `rate()` and `increase()` to use start timestamps as an alternative for rate extrapolation. Hidden behind the `use-start-timestamps` feature flag. #18619
- [FEATURE] TSDB: Add experimental support for encoding start timestamps in histograms and float histograms. Hidden behind the `histograms-st-encoding` feature flag. #18609
- [ENHANCEMENT] OTLP: Emit a warning when OTLP attribute names collide into the same Prometheus label after sanitization (e.g. `k8s.pod.name` and `k8s_pod_name` both become `k8s_pod_name`), and expose the `prometheus_api_otlp_translation_warnings_total` counter labelled by `category` to track such warnings. #18957
- [ENHANCEMENT] Promtool: Add `--remote-write.path` flag to `push metrics` for backends that use a non-default remote-write endpoint. #19086
- [ENHANCEMENT] Remote write: Forward histogram start timestamps in the remote write V2 protocol. #18903
- [ENHANCEMENT] TSDB: Add `prometheus_tsdb_head_native_histogram_series` and `prometheus_tsdb_head_native_histogram_buckets` gauges tracking the number of native histogram series and buckets in the head. #19170
- [ENHANCEMENT] UI: Add syntax highlighting, autocompletion, and linting for PromQL duration expressions (`step()`, `range()`, `min_of()`, `max_of()`) in range selectors and subqueries. #18625
- [ENHANCEMENT] UI: Add copy button next to rule names on the Rules and Alerts pages. #18706
- [ENHANCEMENT] UI: Improve rule group title contrast on the Rules page. #19181
- [PERF] Speed up regex label matchers matching a set of literal values (e.g. `{job=~"foo|bar|baz"}`). #18833
- [PERF] Remote read: Improve remote read throughput by removing unnecessary per-write flushing. #18470
- [PERF] Scrape: Parse text and OpenMetrics formats without recursion, preventing stack overflow from deeply nested or malicious exposition input. #19143
- [PERF] Scrape: Reduce native histogram scrape parsing allocations by ~49%. #19282
- [PERF] TSDB: Speed up queries on series with many in-memory chunks. #18300
- [BUGFIX] Alerting: Fix 100% CPU usage on shutdown that could delay graceful shutdown and trigger timeout-based kills. #17859
- [BUGFIX] Discovery/AWS: Stop `promtool check config` from making AWS metadata service (IMDS) network calls when the `region` field is omitted in EC2, ECS, RDS, MSK, ElastiCache, and Lightsail service discovery configs. #19037
- [BUGFIX] Discovery/Docker: Set a request timeout for `docker_sd` and `dockerswarm_sd` on `unix`, `npipe`, and `tcp` hosts. Previously an unresponsive daemon could freeze discovery indefinitely, silently pinning targets to a stale snapshot. #19237
- [BUGFIX] Discovery/Docker: Fix panic in Docker Swarm service discovery when a service runs as a plugin or network-attachment. #19102
- [BUGFIX] Discovery/Docker: Fix discovery of IPv6-only containers. #18778
- [BUGFIX] PromQL: Fix case-insensitive regex label matchers silently dropping matching values. #19167
- [BUGFIX] PromQL: Fix `mad_over_time` returning 0 instead of `NaN` when the range contains a `NaN` sample. #19040
- [BUGFIX] Promtool: Accept `--enable-feature=promql-binop-fill-modifiers` in `check rules`, which previously rejected valid `fill()`/`fill_left()`/`fill_right()` expressions. #19153
- [BUGFIX] Remote write: Respect the `AZURE_FEDERATED_TOKEN_FILE` environment variable for workload identity authentication instead of hardcoding the token file path. #18973
- [BUGFIX] Rules: Clean up stale `rule_group_last_rule_duration_sum_seconds` and `rule_group_last_restore_duration_seconds` series when a rule group is removed or renamed on reload. Previously each reload leaked two series per dropped group, growing `/metrics` cardinality over time. #19107
- [BUGFIX] Scrape: Fix scrape manager spinning at 100% CPU on shutdown. #19149
- [BUGFIX] TSDB: Fix silent data loss and potential crash loop when `stale_series_compaction_threshold` is used in the config file. #19016
- [BUGFIX] TSDB: Fix potential data loss on restart when out-of-order ingestion is enabled and blocks are compacted. #19016
- [BUGFIX] TSDB: Fix `prometheus_tsdb_head_stale_series` over-counting and early eviction of series that change between float, integer histogram, and float histogram sample types. #19183
- [BUGFIX] TSDB: Fix goroutine and file handle leaks when Prometheus fails to open a corrupt TSDB. On Windows, the leaked directory handle also prevented TSDB directory removal. #18291
- [BUGFIX] TSDB: Fix out-of-order queries blocking compaction for hours, causing memory usage to grow. #19013
- [BUGFIX] TSDB: Fix deleted series causing missing samples and errors after restart. #19140
- [BUGFIX] TSDB: Fix native histogram data becoming incorrect after restart. #19202
- [BUGFIX] TSDB: Surface query errors that were previously silently discarded. #19120
- [BUGFIX] TSDB: Honour the configured float chunk encoding when compaction rewrites chunks; previously chunks encoded with `--enable-feature=xor2-encoding` could silently revert to XOR after compaction. #19145
- [BUGFIX] UI: Show the delete-series form on the TSDB Status page when `--web.enable-admin-api` is enabled. #19025

## 3.13.2 / 2026-07-29

- [SECURITY] Bump golang.org/x/text to v0.39.0 (CVE-2026-56852) and google.golang.org/grpc to v1.82.1 (GHSA-hrxh-6v49-42gf). #19290
- [BUGFIX] PromQL: Preallocate the active query tracker file to avoid SIGBUS crashes when the data disk is full. #19289

## 3.13.1 / 2026-07-10

- [BUGFIX] TSDB: Fix the head-chunk cache returning samples from the wrong chunk, or spurious not-found errors, to range queries after head-chunk truncation. #19134

## 3.13.0 / 2026-07-01

- [SECURITY] UI: Bump `sanitize-html` to fix a cross-site scripting vulnerability (CVE-2026-44990). #18697
- [CHANGE] UI: Third-party npm dependency licenses are now embedded in the Prometheus binary and served at `/assets/third-party-licenses.txt`, replacing the `npm_licenses.tar.bz2` archive previously shipped in release tarballs and container images. #18997
- [CHANGE] API: Use SHA-256 instead of SHA-1 to generate rule group pagination tokens. #18927
- [CHANGE] HTTP clients: Credentials (Authorization header, basic auth, bearer token, OAuth2, configured headers) are no longer forwarded when following a redirect to a different host; affects scraping, remote read/write, alerting, and service discovery. Via prometheus/common v0.69.0 (CVE-2025-4673 CVE-2023-45289). #18949
- [CHANGE] promtool: Relative file paths in the file passed to `--http.config.file` are now resolved relative to that config file's directory instead of its parent directory. Via prometheus/common v0.69.0. #18949
- [CHANGE] PromQL: Rename the `min()` and `max()` duration-expression functions (experimental feature flag `experimental-duration-expr`) to `min_of()` and `max_of()` to avoid confusion with the `min` and `max` aggregate operators. #18687
- [FEATURE] API: Add experimental search endpoints to search metric names, label names, and label values. #18573
- [FEATURE] Discovery/AWS: Add ability to filter RDS instances. #18859
- [FEATURE] PromQL: Add `min_of(a, b)` and `max_of(a, b)` scalar experimental functions, returning the smaller or larger of two scalar values. #18687
- [FEATURE] PromQL: Add support for smoothed/anchored rate with native histograms. #18564
- [FEATURE] PromQL: Expose per-query `samplesRead` (and `samplesReadPerStep` with `stats=all` and the `promql-per-step-stats` feature flag) in the query stats response, and add the `prometheus_engine_query_samples_read_total` engine counter. `samplesRead` reflects storage I/O distinct from `totalQueryableSamples`, which counts samples loaded into the evaluator (and so over-counts when a sample is reused across multiple range-vector windows). #18081
- [FEATURE] Scrape: Add `__convert_classic_histograms_to_nhcb__` internal label to allow per-target override of `convert_classic_histograms_to_nhcb` scrape configuration via relabeling. #18840
- [FEATURE] TSDB: Add `storage.tsdb.chunk_encoding.floats` configuration field to select float chunk encoding (`xor` or `xor2`) at runtime, independently of the `--enable-feature=xor2-encoding` flag. #18769
- [FEATURE] remote_write: Add Certificate support for ingesting data into an Azure Monitor Workspace. #18217
- [FEATURE] Scrape: Add `__always_scrape_classic_histograms__` and `__scrape_native_histograms__` internal labels to allow per-target override of the `always_scrape_classic_histograms` and `scrape_native_histograms` scrape configuration via relabeling. #18929
- [ENHANCEMENT] Release: Container images are now also published to the GitHub Container Registry (ghcr.io). #18791
- [ENHANCEMENT] PromQL: Prettify `fill_left(x) fill_right(x)` as `fill(x)` when both fill values are equal. #18851
- [ENHANCEMENT] UI: Improve autocompletion after closing a function bracket. #18894
- [PERF] Labels: Add case-insensitive prefix matching to speed up evaluation of long case-insensitive regular expressions (up to ~2x faster). #18540
- [PERF] TSDB: Reduce per-sample overhead in chunk population, speeding up affected queries by ~12-15% in benchmarks. #18699
- [PERF] TSDB: Eliminate unnecessary heap allocations in the V2 histogram WAL decoder, reducing allocations by up to 50% and memory by up to 10% for deployments using native histograms with created-timestamp storage enabled (`--enable-feature=created-timestamp-zero-ingestion`). #18813
- [BUGFIX] Discovery/AWS: Fix failure when processing an AWS RDS cluster without instances. #18845
- [BUGFIX] Fix race condition in initTime that could cause ErrOutOfBounds. #18629
- [BUGFIX] PromQL: A range query whose `end` was not aligned to `step` caused subqueries inside it to evaluate past the parent's last actual step, inflating `peakSamples` in the query stats and against the `query.max-samples` limit, and wasting storage I/O reading samples that were never used in the result. #18081
- [BUGFIX] PromQL: A range query containing an at-modifier-unsafe function over a range-vector with an `@` modifier (e.g. `predict_linear(metric[60s] @ T, X)`) silently under-counted `totalQueryableSamples` for steps after step 0. #18081
- [BUGFIX] PromQL: Fix `fill_left`/`fill_right` producing missing samples in range queries when using `group_left`/`group_right`. #18850
- [BUGFIX] PromQL: Fix for resets() and changes() in anchored range extenders with histograms. #18906
- [BUGFIX] PromQL: Fix panic on `1[5m] smoothed` and similar expressions when extended range selectors are enabled. #18764
- [BUGFIX] PromQL: Fix panic when a `smoothed` instant vector selector produces no samples for a series. #18943
- [BUGFIX] PromQL: Fix panic when using a parenthesised plain number as an offset (e.g. `foo offset -(5)`). #18768
- [BUGFIX] promtool: Fix panic when parsing exposition text containing empty braces `{}`. Via prometheus/common v0.69.0. #18949
- [BUGFIX] Promtool: Fix `check healthy` and `check ready` when `--url` ends with a trailing slash. #18854
- [BUGFIX] Rules: Close PromQL query after each rule evaluation to ensure resources are released. #18733
- [BUGFIX] Scaleway SD: Resolve VPC/IPAM-only instances that have no legacy `private_ip` or `public_ip` field, but do have private NICs attached. #18772
- [BUGFIX] TSDB: Do not leak head series when an integer histogram append is rejected (e.g. out-of-order). #18838
- [BUGFIX] UI: Escape label values offered by PromQL autocomplete. #18658
- [BUGFIX] TSDB: Fix chunk snapshot encoding for EncXOR2 chunks, preventing corruption on TSDB restart when EncXOR2-encoded series were present. #18739
- [BUGFIX] TSDB: Store a millisecond timestamp (not a WAL segment number) in walExpiries when a series is evicted via CompactStaleHead/CompactSelectedSeries, so the series's label record is correctly retained in the next WAL checkpoint and replays cleanly. #18847
- [BUGFIX] TSDB: Prevent loss of samples at the chunk-range boundary when CompactSelectedSeries (and CompactStaleHead) evict the series — the per-slice compaction loop now runs one more iteration so the boundary timestamp is captured in a block before the in-memory copy is removed. #18849

