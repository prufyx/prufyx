# Changelog

## 3.4.0 / 2025-05-17

* [CHANGE] Config: Make setting out-of-order native histograms feature (`--enable-feature=ooo-native-histograms`) a no-op. Out-of-order native histograms are now always enabled when `out_of_order_time_window` is greater than zero and `--enable-feature=native-histograms` is set. #16207
* [FEATURE] OTLP translate: Add feature flag for optionally translating OTel explicit bucket histograms into native histograms with custom buckets. #15850
* [FEATURE] OTLP translate: Add option to receive OTLP metrics without translating names or attributes. #16441
* [FEATURE] PromQL: allow arithmetic operations in durations in PromQL parser. #16249
* [FEATURE] OTLP receiver: Add primitive support for ingesting OTLP delta metrics as-is. #16360
* [ENHANCEMENT] PromQL: histogram_fraction for bucket histograms. #16095
* [ENHANCEMENT] TSDB: add `prometheus_tsdb_wal_replay_unknown_refs_total` and `prometheus_tsdb_wbl_replay_unknown_refs_total` metrics to track unknown series references during WAL/WBL replay. #16166
* [ENHANCEMENT] Scraping: Add config option for escaping scheme request. #16066
* [ENHANCEMENT] Config: Add global config option for convert_classic_histograms_to_nhcb. #16226
* [ENHANCEMENT] Alerting: make batch size configurable (`--alertmanager.notification-batch-size`). #16254
* [PERF] Kubernetes SD: make endpointSlice discovery more efficient. #16433
* [BUGFIX] Config: Fix auto-reload on changes to rule and scrape config files. #16340
* [BUGFIX] Scraping: Skip native histogram series if ingestion is disabled. #16218
* [BUGFIX] TSDB: Handle metadata/tombstones/exemplars for duplicate series during WAL replay. #16231
* [BUGFIX] TSDB: Avoid processing exemplars outside the valid time range during WAL replay. #16242
* [BUGFIX] Promtool: Add feature flags for PromQL features. #16443
* [BUGFIX] Rules: correct logging of alert name & template data. #15093
* [BUGFIX] PromQL: Use arithmetic mean for `histogram_stddev()` and `histogram_stdvar()` . #16444

## 3.3.0 / 2025-04-15

* [FEATURE] PromQL: Implement `idelta()` and `irate()` for native histograms. #15853
* [ENHANCEMENT] Scaleway SD: Add `__meta_scaleway_instance_public_ipv4_addresses` and `__meta_scaleway_instance_public_ipv6_addresses` labels. #14228
* [ENHANCEMENT] TSDB: Reduce locking while reloading blocks. #12920
* [ENHANCEMENT] PromQL: Allow UTF-8 labels in `label_replace()`. #15974
* [ENHANCEMENT] Promtool: `tsdb create-blocks-from openmetrics` can now read from a Pipe. #16011
* [ENHANCEMENT] Rules: Add support for anchors and aliases in rule files. #14957
* [ENHANCEMENT] Dockerfile: Make `/prometheus` writable. #16073
* [ENHANCEMENT] API: Include scrape pool name for dropped targets in `/api/v1/targets`. #16085
* [ENHANCEMENT] UI: Improve time formatting and copying of selectors. #15999 #16165
* [ENHANCEMENT] UI: Bring back vertical grid lines and graph legend series toggling instructions. #16163 #16164
* [ENHANCEMENT] Mixin: The `cluster` label can be customized using `clusterLabel`. #15826
* [PERF] TSDB: Optimize some operations on head chunks by taking shortcuts. #12659
* [PERF] TSDB & Agent: Reduce memory footprint during WL replay. #15778
* [PERF] Remote-Write: Reduce memory footprint during WAL replay. #16197
* [PERF] API: Reduce memory footprint during header parsing. #16001
* [PERF] Rules: Improve dependency evaluation, enabling better concurrency. #16039
* [PERF] Scraping: Improve scraping performance for native histograms. #15731
* [PERF] Scraping: Improve parsing of created timestamps. #16072
* [BUGFIX] Scraping: Bump cache iteration after error to avoid false duplicate detections. #16174
* [BUGFIX] Scraping: Skip native histograms series when ingestion is disabled. #16218
* [BUGFIX] PromQL: Fix counter reset detection for native histograms. #15902 #15987
* [BUGFIX] PromQL: Fix inconsistent behavior with an empty range. #15970
* [BUGFIX] PromQL: Fix inconsistent annotation in `quantile_over_time()`. #16018
* [BUGFIX] PromQL: Prevent `label_join()` from producing duplicates. #15975
* [BUGFIX] PromQL: Ignore native histograms in `scalar()`, `sort()` and `sort_desc()`. #15964
* [BUGFIX] PromQL: Fix annotations for binary operations between incompatible native histograms. #15895
* [BUGFIX] Alerting: Consider alert relabeling when deciding whether alerts are dropped. #15979
* [BUGFIX] Config: Set `GoGC` to the default value in case of an empty configuration. #16052
* [BUGFIX] TSDB: Fix unknown series errors and potential data loss during WAL replay when inactive series are removed from the head and reappear before the next WAL checkpoint. #16060
* [BUGFIX] Scaleway SD: The public IP will no longer be set to `__meta_meta_scaleway_instance_public_ipv4` if it is an IPv6 address. #14228
* [BUGFIX] UI: Display the correct value of Alerting rules' `keep_firing_for`. #16211

## 3.2.1 / 2025-02-25

* [BUGFIX] Don't send Accept` header `escape=allow-utf-8` when `metric_name_validation_scheme: legacy` is configured. #16061

## 3.2.0 / 2025-02-17

* [CHANGE] relabel: Replace actions can now use UTF-8 characters in `targetLabel` field. Note that `$<chars>` or `${<chars>}` will be expanded. This also apply to `replacement` field for `LabelMap` action. #15851
* [CHANGE] rulefmt: Rule names can use UTF-8 characters, except `{` and `}` characters (due to common mistake checks). #15851
* [FEATURE] remote/otlp: Add feature flag `otlp-deltatocumulative` to support conversion from delta to cumulative. #15165
* [ENHANCEMENT] openstack SD: Discover Octavia loadbalancers. #15539
* [ENHANCEMENT] scrape: Add metadata for automatic metrics to WAL for `metadata-wal-records` feature. #15837
* [ENHANCEMENT] promtool: Support linting of scrape interval, through lint option `too-long-scrape-interval`. #15719
* [ENHANCEMENT] promtool: Add --ignore-unknown-fields option. #15706
* [ENHANCEMENT] ui: Make "hide empty rules" and hide empty rules" persistent #15807
* [ENHANCEMENT] web/api: Add a limit parameter to `/query` and `/query_range`. #15552
* [ENHANCEMENT] api: Add fields Node and ServerTime to `/status`. #15784
* [PERF] Scraping: defer computing labels for dropped targets until they are needed by the UI.  #15261
* [BUGFIX] remotewrite2: Fix invalid metadata bug for metrics without metadata. #15829
* [BUGFIX] remotewrite2: Fix the unit field propagation. #15825
* [BUGFIX] scrape: Fix WAL metadata for histograms and summaries. #15832
* [BUGFIX] ui: Merge duplicate "Alerts page settings" sections. #15810
* [BUGFIX] PromQL: Fix `<aggr_over_time>` functions with histograms. #15711
