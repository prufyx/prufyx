# Changelog

## master / unreleased

## 1.19.0 in progress

* [CHANGE] Deprecate `-blocks-storage.tsdb.wal-compression-enabled` flag (use `blocks-storage.tsdb.wal-compression-type` instead). #6529
* [CHANGE] OTLP: Change OTLP handler to be consistent with the Prometheus OTLP handler. #6272
- `target_info` metric is enabled by default and can be disabled via `-distributor.otlp.disable-target-info=true` flag
- Convert all attributes to labels is disabled by default and can be enabled via `-distributor.otlp.convert-all-attributes=true` flag
- You can specify the attributes converted to labels via `-distributor.promote-resource-attributes` flag. Supported only if `-distributor.otlp.convert-all-attributes=false`
* [CHANGE] Change all max async concurrency default values `50` to `3` #6268
* [CHANGE] Change default value of `-blocks-storage.bucket-store.index-cache.multilevel.max-async-concurrency` from `50` to `3` #6265
* [CHANGE] Enable Compactor and Alertmanager in target all. #6204
* [CHANGE] Update the `cortex_ingester_inflight_push_requests` metric to represent the maximum number of inflight requests recorded in the last minute. #6437
* [CHANGE] gRPC Client: Expose connection timeout and set default to value to 5s. #6523
* [CHANGE] Enable analysis on Thanos PromQL engine #6472
* [CHANGE] Log grafana headers along with query request before query execution #6391
* [CHANGE] Log query requests in QFE before query execution #6390
* [CHANGE] Log when a request starts running in querier #6525
* [CHANGE] Remove openstack swfit experimental in blocks storage #6322
* [CHANGE] Remove openstack swift experimental #6316
* [CHANGE] Replace `cespare/xxhash` with `cespare/xxhash/v2` #6467
* [CHANGE] Stop using global instant query codec #6328
* [CHANGE] Unify query frontend instant and range protos #6180
* [FEATURE] Ruler: Add an experimental flag `-ruler.query-response-format` to retrieve query response as a proto format. #6345
* [FEATURE] Ruler: Pagination support for List Rules API. #6299
* [FEATURE] Query Frontend/Querier: Add protobuf codec `-api.querier-default-codec` and the option to choose response compression type `-querier.response-compression`. #5527
* [FEATURE] Ruler: Experimental: Add `ruler.frontend-address` to allow query to query frontends instead of ingesters. #6151
* [FEATURE] Ruler: Minimize chances of missed rule group evaluations that can occur due to OOM kills, bad underlying nodes, or due to an unhealthy ruler that appears in the ring as healthy. This feature is enabled via `-ruler.enable-ha-evaluation` flag. #6129
* [FEATURE] Store Gateway: Add an in-memory chunk cache. #6245
* [FEATURE] Chunk Cache: Support multi level cache and add metrics. #6249
* [FEATURE] Distributor: Accept multiple HA Tracker pairs in the same request. #6256
* [FEATURE] Ruler: Add support for per-user external labels #6340
* [FEATURE] Query Frontend: Support a metadata federated query when `-tenant-federation.enabled=true`. #6461
* [FEATURE] Query Frontend: Support an exemplar federated query when `-tenant-federation.enabled=true`. #6455
* [FEATURE] Ingester/StoreGateway: Add support for cache regex query matchers via `-ingester.matchers-cache-max-items` and `-blocks-storage.bucket-store.matchers-cache-max-items`. #6477 #6491
* [FEATURE] Add reason why the key was evicted in the `cortex_ingester_expanded_postings_cache_evicts` metric #6318
* [FEATURE] Create feature flag to switch between current shuffle sharding group planner and partition compaction group planner #6141
* [FEATURE] Hook up partition compaction end to end implementation #6510
* [FEATURE] Implement partition compaction grouper #6172
* [FEATURE] Implement partition compaction planner #6469
* [FEATURE] Make LivenessCheck Timeout Configurable #6227
* [FEATURE] Querier: Add day range limit for LabelNames and LabelValues #6233
* [ENHANCEMENT] Query Frontend: Add more operation label values to the `cortex_query_frontend_queries_total` metric. #6519
* [ENHANCEMENT] Query Frontend: Add a `source` label to query stat metrics. #6470
* [ENHANCEMENT] Query Frontend: Add a flag `-tenant-federation.max-tenant` to limit the number of tenants for federated query. #6493
* [ENHANCEMENT] Querier: Add a `-tenant-federation.max-concurrent` flags to configure the number of worker processing federated query and add a `cortex_querier_federated_tenants_per_query` histogram to track the number of tenants per query. #6449
* [ENHANCEMENT] Query Frontend: Add a number of series in the query response to the query stat log. #6423
* [ENHANCEMENT] Store Gateway: Add a hedged request to reduce the tail latency. #6388
* [ENHANCEMENT] Ingester: Add metrics to track succeed/failed native histograms. #6370
* [ENHANCEMENT] Query Frontend/Querier: Add an experimental flag `-querier.enable-promql-experimental-functions` to enable experimental promQL functions. #6355
* [ENHANCEMENT] OTLP: Add `-distributor.otlp-max-recv-msg-size` flag to limit OTLP request size in bytes. #6333
* [ENHANCEMENT] S3 Bucket Client: Add a list objects version configs to configure list api object version. #6280
* [ENHANCEMENT] OpenStack Swift: Add application credential configs for Openstack swift object storage backend. #6255
* [ENHANCEMENT] Query Frontend: Add new query stats metrics `cortex_query_samples_scanned_total` and `cortex_query_peak_samples` to track scannedSamples and peakSample per user. #6228
* [ENHANCEMENT] Ingester: Add option `ingester.disable-chunk-trimming` to disable chunk trimming. #6300
* [ENHANCEMENT] Ingester: Add `blocks-storage.tsdb.wal-compression-type` to support zstd wal compression type. #6232
* [ENHANCEMENT] Query Frontend: Add info field to query response. #6207
* [ENHANCEMENT] Query Frontend: Add peakSample in query stats response. #6188
* [ENHANCEMENT] Ruler: Add new ruler metric `cortex_ruler_rule_groups_in_store` that is the total rule groups per tenant in store, which can be used to compare with `cortex_prometheus_rule_group_rules` to count the number of rule groups that are not loaded by a ruler. #5869
* [ENHANCEMENT] Ingester/Ring: New `READONLY` status on ring to be used by Ingester. New ingester API to change mode of ingester #6163
* [ENHANCEMENT] Ruler: Add query statistics metrics when --ruler.query-stats-enabled=true. #6173
* [ENHANCEMENT] Ingester: Add new API `/ingester/all_user_stats` which shows loaded blocks, active timeseries and ingestion rate for a specific ingester. #6178
* [ENHANCEMENT] Distributor: Add new `cortex_reduced_resolution_histogram_samples_total` metric to track the number of histogram samples which resolution was reduced. #6182
* [ENHANCEMENT] StoreGateway: Implement metadata API limit in queryable. #6195
* [ENHANCEMENT] Ingester: Add matchers to ingester LabelNames() and LabelNamesStream() RPC. #6209
* [ENHANCEMENT] KV: Add TLS configs to consul. #6374
* [ENHANCEMENT] Ingester/Store Gateway Clients: Introduce an experimental HealthCheck handler to quickly fail requests directed to unhealthy targets. #6225 #6257
* [ENHANCEMENT] Upgrade build image and Go version to 1.23.2. #6261 #6262
* [ENHANCEMENT] Ingester: Introduce a new experimental feature for caching expanded postings on the ingester. #6296
* [ENHANCEMENT] Querier/Ruler: Expose `store_gateway_consistency_check_max_attempts` for max retries when querying store gateway in consistency check. #6276
* [ENHANCEMENT] StoreGateway: Add new `cortex_bucket_store_chunk_pool_inuse_bytes` metric to track the usage in chunk pool. #6310
* [ENHANCEMENT] Distributor: Add new `cortex_distributor_inflight_client_requests` metric to track number of ingester client inflight requests. #6358
* [ENHANCEMENT] Distributor: Expose `cortex_label_size_bytes` native histogram metric. #6372
* [ENHANCEMENT] Add new option `-server.grpc_server-num-stream-workers` to configure the number of worker goroutines that should be used to process incoming streams. #6386
* [ENHANCEMENT] Distributor: Return HTTP 5XX instead of HTTP 4XX when instance limits are hit. #6358
* [ENHANCEMENT] Ingester: Make sure unregistered ingester joining the ring after WAL replay. #6277
* [ENHANCEMENT] Distributor: Add a new `-distributor.num-push-workers` flag to use a goroutine worker pool when sending data from distributor to ingesters. #6406
* [ENHANCEMENT] Ingester: If a limit per label set entry doesn't have any label, use it as the default partition to catch all series that doesn't match any other label sets entries. #6435
* [ENHANCEMENT] Querier: Add new `cortex_querier_codec_response_size` metric to track the size of the encoded query responses from queriers. #6444
* [ENHANCEMENT] Distributor: Added `cortex_distributor_received_samples_per_labelset_total` metric to calculate ingestion rate per label set. #6443
* [ENHANCEMENT] Added metric name in limiter per-metric exceeded errors. #6416
* [ENHANCEMENT] StoreGateway: Added `cortex_bucket_store_indexheader_load_duration_seconds` and `cortex_bucket_store_indexheader_download_duration_seconds` metrics for time of downloading and loading index header files. #6445
* [ENHANCEMENT] Add cleaner logic to clean partition compaction blocks and related files #6507
* [ENHANCEMENT] Add support for native histograms in querier protobuf codec #6368
* [ENHANCEMENT] Add timeout on lifecycler heartbeat #6212
* [ENHANCEMENT] Added UserReplicaGroupMetrics #6463
* [ENHANCEMENT] Blocks Storage: Allow use of non-dualstack endpoints for S3 blocks storage via `-blocks-storage.s3.disable-dualstack`. #6522
* [ENHANCEMENT] Discarded samples per labelset metrics for throttle by labelset #6492
* [ENHANCEMENT] Expanded Postings Cache can cache results without the nearly created series under high load. #6417
* [ENHANCEMENT] Ingester: Disable chunk trimming. #6270
* [ENHANCEMENT] Improve consistency check warn log #6366
* [ENHANCEMENT] Improve streaming on MetricsForLabelMatchersStream method #6436
* [ENHANCEMENT] Improve validation metrics for discarded samples and exemplars #6218
* [ENHANCEMENT] Query Frontend: add new field for dense native histogram format #6199
* [ENHANCEMENT] Return 503 on hitting distributor instance limits #6387
* [ENHANCEMENT] Reusing Batch Iterators #6403
* [ENHANCEMENT] Reusing the grpc client to peform healthcheck #6260
* [ENHANCEMENT] Store Gateway: Add pre add block ownership check #6483
* [ENHANCEMENT] Use slice pooling to populate the query stream response #6466
* [ENHANCEMENT] Using a single seed array for expanded postings cache on ingesters #6365
* [BUGFIX] Runtime-config: Handle absolute file paths when working directory is not / #6224
* [BUGFIX] Ruler: Allow rule evaluation to complete during shutdown. #6326
* [BUGFIX] Ring: update ring with new ip address when instance is lost, rejoins, but heartbeat is disabled. #6271
* [BUGFIX] Ingester: Fix regression on usage of cortex_ingester_queried_chunks. #6398
* [BUGFIX] Ingester: Fix possible race condition when `active series per LabelSet` is configured. #6409
* [BUGFIX] Query Frontend: Fix @ modifier not being applied correctly on sub queries. #6450
* [BUGFIX] Cortex Redis flags with multiple dots #6476
* [BUGFIX] Bug fix on JSON Tag #6339
* [BUGFIX] Calculate # of concurrency only once at the runner #6506
* [BUGFIX] Clean up ingester per labelset metrics #6439
* [BUGFIX] Cleanup dangling request queue metrics #6433
* [BUGFIX] Fix BenchmarkDistributor_Push benchmark #6309
* [BUGFIX] Fix data race on expanded postings Cache #6369
* [BUGFIX] Fix lazy postings merge bug #6415
* [BUGFIX] Fix race on chunks multilevel cache + Optimize to avoid refetching already found keys. #6312
* [BUGFIX] Fix race on the string interning #6408
* [BUGFIX] Fix race that can cause nil reference when using expanded postings #6518
* [BUGFIX] Fix regression of query range result cache unable to parse old cached results #6196
* [BUGFIX] Fix typo in usage message for querier.split-queries-by-interval flag #6305
* [BUGFIX] Fix: PostingCache promise should fetch data only once #6314
* [BUGFIX] Fix: fix slice init length #6237
* [BUGFIX] Fixed bug that blocks cannot be fully deleted from TSDB #6231
* [BUGFIX] Fixed ingester ReadOnly state related bugs #6208
* [BUGFIX] Preserve ingester state on restart #6301
* [BUGFIX] Purge expired postings cache items due inactivity #6502
* [BUGFIX] Util: Check context every N iterations #6250

## 1.18.1 2024-10-14

* [BUGFIX] Backporting upgrade to go 1.22.7 to patch CVE-2024-34155, CVE-2024-34156, CVE-2024-34158 #6217 #6264


## 1.18.0 2024-09-03

* [CHANGE] Ingester: Remove `-querier.query-store-for-labels-enabled` flag. Querying long-term store for labels is always enabled. #5984
* [CHANGE] Server: Instrument `cortex_request_duration_seconds` metric with native histogram. If `native-histograms` feature is enabled in monitoring Prometheus then the metric name needs to be updated in your dashboards. #6056
* [CHANGE] Distributor/Ingester: Change `cortex_distributor_ingester_appends_total`, `cortex_distributor_ingester_append_failures_total`, `cortex_distributor_ingester_queries_total`, and `cortex_distributor_ingester_query_failures_total` metrics to use the ingester ID instead of its IP as the label value. #6078
* [CHANGE] OTLP: Set `AddMetricSuffixes` to true to always enable metric name normalization. #6136
* [CHANGE] Querier: Deprecate and enable by default `querier.ingester-metadata-streaming` flag. #6147
* [CHANGE] QueryFrontend/QueryScheduler: Deprecate `-querier.max-outstanding-requests-per-tenant` and `-query-scheduler.max-outstanding-requests-per-tenant` flags. Use frontend.max-outstanding-requests-per-tenant instead. #6146
* [CHANGE] Ingesters: Enable 'snappy-block' compression on ingester clients by default. #6148
* [CHANGE] Ruler: Scheduling `ruler.evaluation-delay-duration` to be deprecated. Ruler will use the highest value between `ruler.evaluation-delay-duration` and `ruler.query-offset` #6149
* [CHANGE] Querier: Remove `-querier.at-modifier-enabled` flag. #6157
* [CHANGE] Tracing: Remove deprecated `oltp_endpoint` config entirely. #6158
* [CHANGE] Store Gateway: Enable store gateway zone stable shuffle sharding by default. #6161
* [FEATURE] Ingester/Distributor: Experimental: Enable native histogram ingestion via `-blocks-storage.tsdb.enable-native-histograms` flag. #5986 #6010 #6020
* [FEATURE] Querier: Enable querying native histogram chunks. #5944 #6031
* [FEATURE] Query Frontend: Support native histogram in query frontend response. #5996 #6043
* [FEATURE] Ruler: Support sending native histogram samples to Ingester. #6029
* [FEATURE] Ruler: Add support for filtering out alerts in ListRules API. #6011
* [FEATURE] Query Frontend: Added a query rejection mechanism to block resource-intensive queries. #6005
* [FEATURE] OTLP: Support ingesting OTLP exponential metrics as native histograms. #6071 #6135
* [FEATURE] Ingester: Add `ingester.instance-limits.max-inflight-query-requests` to allow limiting ingester concurrent queries. #6081
* [FEATURE] Distributor: Add `validation.max-native-histogram-buckets` to limit max number of bucket count. Distributor will try to automatically reduce histogram resolution until it is within the bucket limit or resolution cannot be reduced anymore. #6104
* [FEATURE] Store Gateway: Introduce token bucket limiter to enhance store gateway throttling. #6016
* [FEATURE] Ruler: Add support for `query_offset` field on RuleGroup and new `ruler_query_offset` per-tenant limit. #6085
* [ENHANCEMENT] Ruler: Add support to persist tokens in rulers. #5987
* [ENHANCEMENT] Query Frontend/Querier: Added store gateway postings touched count and touched size in Querier stats and log in Query Frontend. #5892
* [ENHANCEMENT] Query Frontend/Querier: Returns `warnings` on prometheus query responses. #5916
* [ENHANCEMENT] Ingester: Allowing to configure `-blocks-storage.tsdb.head-compaction-interval` flag up to 30 min and add a jitter on the first head compaction. #5919 #5928
* [ENHANCEMENT] Distributor: Added `max_inflight_push_requests` config to ingester client to protect distributor from OOMKilled. #5917
* [ENHANCEMENT] Distributor/Querier: Clean stale per-ingester metrics after ingester restarts. #5930
* [ENHANCEMENT] Distributor/Ring: Allow disabling detailed ring metrics by ring member. #5931
* [ENHANCEMENT] KV: Etcd Added etcd.ping-without-stream-allowed parameter to disable/enable PermitWithoutStream #5933
* [ENHANCEMENT] Ingester: Add a new `limits_per_label_set` limit. This limit functions similarly to `max_series_per_metric`, but allowing users to define the maximum number of series per LabelSet. #5950 #5993
* [ENHANCEMENT] Store Gateway: Log gRPC requests together with headers configured in `http_request_headers_to_log`. #5958
* [ENHANCEMENT] Ingester: Add a new experimental `-ingester.labels-string-interning-enabled` flag to enable string interning for metrics labels. #6057
* [ENHANCEMENT] Ingester: Add link to renew 10% of the ingesters tokens in the admin page. #6063
* [ENHANCEMENT] Ruler: Add support for filtering by `state` and `health` field on Rules API. #6040
* [ENHANCEMENT] Ruler: Add support for filtering by `match` field on Rules API. #6083
* [ENHANCEMENT] Distributor: Reduce memory usage when error volume is high. #6095
* [ENHANCEMENT] Compactor: Centralize metrics used by compactor and add user label to compactor metrics. #6096
* [ENHANCEMENT] Compactor: Add unique execution ID for each compaction cycle in log for easy debugging. #6097
* [ENHANCEMENT] Compactor: Differentiate retry and halt error and retry failed compaction only on retriable error. #6111
* [ENHANCEMENT] Ruler: Add support for filtering by `state` and `health` field on Rules API. #6040
* [ENHANCEMENT] Compactor: Split cleaner cycle for active and deleted tenants. #6112
* [ENHANCEMENT] Compactor: Introduce cleaner visit marker. #6113
* [ENHANCEMENT] Query Frontend: Add `cortex_query_samples_total` metric. #6142
* [ENHANCEMENT] Ingester: Implement metadata API limit. #6128
* [BUGFIX] Configsdb: Fix endline issue in db password. #5920
* [BUGFIX] Ingester: Fix `user` and `type` labels for the `cortex_ingester_tsdb_head_samples_appended_total` TSDB metric. #5952
* [BUGFIX] Querier: Enforce max query length check for `/api/v1/series` API even though `ignoreMaxQueryLength` is set to true. #6018
* [BUGFIX] Ingester: Fix issue with the minimize token generator where it was not taking in consideration the current ownership of an instance when generating extra tokens. #6062
* [BUGFIX] Scheduler: Fix user queue in scheduler that was not thread-safe. #6077 #6160
* [BUGFIX] Ingester: Include out-of-order head compaction when compacting TSDB head. #6108
* [BUGFIX] Ingester: Fix `cortex_ingester_tsdb_mmap_chunks_total` metric. #6134
* [BUGFIX] Query Frontend: Fix query rejection bug for metadata queries. #6143
