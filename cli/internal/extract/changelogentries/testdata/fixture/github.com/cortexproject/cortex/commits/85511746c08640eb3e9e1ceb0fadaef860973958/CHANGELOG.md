# Changelog

## master / unreleased


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

## 1.17.1 2024-05-20

* [CHANGE] Query Frontend/Ruler: Omit empty data, errorType and error fields in API response. #5953 #5954
* [ENHANCEMENT] Ingester: Added `upload_compacted_blocks_enabled` config to ingester to parameterize uploading compacted blocks. #5959
* [BUGFIX] Querier: Select correct tenant during query federation. #5943

## 1.17.0 2024-04-30

* [CHANGE] Azure Storage: Upgraded objstore dependency and support Azure Workload Identity Authentication. Added `connection_string` to support authenticating via SAS token. Marked `msi_resource` config as deprecating. #5645
* [CHANGE] Store Gateway: Add a new fastcache based inmemory index cache. #5619
* [CHANGE] Index Cache: Multi level cache backfilling operation becomes async. Added `-blocks-storage.bucket-store.index-cache.multilevel.max-async-concurrency` and `-blocks-storage.bucket-store.index-cache.multilevel.max-async-buffer-size` configs and metric `cortex_store_multilevel_index_cache_backfill_dropped_items_total` for number of dropped items. #5661
* [CHANGE] Ingester: Disable uploading compacted blocks and overlapping compaction in ingester. #5735
* [CHANGE] Distributor: Count the number of rate-limited samples in `distributor_samples_in_total`. #5714
* [CHANGE] Ruler: Remove `cortex_ruler_write_requests_total`, `cortex_ruler_write_requests_failed_total`, `cortex_ruler_queries_total`, `cortex_ruler_queries_failed_total`, and `cortex_ruler_query_seconds_total` metrics for the tenant when the ruler deletes the manager for the tenant. #5772
* [CHANGE] Main: Mark `mem-ballast-size-bytes` flag as deprecated. #5816
* [CHANGE] Querier: Mark `-querier.ingester-streaming` flag as deprecated. Now query ingester streaming is always enabled. #5817
* [CHANGE] Compactor/Bucket Store: Added `-blocks-storage.bucket-store.block-discovery-strategy` to configure different block listing strategy. Reverted the current recursive block listing mechanism and use the strategy `Concurrent` as in 1.15. #5828
* [CHANGE] Compactor: Don't halt compactor when overlapped source blocks detected. #5854
* [CHANGE] S3 Bucket Client: Expose `-blocks-storage.s3.send-content-md5` flag and set default checksum algorithm to MD5. #5870
* [CHANGE] Querier: Mark `querier.iterators` and `querier.batch-iterators` flags as deprecated. Now querier always use batch iterators. #5868
* [CHANGE] Query Frontend: Error response returned by Query Frontend now follows Prometheus API error response format. #5811
* [FEATURE] Experimental: OTLP ingestion. #5813
* [FEATURE] Query Frontend/Scheduler: Add query priority support. #5605
* [FEATURE] Tracing: Use `kuberesolver` to resolve OTLP endpoints address with `kubernetes://` prefix as Kubernetes service. #5731
* [FEATURE] Tracing: Add `tracing.otel.round-robin` flag to use `round_robin` gRPC client side LB policy for sending OTLP traces. #5731
* [FEATURE] Ruler: Add `ruler.concurrent-evals-enabled` flag to enable concurrent evaluation within a single rule group for independent rules. Maximum concurrency can be configured via `ruler.max-concurrent-evals`. #5766
* [FEATURE] Distributor Queryable: Experimental: Add config `zone_results_quorum_metadata`. When querying ingesters using metadata APIs such as label names and values, only results from quorum number of zones will be included and merged. #5779
* [FEATURE] Storage Cache Clients: Add config `set_async_circuit_breaker_config` to utilize the circuit breaker pattern for dynamically thresholding asynchronous set operations. Implemented in both memcached and redis cache clients. #5789
* [FEATURE] Ruler: Add experimental `experimental.ruler.api-deduplicate-rules` flag to remove duplicate rule groups from the Prometheus compatible rules API endpoint. Add experimental `ruler.ring.replication-factor` and `ruler.ring.zone-awareness-enabled` flags to configure rule group replication, but only the first ruler in the replicaset evaluates the rule group, the rest will be used as backup to handle events when a ruler is down during an API request to list rules. #5782 #5901
* [FEATURE] Ring: Add experimental `-ingester.tokens-generator-strategy=minimize-spread` flag to enable the new minimize spread token generator strategy. #5855
* [FEATURE] Ring Status Page: Add `Ownership Diff From Expected` column in the ring table to indicate the extent to which the ownership of a specific ingester differs from the expected ownership. #5889
* [ENHANCEMENT] Ingester: Add per-tenant new metric `cortex_ingester_tsdb_data_replay_duration_seconds`. #5477
* [ENHANCEMENT] Store Gateway: Added `-store-gateway.enabled-tenants` and `-store-gateway.disabled-tenants` to explicitly enable or disable store-gateway for specific tenants. #5638
* [ENHANCEMENT] Query Frontend: Write service timing header in response even though there is an error. #5653
* [ENHANCEMENT] Compactor: Add new compactor metric `cortex_compactor_start_duration_seconds`. #5683
* [ENHANCEMENT] Index Cache: Multi level cache adds config `max_backfill_items` to cap max items to backfill per async operation. #5686
* [ENHANCEMENT] Query Frontend: Log number of split queries in `query stats` log. #5703
* [ENHANCEMENT] Compactor: Skip compaction retry when encountering a permission denied error. #5727
* [ENHANCEMENT] Logging: Added new options for logging HTTP request headers: `-server.log-request-headers` enables logging HTTP request headers, `-server.log-request-headers-exclude-list` allows users to specify headers which should not be logged. #5744
* [ENHANCEMENT] Query Frontend/Scheduler: Time check in query priority now considers overall data select time window (including range selectors, modifiers and lookback delta). #5758
* [ENHANCEMENT] Querier: Added `querier.store-gateway-query-stats-enabled` to enable or disable store gateway query stats log. #5749
* [ENHANCEMENT] Querier: Improve labels APIs latency by merging slices using K-way merge and more than 1 core. #5785
* [ENHANCEMENT] AlertManager: Retrying AlertManager Delete Silence on error. #5794
* [ENHANCEMENT] Ingester: Add new ingester metric `cortex_ingester_max_inflight_query_requests`. #5798
* [ENHANCEMENT] Query: Added `query_storage_wall_time` to Query Frontend and Ruler query stats log for wall time spent on fetching data from storage. Query evaluation is not included. #5799
* [ENHANCEMENT] Query: Added additional max query length check at Query Frontend and Ruler. Added `-querier.ignore-max-query-length` flag to disable max query length check at Querier. #5808
* [ENHANCEMENT] Querier: Add context error check when converting Metrics to SeriesSet for GetSeries on distributorQuerier. #5827
* [ENHANCEMENT] Ruler: Improve GetRules response time by reducing lock contention and introducing a temporary rules cache in `ruler/manager.go`. #5805
* [ENHANCEMENT] Querier: Add context error check when merging slices from ingesters for GetLabel operations. #5837
* [BUGFIX] Distributor: Do not use label with empty values for sharding #5717
* [BUGFIX] Query Frontend: queries with negative offset should check whether it is cacheable or not. #5719
* [BUGFIX] Redis Cache: pass `cache_size` config correctly. #5734
* [BUGFIX] Distributor: Shuffle-Sharding with `ingestion_tenant_shard_size` set to 0, default sharding strategy should be used. #5189
* [BUGFIX] Cortex: Fix GRPC stream clients not honoring overrides for call options. #5797
* [BUGFIX] Ruler: Fix support for `keep_firing_for` field in alert rules. #5823
* [BUGFIX] Ring DDB: Fix lifecycle for ring counting unhealthy pods as healthy. #5838
* [BUGFIX] Ring DDB: Fix region assignment. #5842
