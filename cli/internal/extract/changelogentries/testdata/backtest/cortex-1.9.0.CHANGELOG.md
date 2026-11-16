# Changelog

## master / unreleased

## 1.9.0 / 2021-05-14

* [CHANGE] Alertmanager now removes local files after Alertmanager is no longer running for removed or resharded user. #3910
* [CHANGE] Alertmanager now stores local files in per-tenant folders. Files stored by Alertmanager previously are migrated to new hierarchy. Support for this migration will be removed in Cortex 1.11. #3910
* [CHANGE] Ruler: deprecated `-ruler.storage.*` CLI flags (and their respective YAML config options) in favour of `-ruler-storage.*`. The deprecated config will be removed in Cortex 1.11. #3945
* [CHANGE] Alertmanager: deprecated `-alertmanager.storage.*` CLI flags (and their respective YAML config options) in favour of `-alertmanager-storage.*`. This change doesn't apply to `alertmanager.storage.path` and `alertmanager.storage.retention`. The deprecated config will be removed in Cortex 1.11. #4002
* [CHANGE] Alertmanager: removed `-cluster.` CLI flags deprecated in Cortex 1.7. The new config options to use are: #3946
  * `-alertmanager.cluster.listen-address` instead of `-cluster.listen-address`
  * `-alertmanager.cluster.advertise-address` instead of `-cluster.advertise-address`
  * `-alertmanager.cluster.peers` instead of `-cluster.peer`
  * `-alertmanager.cluster.peer-timeout` instead of `-cluster.peer-timeout`
* [CHANGE] Blocks storage: removed the config option `-blocks-storage.bucket-store.index-cache.postings-compression-enabled`, which was deprecated in Cortex 1.6. Postings compression is always enabled. #4101
* [CHANGE] Querier: removed the config option `-store.max-look-back-period`, which was deprecated in Cortex 1.6 and was used only by the chunks storage. You should use `-querier.max-query-lookback` instead. #4101
* [CHANGE] Query Frontend: removed the config option `-querier.compress-http-responses`, which was deprecated in Cortex 1.6. You should use`-api.response-compression-enabled` instead. #4101
* [CHANGE] Runtime-config / overrides: removed the config options `-limits.per-user-override-config` (use `-runtime-config.file`) and `-limits.per-user-override-period` (use `-runtime-config.reload-period`), both deprecated since Cortex 0.6.0. #4112
* [CHANGE] Cortex now fails fast on startup if unable to connect to the ring backend. #4068
* [FEATURE] The following features have been marked as stable: #4101
  - Shuffle-sharding
  - Querier support for querying chunks and blocks store at the same time
  - Tracking of active series and exporting them as metrics (`-ingester.active-series-metrics-enabled` and related flags)
  - Blocks storage: lazy mmap of block indexes in the store-gateway (`-blocks-storage.bucket-store.index-header-lazy-loading-enabled`)
  - Ingester: close idle TSDB and remove them from local disk (`-blocks-storage.tsdb.close-idle-tsdb-timeout`)
* [FEATURE] Memberlist: add TLS configuration options for the memberlist transport layer used by the gossip KV store. #4046
  * New flags added for memberlist communication:
    * `-memberlist.tls-enabled`
    * `-memberlist.tls-cert-path`
    * `-memberlist.tls-key-path`
    * `-memberlist.tls-ca-path`
    * `-memberlist.tls-server-name`
    * `-memberlist.tls-insecure-skip-verify`
* [FEATURE] Ruler: added `local` backend support to the ruler storage configuration under the `-ruler-storage.` flag prefix. #3932
* [ENHANCEMENT] Upgraded Docker base images to `alpine:3.13`. #4042
* [ENHANCEMENT] Blocks storage: reduce ingester memory by eliminating series reference cache. #3951
* [ENHANCEMENT] Ruler: optimized `<prefix>/api/v1/rules` and `<prefix>/api/v1/alerts` when ruler sharding is enabled. #3916
* [ENHANCEMENT] Ruler: added the following metrics when ruler sharding is enabled: #3916
  * `cortex_ruler_clients`
  * `cortex_ruler_client_request_duration_seconds`
* [ENHANCEMENT] Alertmanager: Add API endpoint to list all tenant alertmanager configs: `GET /multitenant_alertmanager/configs`. #3529
* [ENHANCEMENT] Ruler: Add API endpoint to list all tenant ruler rule groups: `GET /ruler/rule_groups`. #3529
* [ENHANCEMENT] Query-frontend/scheduler: added querier forget delay (`-query-frontend.querier-forget-delay` and `-query-scheduler.querier-forget-delay`) to mitigate the blast radius in the event queriers crash because of a repeatedly sent "query of death" when shuffle-sharding is enabled. #3901
* [ENHANCEMENT] Query-frontend: reduced memory allocations when serializing query response. #3964
* [ENHANCEMENT] Querier / ruler: some optimizations to PromQL query engine. #3934 #3989
* [ENHANCEMENT] Ingester: reduce CPU and memory when an high number of errors are returned by the ingester on the write path with the blocks storage. #3969 #3971 #3973
* [ENHANCEMENT] Distributor: reduce CPU and memory when an high number of errors are returned by the distributor on the write path. #3990
* [ENHANCEMENT] Put metric before label value in the "label value too long" error message. #4018
* [ENHANCEMENT] Allow use of `y|w|d` suffixes for duration related limits and per-tenant limits. #4044
* [ENHANCEMENT] Query-frontend: Small optimization on top of PR #3968 to avoid unnecessary Extents merging. #4026
* [ENHANCEMENT] Add a metric `cortex_compactor_compaction_interval_seconds` for the compaction interval config value. #4040
* [ENHANCEMENT] Ingester: added following per-ingester (instance) experimental limits: max number of series in memory (`-ingester.instance-limits.max-series`), max number of users in memory (`-ingester.instance-limits.max-tenants`), max ingestion rate (`-ingester.instance-limits.max-ingestion-rate`), and max inflight requests (`-ingester.instance-limits.max-inflight-push-requests`). These limits are only used when using blocks storage. Limits can also be configured using runtime-config feature, and current values are exported as `cortex_ingester_instance_limits` metric. #3992.
* [ENHANCEMENT] Cortex is now built with Go 1.16. #4062
* [ENHANCEMENT] Distributor: added per-distributor experimental limits: max number of inflight requests (`-distributor.instance-limits.max-inflight-push-requests`) and max ingestion rate in samples/sec (`-distributor.instance-limits.max-ingestion-rate`). If not set, these two are unlimited. Also added metrics to expose current values (`cortex_distributor_inflight_push_requests`, `cortex_distributor_ingestion_rate_samples_per_second`) as well as limits (`cortex_distributor_instance_limits` with various `limit` label values). #4071
* [ENHANCEMENT] Ruler: Added `-ruler.enabled-tenants` and `-ruler.disabled-tenants` to explicitly enable or disable rules processing for specific tenants. #4074
* [ENHANCEMENT] Block Storage Ingester: `/flush` now accepts two new parameters: `tenant` to specify tenant to flush and `wait=true` to make call synchronous. Multiple tenants can be specified by repeating `tenant` parameter. If no `tenant` is specified, all tenants are flushed, as before. #4073
* [ENHANCEMENT] Alertmanager: validate configured `-alertmanager.web.external-url` and fail if ends with `/`. #4081
* [ENHANCEMENT] Alertmanager: added `-alertmanager.receivers-firewall.block.cidr-networks` and `-alertmanager.receivers-firewall.block.private-addresses` to block specific network addresses in HTTP-based Alertmanager receiver integrations. #4085
* [ENHANCEMENT] Allow configuration of Cassandra's host selection policy. #4069
* [ENHANCEMENT] Store-gateway: retry synching blocks if a per-tenant sync fails. #3975 #4088
* [ENHANCEMENT] Add metric `cortex_tcp_connections` exposing the current number of accepted TCP connections. #4099
* [ENHANCEMENT] Querier: Allow federated queries to run concurrently. #4065
* [ENHANCEMENT] Label Values API call now supports `match[]` parameter when querying blocks on storage (assuming `-querier.query-store-for-labels-enabled` is enabled). #4133
* [BUGFIX] Ruler-API: fix bug where `/api/v1/rules/<namespace>/<group_name>` endpoint return `400` instead of `404`. #4013
* [BUGFIX] Distributor: reverted changes done to rate limiting in #3825. #3948
* [BUGFIX] Ingester: Fix race condition when opening and closing tsdb concurrently. #3959
* [BUGFIX] Querier: streamline tracing spans. #3924
* [BUGFIX] Ruler Storage: ignore objects with empty namespace or group in the name. #3999
* [BUGFIX] Distributor: fix issue causing distributors to not extend the replication set because of failing instances when zone-aware replication is enabled. #3977
* [BUGFIX] Query-frontend: Fix issue where cached entry size keeps increasing when making tiny query repeatedly. #3968
* [BUGFIX] Compactor: `-compactor.blocks-retention-period` now supports weeks (`w`) and years (`y`). #4027
* [BUGFIX] Querier: returning 422 (instead of 500) when query hits `max_chunks_per_query` limit with block storage, when the limit is hit in the store-gateway. #3937
* [BUGFIX] Ruler: Rule group limit enforcement should now allow the same number of rules in a group as the limit. #3616
* [BUGFIX] Frontend, Query-scheduler: allow querier to notify about shutdown without providing any authentication. #4066
* [BUGFIX] Querier: fixed race condition causing queries to fail right after querier startup with the "empty ring" error. #4068
* [BUGFIX] Compactor: Increment `cortex_compactor_runs_failed_total` if compactor failed compact a single tenant. #4094
* [BUGFIX] Tracing: hot fix to avoid the Jaeger tracing client to indefinitely block the Cortex process shutdown in case the HTTP connection to the tracing backend is blocked. #4134
* [BUGFIX] Forward proper EndsAt from ruler to Alertmanager inline with Prometheus behaviour. #4017

## 1.8.1 / 2021-04-27
