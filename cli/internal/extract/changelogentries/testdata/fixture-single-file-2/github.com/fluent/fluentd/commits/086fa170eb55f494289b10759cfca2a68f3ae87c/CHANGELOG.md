# v1.20

## Release v1.20.1 - 2026/10/26

### Bug Fix

* gem: remove yajl-ruby from runtime dependencies for Ruby 4.1 https://github.com/fluent/fluentd/pull/5574
  * Plugins that `require 'yajl'` need to declare yajl-ruby in their own gemspec.
  * If you see `LoadError: cannot load such file -- yajl`, add yajl-ruby to your Gemfile. This works only on Ruby 4.0 or earlier.

## Release v1.20.0 - 2026/10/23

### Enhancement

* Replace Yajl with built-in JSON for simple cases https://github.com/fluent/fluentd/pull/5090
* out_forward: add `send_keepalive_packet` option to enable TCP keepalive (SO_KEEPALIVE) https://github.com/fluent/fluentd/pull/5262
* in_exec: add `command_timeout` option to limit child process execution time https://github.com/fluent/fluentd/pull/5320
* Replace Yajl with JSON for handling JSON stream https://github.com/fluent/fluentd/pull/5383
  * When an input stream ends in the middle of a JSON document, Fluentd now logs a warning and discards the incomplete tail instead of raising `ParseError`.
* system_config: add `umask` option to `<system>` directive https://github.com/fluent/fluentd/pull/5390
* parser_syslog: accept a space after RFC3164 priority https://github.com/fluent/fluentd/pull/5449
* in_tail: add opt-in `enable_dir_watcher` and `dir_watcher_limit` to discover new files earlier by watching directories https://github.com/fluent/fluentd/pull/5528
* in_tail: add opt-in worker-thread parsing via `num_threads` to offload parsing from the event loop https://github.com/fluent/fluentd/pull/5529
  * The default `num_threads 1` keeps the previous synchronous behavior.
  * In worker mode, `monitor_agent` also reports `worker_pending_batch_count`, `worker_pending_bytes` and `worker_parse_error_count`.
* buffer: add `evacuate_limit_size` to keep evacuated chunks from filling the disk https://github.com/fluent/fluentd/pull/5473
  * This option sets an approximate limit on the total size of the chunk files evacuated when the retry limit is reached, including the ones evacuated before. Chunks that do not fit are purged without being evacuated.
  * The default `nil` keeps the previous behavior. Set `0` to disable evacuation.
* in_forward: accept metadata on encapsulated timestamps sent by Fluent Bit v5.0.5 or later https://github.com/fluent/fluentd/pull/5411
* Enable Ruby JIT by default https://github.com/fluent/fluentd/pull/5464
  * The system configuration `enable_jit` now defaults to `true`.
  * JIT increases memory usage of each worker process. Set `enable_jit false` in the `<system>` section to restore the previous behavior.
  * This has no effect on Windows because YJIT is not supported there.
* fluent-plugin-generate: add .gitignore file https://github.com/fluent/fluentd/pull/5370
* Performance improvements
  * https://github.com/fluent/fluentd/pull/5281
  * https://github.com/fluent/fluentd/pull/5288
  * https://github.com/fluent/fluentd/pull/5289
  * https://github.com/fluent/fluentd/pull/5344
  * https://github.com/fluent/fluentd/pull/5353
  * https://github.com/fluent/fluentd/pull/5354
  * https://github.com/fluent/fluentd/pull/5357
  * https://github.com/fluent/fluentd/pull/5287
  * https://github.com/fluent/fluentd/pull/5278
  * https://github.com/fluent/fluentd/pull/5567

### Bug Fix

* http_server helper: Fix IPv6 bind address support in URI construction https://github.com/fluent/fluentd/pull/5239
  * Fixed `URI::InvalidURIError` when binding to IPv6 addresses (e.g., `::`, `::1`)
  * IPv6 addresses are now properly bracketed in URIs per RFC 3986 (e.g., `http://[::]:24231`)
  * Handles pre-bracketed addresses correctly to avoid double-bracketing
  * Affects all plugins using http_server helper with IPv6 bind addresses
* out_file: create symlinks for all chunks sharing the latest timekey https://github.com/fluent/fluentd/pull/5476
* time: fix TimeFormatter returning nil for the Unix epoch https://github.com/fluent/fluentd/pull/5420
* in_tail: fix log duplication when a rotated file is appended during `rotate_wait` with `follow_inodes` https://github.com/fluent/fluentd/pull/5499
* in_tail: fix `NameError` raised when flushing buffered lines with `emit_unmatched_lines true` https://github.com/fluent/fluentd/pull/5513
* in_tail: fix unread lines never being collected when a throttled file is removed from the watch list https://github.com/fluent/fluentd/pull/5515
* in_tail: fix shutdown errors and timeouts caused by an ongoing watcher refresh https://github.com/fluent/fluentd/pull/5530
* in_tail: fix closed stream error when file rotation overlaps with shutdown https://github.com/fluent/fluentd/pull/5551
* in_tail: use a monotonic clock for multiline flush timers so that they are not affected by wall-clock adjustments https://github.com/fluent/fluentd/pull/5542
* buffer: fix a race that could make the buffer `stage_size` gauge transiently negative while a write and a chunk enqueue overlap https://github.com/fluent/fluentd/pull/5481
* buffer: fix an enqueued unstaged file chunk being re-staged and flushed twice, which caused `closed stream` / `ENOENT` errors and leaked buffer size gauges https://github.com/fluent/fluentd/pull/5517
* parser_msgpack: fix leftover data from one parse call leaking into the next https://github.com/fluent/fluentd/pull/5553
* http_server helper: fix HTTP endpoints never recovering after a bind failure https://github.com/fluent/fluentd/pull/5523
  * The plugin now fails to start, and the worker is restarted until the port is available.
* root_agent: fix `emit_records` and `emit_size` never counted for inputs with `@label` https://github.com/fluent/fluentd/pull/5526
* supervisor: fix graceful config reload failing for YAML configuration https://github.com/fluent/fluentd/pull/5522
  * It also fixes `<<: !include` of a file that contains a mapping.

### Misc

* Drop Ruby 3.2 support https://github.com/fluent/fluentd/pull/5465
* out_http: remove the Net::HTTP extra_chain_cert monkey patch https://github.com/fluent/fluentd/pull/5484
* gem: add aarch64-mingw-ucrt gem https://github.com/fluent/fluentd/pull/5400
* gem: add json gem (>= 2.21) as runtime dependency and remove Refinements workaround https://github.com/fluent/fluentd/pull/5429
* in_tail: internal refactoring
  * https://github.com/fluent/fluentd/pull/5518
  * https://github.com/fluent/fluentd/pull/5520
  * https://github.com/fluent/fluentd/pull/5521
  * https://github.com/fluent/fluentd/pull/5527
  * https://github.com/fluent/fluentd/pull/5554
