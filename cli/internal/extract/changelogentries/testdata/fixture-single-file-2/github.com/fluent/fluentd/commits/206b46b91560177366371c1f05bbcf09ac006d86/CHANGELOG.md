# v1.16

## Release v1.16.0 - 2023/03/29

### Enhancement

* in_tcp: Add `send_keepalive_packet` option
  https://github.com/fluent/fluentd/pull/3961
* buffer: backup broken file chunk
  https://github.com/fluent/fluentd/pull/4025
* Add warning messages for restoring buffer with `flush_at_shutdown true`
  https://github.com/fluent/fluentd/pull/4027
* Add logs for time period of restored buffer possibly broken
  https://github.com/fluent/fluentd/pull/4028

### Bug Fix

* http_server_helper: Fix format of log messages originating from Async gem
  https://github.com/fluent/fluentd/pull/3987
* Change to not generate a sigdump file after receiving a `SIGTERM` signal on
  non-Windows
  https://github.com/fluent/fluentd/pull/4034
  https://github.com/fluent/fluentd/pull/4043
* out_forward: fix error of ack handling conflict on stopping with
  `require_ack_response` enabled
  https://github.com/fluent/fluentd/pull/4030
* Fix problem that some `system` configs are not reflected
  https://github.com/fluent/fluentd/pull/4064
  https://github.com/fluent/fluentd/pull/4065
  https://github.com/fluent/fluentd/pull/4086
  https://github.com/fluent/fluentd/pull/4090
  https://github.com/fluent/fluentd/pull/4096
* Fix bug that the logger outputs some initial log messages without applying
  some settings such as `format`
  https://github.com/fluent/fluentd/pull/4091
* Windows: Fix a bug that the wrong log file is reopened with log rotate setting
  when flushing or graceful reloading
  https://github.com/fluent/fluentd/pull/4054
* Fix race condition of out_secondary_file
  https://github.com/fluent/fluentd/pull/4081
* Suppress warning using different secondary for out_secondary_file
  https://github.com/fluent/fluentd/pull/4087
* Fix value of `system_config.workers` at `run_configure`.
  Change argument type of `Fluent::Plugin::Base::configure()` to
  `Fluent::Config::Element` only.
  https://github.com/fluent/fluentd/pull/4066
* Fix bug that Fluentd sometimes tries to use an unavailable port and fails to
  start on Windows
  https://github.com/fluent/fluentd/pull/4092

### Misc

* Add method for testing `filtered_with_time`
  https://github.com/fluent/fluentd/pull/3899
* Replace `$$` with `Process.pid`
  https://github.com/fluent/fluentd/pull/4040
* Relax required webric gem version
  https://github.com/fluent/fluentd/pull/4061
* CI fixes to support Ruby 3.2
  https://github.com/fluent/fluentd/pull/3968
  https://github.com/fluent/fluentd/pull/3996
  https://github.com/fluent/fluentd/pull/3997
* Other CI fixes
  https://github.com/fluent/fluentd/pull/3969
  https://github.com/fluent/fluentd/pull/3990
  https://github.com/fluent/fluentd/pull/4013
  https://github.com/fluent/fluentd/pull/4033
  https://github.com/fluent/fluentd/pull/4044
  https://github.com/fluent/fluentd/pull/4050
  https://github.com/fluent/fluentd/pull/4062
  https://github.com/fluent/fluentd/pull/4074
  https://github.com/fluent/fluentd/pull/4082
  https://github.com/fluent/fluentd/pull/4085
* Update MAINTAINERS.md
  https://github.com/fluent/fluentd/pull/4026
  https://github.com/fluent/fluentd/pull/4069

# v1.15

## Release v1.15.3 - 2022/11/02

### Bug Fix

* Support glob for `!include` directive in YAML config format
  https://github.com/fluent/fluentd/pull/3917
* Remove meaningless oj options
  https://github.com/fluent/fluentd/pull/3929
* Fix log initializer to correctly create per-process files on Windows
  https://github.com/fluent/fluentd/pull/3939
* out_file: Fix the multi-worker check with `<worker 0-N>` directive
  https://github.com/fluent/fluentd/pull/3942

### Misc

* Fix broken tests on Ruby 3.2
  https://github.com/fluent/fluentd/pull/3883
  https://github.com/fluent/fluentd/pull/3922
