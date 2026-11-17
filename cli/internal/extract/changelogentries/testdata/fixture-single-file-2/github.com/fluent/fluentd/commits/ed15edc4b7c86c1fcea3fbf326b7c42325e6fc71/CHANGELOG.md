# v1.19

## Release v1.19.0 - 2025/07/29

### Enhancement

New features:

* Add zstd compression support https://github.com/fluent/fluentd/pull/4657
  * Buffer: add `zstd` to `compress` option.
  * out_file: add `zstd` to `compress` option.
  * out_forward: add `zstd` to `compress` option.
  * in_forward: support `zstd` format. (Experimental)
* buffer: add feature to evacuate chunk files when retry limit
  https://github.com/fluent/fluentd/pull/4986
* out_http: TLS1.3 support
  https://github.com/fluent/fluentd/pull/4859
* out_stdout: support output to STDOUT independently of Fluentd logger by setting `use_logger` to `false`
  https://github.com/fluent/fluentd/pull/5036
* out_file: add symlink_path_use_relative option to use relative path instead of absolute path in symlink_path
  https://github.com/fluent/fluentd/pull/4904
* System configuration: Add forced_stacktrace_level to force the log level of stacktraces.
  https://github.com/fluent/fluentd/pull/5008
* System configuration: support built-in config files
  https://github.com/fluent/fluentd/pull/4893

Metrics:

* metrics: enable input metrics by default
  https://github.com/fluent/fluentd/pull/4966
* in_tail: add "tracked_file_count" metrics to see how many log files are being tracked
  https://github.com/fluent/fluentd/pull/4980
* output: add metrics for number of writing events in secondary
  https://github.com/fluent/fluentd/pull/4971
* output: add metrics for dropped oldest chunk count
  https://github.com/fluent/fluentd/pull/4981

Others:

* in_forward: enable skip_invalid_event by default not to process broken data
  https://github.com/fluent/fluentd/pull/5003
* buf_file: reinforce buffer file corruption check
  https://github.com/fluent/fluentd/pull/4998
* in_http: allow empty Origin header requests to pass CORS checks
  https://github.com/fluent/fluentd/pull/4866
* in_tail: add warning for directory permission
  https://github.com/fluent/fluentd/pull/4865
* Add logging for errors about loading dependencies on startup
  https://github.com/fluent/fluentd/pull/4858
* Performance improvements
  * https://github.com/fluent/fluentd/pull/4759
    https://github.com/fluent/fluentd/pull/4760
    https://github.com/fluent/fluentd/pull/4763
    https://github.com/fluent/fluentd/pull/4764
    https://github.com/fluent/fluentd/pull/4769
    https://github.com/fluent/fluentd/pull/4813
    https://github.com/fluent/fluentd/pull/4817
    https://github.com/fluent/fluentd/pull/4835
    https://github.com/fluent/fluentd/pull/4845
    https://github.com/fluent/fluentd/pull/4881
    https://github.com/fluent/fluentd/pull/4884
    https://github.com/fluent/fluentd/pull/4886
    https://github.com/fluent/fluentd/pull/4930
    https://github.com/fluent/fluentd/pull/4931
    https://github.com/fluent/fluentd/pull/4932
    https://github.com/fluent/fluentd/pull/4933
    https://github.com/fluent/fluentd/pull/4934
    https://github.com/fluent/fluentd/pull/4995

### Bug Fix

* in_tail: fixed where specifying only encoding parameter might cause data corruption (affects since v0.14.12).
  https://github.com/fluent/fluentd/pull/5010
* formatter_csv: fix memory leak
  https://github.com/fluent/fluentd/pull/4864
* server plugin helper: ensure to close all connections at shutdown
  https://github.com/fluent/fluentd/pull/502
* Fixed a bug where the default `umask` was not set to `0` when using `--daemon` (td-agent, fluent-package) since v1.14.6.
  https://github.com/fluent/fluentd/pull/4836
* `--umask` command line option: Fixed so that it is applied when Fluentd runs with `--daemon` (fluent-package) as well as when Fluentd runs with `--no-supervisor`.
  https://github.com/fluent/fluentd/pull/4836
* Windows: Stop the service when the supervisor is dead
  https://github.com/fluent/fluentd/pull/4909
* Windows: Fixed an issue where stopping the service immediately after startup could leave the processes.
  https://github.com/fluent/fluentd/pull/4782
* Windows: Fixed an issue where stopping service sometimes can not be completed forever.
  https://github.com/fluent/fluentd/pull/4782

### Misc

* in_monitor_agent: stop using CGI.parse due to support Ruby 3.5
  https://github.com/fluent/fluentd/pull/4962
* HTTP server plugin helper: stop using CGI.parse due to support Ruby 3.5
  https://github.com/fluent/fluentd/pull/4962
* config: change inspect format
  https://github.com/fluent/fluentd/pull/4914
* console_adapter: support console gem v1.30
  https://github.com/fluent/fluentd/pull/4857
* gemspec: fix io-event and io-stream version to avoid unstable behavior on Windows
  https://github.com/fluent/fluentd/pull/5042
* in_http: replace WEBrick::HTTPUtils.parse_query with URI
  Note that at least, this makes it unable to use ; delimiter.
  https://github.com/fluent/fluentd/pull/4900
* http_server: stop fallback to WEBrick
  https://github.com/fluent/fluentd/pull/4899
* metrics: add getter method automatically
  https://github.com/fluent/fluentd/pull/4978
* http_server helper: add `header` method for `Request`
  https://github.com/fluent/fluentd/pull/4903
* multi_output: fix metrics name
  https://github.com/fluent/fluentd/pull/4979
* plugin_id: fix typo
  https://github.com/fluent/fluentd/pull/4964
* CI fixes
  * https://github.com/fluent/fluentd/pull/4728
    https://github.com/fluent/fluentd/pull/4730
    https://github.com/fluent/fluentd/pull/4746
    https://github.com/fluent/fluentd/pull/4747
    https://github.com/fluent/fluentd/pull/4748
    https://github.com/fluent/fluentd/pull/4750
    https://github.com/fluent/fluentd/pull/4755
    https://github.com/fluent/fluentd/pull/4820
    https://github.com/fluent/fluentd/pull/4874
    https://github.com/fluent/fluentd/pull/4877
* Fixes RuboCop's remarks
  https://github.com/fluent/fluentd/pull/4928
* CI: Add benchmark scripts
  https://github.com/fluent/fluentd/pull/4989

# v1.18

## Release v1.18.0 - 2024/11/29

### Enhancement

* Add zero-downtime-restart feature for non-Windows
  https://github.com/fluent/fluentd/pull/4624
* Add with-source-only feature
  https://github.com/fluent/fluentd/pull/4661
  * `fluentd` command: Add `--with-source-only` option
  * System configuration: Add `with_source_only` option
* Embedded plugin: Add `out_buffer` plugin, which can be used for buffering and relabeling events
  https://github.com/fluent/fluentd/pull/4661
* Config File Syntax: Extend Embedded Ruby Code support for Hashes and Arrays
  https://github.com/fluent/fluentd/pull/4580
  * Example: `key {"foo":"#{1 + 1}"} => key {"foo":"2"}`
  * Please note that this is not backward compatible, although we assume that this will never affect to actual existing configs.
  * In case the behavior changes unintentionally, you can disable this feature by surrounding the entire value with single quotes.
    * `key '{"foo":"#{1 + 1}"}' => key {"foo":"#{1 + 1}"}`
* transport tls: Use SSL_VERIFY_NONE by default
  https://github.com/fluent/fluentd/pull/4718
* transport tls: Add ensure_fips option to ensure FIPS compliant mode
  https://github.com/fluent/fluentd/pull/4720
* plugin_helper/server: Add receive_buffer_size parameter in transport section
  https://github.com/fluent/fluentd/pull/4649
* filter_parser: Now able to handle multiple parsed results
  https://github.com/fluent/fluentd/pull/4620
* in_http: add `add_tag_prefix` option
  https://github.com/fluent/fluentd/pull/4655
* System configuration: add `path` option in `log` section
  https://github.com/fluent/fluentd/pull/4604

### Bug Fix

* command: fix NoMethodError of --daemon under Windows
  https://github.com/fluent/fluentd/pull/4716
* `fluentd` command: fix `--plugin` (`-p`) option not to overwrite default value
  https://github.com/fluent/fluentd/pull/4605

### Misc

* http_server: Ready to support Async 2.0 gem
  https://github.com/fluent/fluentd/pull/4619
* Minor code refactoring
  * https://github.com/fluent/fluentd/pull/4641
* CI fixes
  * https://github.com/fluent/fluentd/pull/4638
  * https://github.com/fluent/fluentd/pull/4644
  * https://github.com/fluent/fluentd/pull/4675
  * https://github.com/fluent/fluentd/pull/4676
  * https://github.com/fluent/fluentd/pull/4677
  * https://github.com/fluent/fluentd/pull/4686
