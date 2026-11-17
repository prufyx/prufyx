# v1.15

## Release v1.15.0 - 2022/06/29

### Enhancement

* in_tail: Add log throttling in files based on group rules
  https://github.com/fluent/fluentd/pull/3535
  https://github.com/fluent/fluentd/pull/3771
* Add `dump` command to fluent-ctl
  https://github.com/fluent/fluentd/pull/3680
* Handle YAML configuration format on configuration file
  https://github.com/fluent/fluentd/pull/3712
* Add `restart_worker_interval` parameter in `<system>` directive to set
  interval to restart workers that has stopped for some reason.
  https://github.com/fluent/fluentd/pull/3768

### Bug fixes

* out_forward: Fix to update timeout of cached sockets
  https://github.com/fluent/fluentd/pull/3711
* in_tail: Fix a possible crash on file rotation when `follow_inodes true`
  https://github.com/fluent/fluentd/pull/3754
* output: Fix a possible crash of flush thread
  https://github.com/fluent/fluentd/pull/3755
* in_tail: Fix crash bugs on Ruby 3.1 on Windows
  https://github.com/fluent/fluentd/pull/3766
* in_tail: Fix a bug that in_tail cannot open non-ascii path on Windows
  https://github.com/fluent/fluentd/pull/3774
* Fix a bug that fluentd doesn't release its own log file even after rotated by
  external tools
  https://github.com/fluent/fluentd/pull/3782

### Misc

* in_tail: Simplify TargetInfo related code
  https://github.com/fluent/fluentd/pull/3489
* Fix a wrong issue number in CHANGELOG
  https://github.com/fluent/fluentd/pull/3700
* server helper: Add comments to linger_timeout behavior about Windows
  https://github.com/fluent/fluentd/pull/3701
* service_discovery: Fix typo
  https://github.com/fluent/fluentd/pull/3724
* test: Fix unstable tests and warnings
  https://github.com/fluent/fluentd/pull/3745
  https://github.com/fluent/fluentd/pull/3753
  https://github.com/fluent/fluentd/pull/3767
  https://github.com/fluent/fluentd/pull/3783
  https://github.com/fluent/fluentd/pull/3784
  https://github.com/fluent/fluentd/pull/3785
  https://github.com/fluent/fluentd/pull/3787

# v1.14

## Release v1.14.6 - 2022/03/31

### Enhancement

* Enable server plugins to specify socket-option `SO_LINGER`
  https://github.com/fluent/fluentd/pull/3644
* Add `--umask` command line parameter
  https://github.com/fluent/fluentd/pull/3671
  https://github.com/fluent/fluentd/pull/3679

### Bug fixes

* Fix metric name typo
  https://github.com/fluent/fluentd/pull/3630
  https://github.com/fluent/fluentd/pull/3673
* Apply modifications in pipeline to the records being passed to `@ERROR` label
  https://github.com/fluent/fluentd/pull/3631
* Fix wrong calculation of retry interval
  https://github.com/fluent/fluentd/pull/3640
  https://github.com/fluent/fluentd/pull/3649
  https://github.com/fluent/fluentd/pull/3685
  https://github.com/fluent/fluentd/pull/3686
* Support IPv6 address for `rpc_endpoint` in `system` config
  https://github.com/fluent/fluentd/pull/3641

### Misc

* CI: Support Ruby 3.1 except Windows
  https://github.com/fluent/fluentd/pull/3619
* Switch to GitHub Discussions
  https://github.com/fluent/fluentd/pull/3654
* Fix CHANGELOG.md heading styles
  https://github.com/fluent/fluentd/pull/3648
* Declare `null_value_pattern` as `regexp`
  https://github.com/fluent/fluentd/pull/3650
