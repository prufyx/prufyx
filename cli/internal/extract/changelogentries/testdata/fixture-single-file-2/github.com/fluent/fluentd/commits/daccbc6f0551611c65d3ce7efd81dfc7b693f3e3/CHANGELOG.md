# v1.16

## Release v1.16.9 - 2025/05/14

### Bug Fix

* winsvc: Fix bug where service accidentally stops after starting.
  The previous version (v1.16.8) should not be used for Windows Service.
  https://github.com/fluent/fluentd/pull/4955

### Misc

* CI improvemnts
  https://github.com/fluent/fluentd/pull/4956

## Release v1.16.8 - 2025/05/01

**This version has a critical bug about Windows Service. Do not use this version.**
(https://github.com/fluent/fluentd/pull/4955)

### Bug Fix

* winsvc: Stop the service when the supervisor is dead
  https://github.com/fluent/fluentd/pull/4942
* formatter_csv: Fix memory leak
  https://github.com/fluent/fluentd/pull/4920

### Misc

* Add fiddle as dependency gem for Ruby 3.5 on Windows
  https://github.com/fluent/fluentd/pull/4919
* Refactoring code
  https://github.com/fluent/fluentd/pull/4921
  https://github.com/fluent/fluentd/pull/4922
  https://github.com/fluent/fluentd/pull/4926
  https://github.com/fluent/fluentd/pull/4943
* CI improvemnts
  https://github.com/fluent/fluentd/pull/4821
  https://github.com/fluent/fluentd/pull/4850
  https://github.com/fluent/fluentd/pull/4851
  https://github.com/fluent/fluentd/pull/4862
  https://github.com/fluent/fluentd/pull/4915
  https://github.com/fluent/fluentd/pull/4923
  https://github.com/fluent/fluentd/pull/4925
  https://github.com/fluent/fluentd/pull/4927
