## master / unreleased

BREAKING CHANGES:

Changes:

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 0.26.0 / 2025-02-26

* [CHANGE] adopt log/slog, drop go-kit/log #1311
* [FEATURE] Add metric to record tls ciphersuite negotiated during handshake #1203
* [FEATURE] Add a way to export labels with content matched by the probe #1284
* [FEATURE] Reports Certificate Serial number #1333
* [ENHANCEMENT] Enable misspell linter #1248
* [ENHANCEMENT] Fix incorrect parameters name in documentation #1126
* [ENHANCEMENT] Add stale workflow to start sync with stale.yaml in prometheus #1170
* [ENHANCEMENT] Update CONFIGURATION.md to clarify that valid_status_codes expects a list #1335
* [ENHANCEMENT] Skip failing IPv6 tests in test CI Pipeline #1342
* [ENHANCEMENT] Add RabbitMQ probe example #1349
* [BUGFIX] Only register grpc TLS metrics on successful handshake #1338

## 0.25.0 / 2024-04-09

* [FEATURE] Allow to get Probe logs by target #1063
* [FEATURE] Log errors from probe #1091
* [BUGFIX] Prevent logging confusing error message #1059
* [BUGFIX] Explicit registration of internal exporter metrics 1060
