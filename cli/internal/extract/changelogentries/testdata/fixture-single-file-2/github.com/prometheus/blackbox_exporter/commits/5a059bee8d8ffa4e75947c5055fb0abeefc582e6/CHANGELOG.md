## master / unreleased

BREAKING CHANGES:

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 0.28.0 / 2025-12-04

BREAKING CHANGES:

* The `--log.prober` flag behavior has changed. The scrape probe logger is now an independent logger. Please review the README.md and adjust configurations as needed. #1461
* Log leveling has been improved for several prober modules. Changes include logging errors at `ERROR` level instead of `INFO`, and adjusting many prober logs from `INFO` to `DEBUG` level. To see more detailed probe logs, set `--log.prober=debug`. #1461

Changes:

* [CHANGE] Make default HTTP User-Agent compliant with RFC9110 (now `Blackbox-Exporter/<version>`) #1446
* [CHANGE] Config is not reloaded if the file content didn't change when using all reload methods #1464
* [FEATURE] Support HTTP/3 (QUIC) prober #1425
* [FEATURE] Add support for configuring gRPC metadata in gRPC prober #956
* [FEATURE] Implement byte matching in TCP query responses #1441
* [FEATURE] Add a new type of probe using unix domain sockets #1480
* [FEATURE] Support config reload automatically - feature flag `config.enable-auto-reload`, `config.auto-reload-interval` #1464
* [BUGFIX] Fix retrieving probe logs by target name when probed by multiple modules #1257
* [BUGFIX] Fix error handling in auto-reload config case #1478
* [BUGFIX] Fix `debug` param log output work regardless of log level #1438

## 0.27.0 / 2025-06-26

* [FEATURE] Support matching JSON body with CEL expressions #1255
* [BUGFIX] Fix condition when local dns lookup should happen #1272
* [BUGFIX] Stop scrape logger spam #1381
