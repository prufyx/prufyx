## master / unreleased

BREAKING CHANGES:

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]
* [BUGFIX] Randomize ICMP Echo ID in probes to avoid SNAT session collisions that could drop replies for some clients.

## 0.29.0 / 2026-10-07

* [CHANGE] Reduce log noise #1517
* [CHANGE] Fail if `prober` config contains invalid value #1521
* [FEATURE] Add websocket connection prober #1278
* [FEATURE] Add probe timeout metric #1571
* [FEATURE] Add tcp and unix prober metric for `tls_cipher_info` #1579
* [FEATURE] Add CRL certificate revocation checking #1583
* [ENHANCEMENT] prober: Handle single and double encoded target parameter #1525
* [EHHANCEMENT] prober: Randomize ICMP echo identifier to avoid SNAT session collision #1537
* [BUGFIX] Make HTTP scheme parsing case-insensitive #1137
* [BUGFIX] Return on grpc.NewClient error and propagate probe context- #1557
* [BUGFIX] prober/unix: Return the TLS-config error instead of a nil error #1629

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
