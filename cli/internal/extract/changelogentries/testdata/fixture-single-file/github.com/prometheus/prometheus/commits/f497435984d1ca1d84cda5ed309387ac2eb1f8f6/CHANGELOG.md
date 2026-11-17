# Changelog

## 3.13.5 / 2026-10-21

- [SECURITY] Container images: Update CA certificates to distrust "emSign ECC Root CA - G3" and "Comodo AAA Services root" following the compromise of eMudhra intermediate CA private keys.
- [SECURITY] Build with Go 1.26.10 to fix vulnerabilities in `net/http`, `net/textproto`, `crypto/tls` and `html/template`.
- [SECURITY] Bump golang.org/x/net to v0.60.0 to fix HTTP/2 vulnerabilities (GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617).
- [SECURITY] Bump OpenTelemetry to v1.45.0 to fix exporter endpoint URLs leaking into info logs (GO-2026-6505).
- [CHANGE] Building Prometheus now requires Go 1.26 or later.

## 3.13.4 / 2026-09-29

- [SECURITY] Bump google.golang.org/grpc to v1.83.1 to fix HTTP/2 DATA frame fragmentation memory exhaustion (GO-2026-6348). #19834
- [SECURITY] UI: Update vulnerable npm dependencies. #19834
- [BUGFIX] Agent: Ignore unknown WAL record types to allow rolling back from newer versions. #19814
- [BUGFIX] Federation: Fix corruption of float native histograms. #19679
- [BUGFIX] Scrape: Fix failing scrapes of protobuf float histograms with zero sample, zero and bucket counts, such as the result of recording `rate(x[1m])` over a constant histogram. #19682

## 3.13.3 / 2026-09-07

- [SECURITY] Bump github.com/klauspost/compress to v1.18.7 (GO-2026-5841) and golang.org/x/crypto to v0.55.0 (GO-2026-6303).
- [BUGFIX] Docker SD: Fix panic in Docker Swarm service discovery when a service runs as a plugin or network-attachment. #19102
- [BUGFIX] PromQL: Fix case-insensitive regex label matchers silently dropping matching values. #19167
- [BUGFIX] Scrape: Fix scrape manager spinning at 100% CPU on shutdown. #19149
- [BUGFIX] Alerting: Fix 100% CPU usage on shutdown that could delay graceful shutdown and trigger timeout-based kills. #17859
- [BUGFIX] TSDB: Fix out-of-order queries blocking compaction for hours, causing memory usage to grow. #19013
- [BUGFIX] TSDB: Fix deleted series causing missing samples and errors after restart. #19140
- [BUGFIX] TSDB: Fix goroutine and file handle leaks when Prometheus fails to open a corrupt TSDB. On Windows, the leaked directory handle also prevented TSDB directory removal. #18291

## 3.13.2 / 2026-07-29

- [SECURITY] Bump golang.org/x/text to v0.39.0 (CVE-2026-56852) and google.golang.org/grpc to v1.82.1 (GHSA-hrxh-6v49-42gf). #19290
- [BUGFIX] PromQL: Preallocate the active query tracker file to avoid SIGBUS crashes when the data disk is full. #19289

