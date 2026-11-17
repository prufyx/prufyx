## master / unreleased

BREAKING CHANGES:

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 0.29.1 / 2026-10-21

* [SECURITY] Container images: Update CA certificates to distrust "emSign ECC Root CA - G3" and "Comodo AAA Services root" following the compromise of eMudhra intermediate CA private keys.
* [SECURITY] Build with Go 1.27.3 to fix vulnerabilities in `net/http`, `net/textproto`, `mime/multipart`, `crypto/tls`, `crypto/x509` and `html/template`. `crypto/x509` now rejects the compromised eMudhra intermediates on hosts with an outdated CA store.
* [SECURITY] Bump golang.org/x/net to v0.61.0 to fix HTTP/2 vulnerabilities (GO-2026-6603, GO-2026-6611, GO-2026-6612, GO-2026-6617). #1710
* [BUGFIX] Update cel-go to v0.32.0, now imported from `cel.dev/cel-go`. #1697
* [BUGFIX] Update client_golang to v1.25.0, common to v0.72.1 and brotli to v1.2.6. #1710 #1711

## 0.29.0 / 2026-10-07

* [CHANGE] Reduce log noise #1517
* [CHANGE] Fail if `prober` config contains invalid value #1521
* [FEATURE] Add websocket connection prober #1278
* [FEATURE] Add probe timeout metric #1571
* [FEATURE] Add tcp and unix prober metric for `tls_cipher_info` #1579
* [FEATURE] Add CRL certificate revocation checking #1583
* [ENHANCEMENT] prober: Handle single and double encoded target parameter #1525
* [ENHANCEMENT] prober: Randomize ICMP echo identifier to avoid SNAT session collision #1537
* [BUGFIX] Make HTTP scheme parsing case-insensitive #1137
* [BUGFIX] Return on grpc.NewClient error and propagate probe context- #1557
* [BUGFIX] prober/unix: Return the TLS-config error instead of a nil error #1629
