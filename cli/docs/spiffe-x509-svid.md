# SPIFFE X.509-SVID public-leaf URI-SAN subset

`prufyx check spiffe-x509-svid` checks one named standards-conformance subset
against a private local certificate. It has no version transition and does not
count as SPIRE upgrade coverage.

The subset requires a supplied certificate to be a non-CA leaf with exactly one
URI SAN, a reviewed-form lowercase `spiffe` scheme, and a non-root path. A
scoped `PASS` establishes only those four predicates. It does not validate the
complete SPIFFE ID grammar, signature or trust chain, issuer, trust bundle,
private-key possession, authentication, Workload API, issuance, authorization,
or runtime use.

## Check a local certificate

Use a regular private file owned by your account with mode `0600`. The input
must contain one exact DER certificate or one PEM `CERTIFICATE` block followed
only by whitespace.

```sh
chmod 600 ./workload-cert.pem
prufyx check spiffe-x509-svid \
  --certificate ./workload-cert.pem \
  --now 2026-09-11T01:00:00Z \
  --format human
```

The current embedded mode requires a canonical whole-second UTC `--now`. The
exit status is `0` for scoped `PASS`, `10` for scoped `FAIL`, `11` for
`UNKNOWN`, `2` for input/setup errors, and `3` for integrity failures. A parsed
CA certificate and a sole URI representation outside the reviewed field subset
return `UNKNOWN`. Malformed, multiple, or trailing certificate encodings stop
as input errors.

The checker reads but does not modify the certificate. Reports contain only the
four minimized typed predicates and their digest. They exclude the certificate
bytes, subject, URI, host, path, input file path, and raw certificate digest.
An optional `--certificate-digest sha256:...` verifies the supplied bytes for a
current check and is mandatory for replay, but remains separate from the saved
report.

## Select verified local profile metadata

Use a dedicated store for the closed `spiffe-x509-svid` profile. Explicit local
selection is authoritative and never falls back to the embedded profile.

```sh
prufyx db import ./profile-revision.tar \
  --profile spiffe-x509-svid --db-root ./spiffe-profile-store \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest>

prufyx check spiffe-x509-svid \
  --certificate ./workload-cert.pem \
  --knowledge-db ./spiffe-profile-store --format json \
  > ./saved-report.json
chmod 600 ./saved-report.json
```

External current evaluation uses the verifier's clock and rejects `--now`.
An empty selected revision produces `UNKNOWN`; it does not use the embedded
rule. Current checks may optionally assert revision, bundle digest, and trust
receipt digest.

Historical replay uses the saved report time and requires the report, the raw
certificate digest, and all three exact knowledge identities:

```sh
prufyx check spiffe-x509-svid \
  --certificate ./workload-cert.pem \
  --certificate-digest sha256:<raw-certificate-digest> \
  --knowledge-db ./spiffe-profile-store \
  --replay-report ./saved-report.json \
  --knowledge-revision 2 \
  --knowledge-bundle-digest sha256:<profile-digest> \
  --knowledge-trust-receipt-digest sha256:<receipt-digest> \
  --format json
```

Replay reports `MATCH` only for the same minimized predicates, selected
knowledge, recorded time, and binary identity. The separate raw pin verifies
the certificate bytes presented for replay; it is not stored in the report.
Offline replay does not establish current non-revocation or cross-binary replay.

## Profile contributions and publication

The fixed target is
`knowledge/spiffe-x509-svid-profile.v1.json`. The schema admits zero or one
closed rule and an immutable normative source from
`https://github.com/spiffe/spiffe` at `standards/X509-SVID.md`. A profile update
may change its positive revision, full commit, source digest, line spans, and
evidence expiry. Repository, path, rule identity, schema, purpose, and engine
capability remain closed. An update cannot add new certificate predicates or
broaden this subset without a CLI release.

A contributor proposes exact source bytes, digest, spans, expiry, and expected
positive, failure, unknown, privacy, and replay cases. Independent source and
implementation review precede maintainer acceptance. Local JSON validation and
archive assembly do not sign or publish trusted metadata. After acceptance,
the existing [signed-package handoff](knowledge-updates.md#assemble-an-already-signed-package)
is a separate responsibility of maintainer Spas Atanasov (`@airstand`), followed
by consumer verification and explicit import or update. This repository does
not provide a production signer, hosted feed, or official trust root.

The synthetic generator exercises empty revision 1 and active revisions 2 and
3 with ephemeral keys and public certificate inputs:

```sh
go run ./examples/community/knowledge/generate-synthetic-packages.go \
  --profile spiffe-x509-svid --output ./synthetic-spiffe-profile
```

Synthetic metadata is test-only and creates no conformance authority.
