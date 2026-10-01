# CloudEvents structured JSON core-envelope subset

`prufyx check cloudevents-structured-json` checks one named
standards-conformance subset against a private local JSON event. It has no
version transition. The embedded profile covers CloudEvents edition `1.0` and
requires:

- an object with no repeated exact decoded top-level member name;
- nonempty valid CloudEvents String values for `specversion`, `id`, and `type`;
- a nonempty JSON string for `source`, without Unicode surrogate repair; and
- no simultaneous `data` and `data_base64` members.

A scoped `PASS` establishes only these predicates. It does not validate source
URI-reference semantics, source-plus-id uniqueness, payload schemas, base64
content, extensions, batching, transport bindings, SDK/runtime behavior,
delivery, signing, or authentication.

## Check a private event

Use a regular single-link file owned by your account with mode `0600`. The file
must contain one UTF-8 JSON value no larger than 1 MiB. Unrelated members and
nested data are syntax-checked but otherwise ignored.

```sh
cp cli/examples/cncf/cloudevents-structured-json/event.json ./event.json
chmod 600 ./event.json
prufyx check cloudevents-structured-json \
  --event ./event.json \
  --now 2026-09-11T04:00:00Z \
  --format human
```

Embedded current evaluation requires a canonical whole-second UTC `--now`.
Exit status is `0` for scoped `PASS`, `10` for scoped `FAIL`, `11` for
`UNKNOWN`, `2` for input/setup errors, and `3` for integrity failures.
Malformed JSON or UTF-8 is an input error. A non-object, an exact decoded
top-level duplicate, a valid non-`1.0` edition, or `source` requiring unpaired
surrogate repair is `UNKNOWN`. A missing or invalid required core attribute, or
both payload members, is scoped `FAIL`.

The checker reads but does not modify the event. The report contains only the
staged typed predicates and their canonical digest. It excludes the raw event,
its path and raw digest, and all caller-supplied member names and values. An
optional `--event-digest sha256:...` verifies the supplied bytes for a current
check and is mandatory for replay; that raw pin stays outside the report and
knowledge store.

## Select verified local profile metadata

The `cloudevents-structured-json` profile uses its own store. Explicit local
selection is authoritative and never falls back to the embedded rule.

```sh
prufyx db import ./profile-revision.tar \
  --profile cloudevents-structured-json \
  --db-root ./cloudevents-profile-store \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest>

prufyx check cloudevents-structured-json \
  --event ./event.json \
  --knowledge-db ./cloudevents-profile-store \
  --format json > ./saved-report.json
chmod 600 ./saved-report.json
```

External current evaluation uses the verifier's clock and rejects `--now`. A
valid selected revision with zero rules produces `UNKNOWN`; it does not use the
embedded rule. Current checks may optionally assert revision, bundle digest,
and trust-receipt digest.

Historical replay uses the saved report time and requires the report, exact raw
event digest, and all three knowledge identities:

```sh
prufyx check cloudevents-structured-json \
  --event ./event.json \
  --event-digest sha256:<raw-event-digest> \
  --knowledge-db ./cloudevents-profile-store \
  --replay-report ./saved-report.json \
  --knowledge-revision 2 \
  --knowledge-bundle-digest sha256:<profile-digest> \
  --knowledge-trust-receipt-digest sha256:<receipt-digest> \
  --format json
```

Replay reports `MATCH` only when the minimized predicates, selected historical
profile, recorded time, and binary identity reproduce the saved report. The raw
event digest is checked separately and is not persisted. Historical replay does
not establish current non-revocation.

## Profile and source boundary

The embedded and signed local targets use
`prufyx.io/cloudevents-structured-json-profile/v1`. An active profile contains
one rule, `cloudevents-v1-structured-json-core-envelope-v1`, and exactly two
source records from `https://github.com/cloudevents/spec`: role `spec` at
`spec.md`, and role `json-format` at `json-format.md`. Each signed profile binds
the full source commit, content digest, bounded line spans, evidence expiry, and
engine capability. A later independently reviewed signed profile may update
those source tuples and its positive revision while the repository, roles,
paths, profile identity, rule identity, and capability remain closed.

Profile evidence expiry and selected TUF metadata expiry each produce
`UNKNOWN` for their own reason. Invalid profile shape, marker, signature,
digest, or selection binding is an integrity failure with no fallback.

The synthetic generator can produce empty and active local profiles for
protocol testing:

```sh
cd cli
go run ./examples/community/knowledge/generate-synthetic-packages.go \
  --profile cloudevents-structured-json \
  --output /absolute/private/test-directory
```

Those packages use ephemeral fixture keys, synthetic review dates, and
`synthetic_test_only` purpose. They demonstrate import, selection, and replay
mechanics only. They are not reviewed CloudEvents authority or a production
signing/publication path. The offline `prufyx-maintainer package-knowledge` assembler accepts
an already signed target for this closed profile; assembly does not sign or
approve it.
