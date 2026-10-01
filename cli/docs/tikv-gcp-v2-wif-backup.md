# TiKV 8.5.8 GCS WIF full-backup planned-operation preflight

`prufyx check tikv-gcp-v2-wif-backup` checks one source-linked setting in a
caller-supplied proposed TiKV configuration. It has no from-version or upgrade
claim. The embedded profile covers only target TiKV `8.5.8` and the declared
operation `gcs-full-backup-wif`.

The check parses a complete native TOML document and inspects only the root
`[backup]` table. Exactly one of these spellings must be present as a TOML
Boolean:

- `gcp-v2-enable`
- `gcp_v2_enable`

The spellings are normalized to the same typed observation. If both are
present, neither is selected and the result is `UNKNOWN`, even when their
values agree. A missing `[backup]` table, a non-table `backup` value, an absent
setting, or a non-Boolean setting is also `UNKNOWN`. The checker does not infer
the documented target default for an omitted setting.

For the exact target and operation, explicit `false` is scoped `BLOCKED` and
explicit `true` is scoped `PASS`. Every result keeps aggregate backup readiness
`UNKNOWN`. The check does not observe effective configuration, include or
override precedence, online configuration, `last_tikv.toml`, credentials,
Workload Identity Federation setup, GCS access, backup execution or completion,
restore, log backup, installation, startup, runtime behavior, or data safety.

## Check a private proposed configuration

Copy the example to an operator-owned regular single-link file and make it
private:

```sh
cp cli/examples/cncf/tikv-gcp-v2-wif-backup/tikv.toml ./tikv.toml
chmod 600 ./tikv.toml
prufyx check tikv-gcp-v2-wif-backup \
  --config ./tikv.toml \
  --target-version 8.5.8 \
  --operation gcs-full-backup-wif \
  --now 2026-09-11T05:00:00Z \
  --format human
```

Embedded current evaluation requires canonical whole-second UTC `--now`.
Change the one explicit supported setting from `false` to `true`, validate the
complete intended configuration separately with the target TiKV binary's
`--config-check` flow when available, and rerun the same Prufyx command. Prufyx
does not execute TiKV, `--config-check`, backup, restore, a shell command, or a
network request.

Exit status is `0` for scoped `PASS`, `10` for scoped `BLOCKED`, `11` for
`UNKNOWN`, `2` for input/setup errors, and `3` for integrity failures. A
well-formed target version other than `8.5.8` or a well-formed operation other
than `gcs-full-backup-wif` is minimized to an unsupported class and returns
`UNKNOWN`. Malformed target or operation syntax is an input error. Raw flag
tokens are never printed or stored.

The input is bounded to 1 MiB and uses the shared private-file admission: mode
`0600`, regular file, no symlink, exactly one hard link, and a stable read from
one descriptor. Valid unrelated TOML fields are allowed. The report retains
only the covered/unsupported target class, reviewed-operation Boolean, and the
setting Boolean when available. It excludes raw TOML, comments, unrelated keys
and values, input path, raw digest, addresses, endpoints, buckets and
credentials. An optional `--config-digest sha256:...` pins the current bytes and
is mandatory for replay; the pin remains outside the report and knowledge
store.

## Select verified local profile metadata

The `tikv-gcp-v2-wif-backup` profile has its own store. Explicit selection is
authoritative and never falls back to the embedded rule:

```sh
prufyx db import ./profile-revision.tar \
  --profile tikv-gcp-v2-wif-backup \
  --db-root ./tikv-preflight-store \
  --bootstrap-root ./root.json \
  --bootstrap-root-digest sha256:<independently-verified-root-digest>

prufyx check tikv-gcp-v2-wif-backup \
  --config ./tikv.toml \
  --target-version 8.5.8 \
  --operation gcs-full-backup-wif \
  --knowledge-db ./tikv-preflight-store \
  --format json > ./saved-report.json
chmod 600 ./saved-report.json
```

External current evaluation uses the verifier's clock and rejects `--now`. A
valid selected revision with zero rules produces `UNKNOWN`; it does not use the
embedded rule. Current checks may optionally assert revision, bundle digest,
and trust-receipt digest.

Historical replay uses the saved report time and requires the saved report,
the exact raw configuration digest, and all three knowledge identities:

```sh
prufyx check tikv-gcp-v2-wif-backup \
  --config ./tikv.toml \
  --target-version 8.5.8 \
  --operation gcs-full-backup-wif \
  --config-digest sha256:<raw-config-digest> \
  --knowledge-db ./tikv-preflight-store \
  --replay-report ./saved-report.json \
  --knowledge-revision 2 \
  --knowledge-bundle-digest sha256:<profile-digest> \
  --knowledge-trust-receipt-digest sha256:<receipt-digest> \
  --format json
```

Replay reports `MATCH` only when the minimized observation, selected historical
profile, saved time and binary identity reproduce the canonical saved report.
It retains the saved scoped claim exit: a matching saved `BLOCKED` report exits
`10`. The separately checked raw digest is not persisted. Historical replay
does not establish current non-revocation.

## Profile and source boundary

The embedded and signed local targets use
`prufyx.io/tikv-gcp-v2-wif-backup-profile/v1`. An active profile contains one
rule, `tikv-8.5.8-gcp-v2-wif-full-backup-enabled-v1`, and exactly three source
roles: the target setting declaration in `tikv/tikv`, the target full-backup
caller in `tikv/tikv`, and operator action guidance in `pingcap/docs`. Each
profile binds repositories, paths, immutable commits, content digests, bounded
line spans, evidence expiry, and engine capability. The two TiKV source records
must use the same target commit. The independently pinned documentation commit
is a source revision for the claimed TiKV applicability; it is not a PingCAP
Docs release tag.

Profile evidence expiry and selected TUF metadata expiry each produce
`UNKNOWN` for their own reason. Invalid profile shape, marker, signature,
digest, or selection binding is an integrity failure with no fallback.

The synthetic generator can produce empty and active packages for protocol
testing:

```sh
cd cli
go run ./examples/community/knowledge/generate-synthetic-packages.go \
  --profile tikv-gcp-v2-wif-backup \
  --output /absolute/private/test-directory
```

Those packages use ephemeral fixture keys, synthetic review dates and
`synthetic_test_only` purpose. They demonstrate import, selection and replay
mechanics only. They are not reviewed TiKV authority or a production
signing/publication path. The offline `prufyx-maintainer package-knowledge` assembler accepts
an already signed target for this closed profile; assembly does not sign or
approve it.
