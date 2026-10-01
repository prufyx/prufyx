# Cloud Custodian IAM access-key filter preflight

Cloud Custodian package 0.9.52 no longer registers `json-diff` for the
`iam-access-key` resource. The latest route covers exact package versions
0.9.47, 0.9.48, 0.9.49, 0.9.50, and 0.9.51 to 0.9.52. The retained source
contract binds those package versions to the corresponding four-part upstream
release tags. The existing 0.9.50 to 0.9.51 route remains available.
The retained target evidence binds the complete `iam-access-key` resource
definition to the inherited `TypeInfo.config_type = None` default used by the
`json-diff` registration guard.

This local check reads one private JSON policy, projects only the selected
filter fact, and never runs Cloud Custodian or contacts AWS.

From the `cli` directory with Go 1.26.8 available:

```sh
umask 077
custodian_tmp=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-custodian.XXXXXX")
trap 'rm -rf "$custodian_tmp"' EXIT HUP INT TERM
go build -trimpath -buildvcs=false -mod=vendor -o "$custodian_tmp/prufyx" ./cmd/prufyx-community
cp examples/cncf/cloud-custodian-json-diff/blocked-policy.json "$custodian_tmp/policy.json"
chmod 600 "$custodian_tmp/policy.json"
"$custodian_tmp/prufyx" prepare cncf --project cloud-custodian \
  --input "$custodian_tmp/policy.json" \
  --from 0.9.47 --to 0.9.52 --format input >"$custodian_tmp/prepared.json"
chmod 600 "$custodian_tmp/prepared.json"
"$custodian_tmp/prufyx" check cncf --project cloud-custodian \
  --input "$custodian_tmp/prepared.json" \
  --now 2026-09-12T10:00:00Z --format human
custodian_exit=$?
test "$custodian_exit" -eq 10
```

The blocked example returns exit 10. The fixed example has an explicitly empty
filter list and returns a scoped PASS (exit 0) for absence of this one removed
filter in this one complete selected policy. Missing filters, variables,
includes, dynamic selection, nested or unsupported filters, malformed JSON, and
other resources remain UNKNOWN or are rejected as invalid input. Policy names,
paths, values, and arbitrary filters are not retained in the minimized input or
report. This does not assess AWS Config, policy execution, runtime behavior, or
whole-upgrade safety.
