# Argo CD resource-exclusions native check

Run these commands from the repository root after building the local executable.
Set `PRUFYX_BIN` to that executable's absolute or repository-relative path; this
preview has no prebuilt binary. Each command copies a public fixture into a new
private directory, so it does not modify a user ConfigMap or an existing file.

```sh
set -eu
: "${PRUFYX_BIN:?set PRUFYX_BIN to an existing built prufyx executable}"
test -x "$PRUFYX_BIN"
umask 077
example_dir="$(mktemp -d)"
trap 'rm -rf "$example_dir"' EXIT
fixture='cli/examples/cncf/native-resources/argocd-resource-exclusions'
review_time='2026-09-12T01:23:59Z'
```

The following four commands use identical route, version, completeness,
precedence, intent, clock, and `human` format arguments. They differ only in
the copied public fixture.

```sh
cp "$fixture/blocked-source-default.yaml" "$example_dir/blocked-source-default.yaml"
chmod 600 "$example_dir/blocked-source-default.yaml"
set +e
"$PRUFYX_BIN" check cncf --project argo-cd \
  --resource-exclusions-config-map "$example_dir/blocked-source-default.yaml" \
  --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete \
  --resource-exclusions-precedence-resolved \
  --requires-v2-visibility-of-v3-default-excluded-resources true \
  --now "$review_time" --format human
result=$?
set -e
test "$result" -eq 10 # BLOCKED
```

```sh
cp "$fixture/fixed-absent.yaml" "$example_dir/fixed-absent.yaml"
chmod 600 "$example_dir/fixed-absent.yaml"
"$PRUFYX_BIN" check cncf --project argo-cd \
  --resource-exclusions-config-map "$example_dir/fixed-absent.yaml" \
  --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete \
  --resource-exclusions-precedence-resolved \
  --requires-v2-visibility-of-v3-default-excluded-resources true \
  --now "$review_time" --format human
# Exit 0: PASS
```

```sh
cp "$fixture/fixed-empty.yaml" "$example_dir/fixed-empty.yaml"
chmod 600 "$example_dir/fixed-empty.yaml"
"$PRUFYX_BIN" check cncf --project argo-cd \
  --resource-exclusions-config-map "$example_dir/fixed-empty.yaml" \
  --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete \
  --resource-exclusions-precedence-resolved \
  --requires-v2-visibility-of-v3-default-excluded-resources true \
  --now "$review_time" --format human
# Exit 0: PASS
```

```sh
cp "$fixture/unknown-altered-key.yaml" "$example_dir/unknown-altered-key.yaml"
chmod 600 "$example_dir/unknown-altered-key.yaml"
set +e
"$PRUFYX_BIN" check cncf --project argo-cd \
  --resource-exclusions-config-map "$example_dir/unknown-altered-key.yaml" \
  --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete \
  --resource-exclusions-precedence-resolved \
  --requires-v2-visibility-of-v3-default-excluded-resources true \
  --now "$review_time" --format human
result=$?
set -e
test "$result" -eq 11 # UNKNOWN
```

The native input is one caller-selected `v1` ConfigMap whose literal
`metadata.name` is `argocd-cm`. The checker canonical-parses the scalar as YAML
and compares the complete seven-entry sequence, map keys, list values, and
order to the reviewed 3.0 source default. It rejects additional entries,
duplicate or altered keys, tags, anchors, aliases, merges, templates,
multi-document input, and non-string ConfigMap data. It reports only digests
and the classification, never a raw ConfigMap value. Completeness, precedence,
and preservation intent are caller declarations; resource existence, watches,
UI, reconciliation, runtime, and whole-upgrade behavior remain unassessed.
