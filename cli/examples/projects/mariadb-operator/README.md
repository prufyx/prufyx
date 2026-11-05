# MariaDB Operator: check an intermediate configuration

This offline example checks one synthetic Galera-enabled `MariaDB` resource for
the exact MariaDB Operator `26.3.0` to `26.6.0` transition. It evaluates the
blocked resource, a separate corrected intermediate resource, and an incomplete
resource. The results are scoped to the existing reviewed rule: they do not
establish Kubernetes admission, runtime readiness, data-plane completion, or
whole-upgrade safety. The operator update is not performed.

From the repository root, with Go dependencies already available and `jq` and
`sha256sum` installed, run:

```sh
set -eu
umask 077
work=$(mktemp -d)
mkdir "$work/inputs" "$work/reports"
go -C cli build -o "$work/prufyx" ./cmd/prufyx-community
cp cli/examples/projects/mariadb-operator/broken.json \
  cli/examples/projects/mariadb-operator/fixed.json \
  cli/examples/projects/mariadb-operator/unknown.json "$work/inputs/"

# These are three separate reference artifacts, not observed cluster state.
sha256sum "$work"/inputs/*.json > "$work/inputs.sha256"
run_check() {
  name=$1
  expected_exit=$2
  expected_claim=$3
  input="$work/inputs/$name.json"
  pin="sha256:$(sha256sum "$input" | cut -d ' ' -f 1)"
  if "$work/prufyx" check project --project mariadb-operator \
      --mariadb-resource "$input" --mariadb-resource-digest "$pin" \
      --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update \
      --now 2026-09-13T09:00:00Z --format json \
      > "$work/reports/$name.json" 2> "$work/reports/$name.stderr"; then
    actual_exit=0
  else
    actual_exit=$?
  fi
  test "$actual_exit" -eq "$expected_exit"
  jq -e --arg claim "$expected_claim" \
    '.assessment == "UNKNOWN" and .check.claims[0].status == $claim' \
    "$work/reports/$name.json" > /dev/null
  printf '%s: exit %s, scoped %s, whole upgrade UNKNOWN\n' \
    "$name" "$actual_exit" "$expected_claim"
}
run_check broken 10 BLOCKED
run_check fixed 0 PASS
run_check unknown 11 UNKNOWN

# A saved digest for the corrected input cannot authorize the blocked input.
fixed_pin="sha256:$(sha256sum "$work/inputs/fixed.json" | cut -d ' ' -f 1)"
if "$work/prufyx" check project --project mariadb-operator \
    --mariadb-resource "$work/inputs/broken.json" \
    --mariadb-resource-digest "$fixed_pin" --from 26.3.0 --to 26.6.0 \
    --resource-complete --pre-operator-update --now 2026-09-13T09:00:00Z \
    --format json > "$work/reports/pin-mismatch.json" 2> "$work/reports/pin-mismatch.stderr"; then
  pin_exit=0
else
  pin_exit=$?
fi
test "$pin_exit" -eq 3
printf 'input digest mismatch: exit %s\n' "$pin_exit"

# Unsupported target, resource and expired-evidence cases never inherit PASS.
negative() {
  name=$1
  expected_exit=$2
  shift 2
  if "$work/prufyx" check project "$@" --format json \
      > "$work/reports/$name.json" 2> "$work/reports/$name.stderr"; then
    actual_exit=0
  else
    actual_exit=$?
  fi
  test "$actual_exit" -eq "$expected_exit"
  if test "$expected_exit" -eq 11; then
    jq -e '.assessment == "UNKNOWN"' "$work/reports/$name.json" > /dev/null
  fi
  printf '%s: exit %s\n' "$name" "$actual_exit"
}
sed 's/"kind": "MariaDB"/"kind": "Other"/' "$work/inputs/fixed.json" > "$work/inputs/wrong-kind.json"
negative wrong-project 2 --project mariadb --mariadb-resource "$work/inputs/fixed.json" \
  --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update --now 2026-09-13T09:00:00Z
negative wrong-pair 11 --project mariadb-operator --mariadb-resource "$work/inputs/fixed.json" \
  --from 26.3.0 --to 26.7.0 --resource-complete --pre-operator-update --now 2026-09-13T09:00:00Z
negative wrong-kind 11 --project mariadb-operator --mariadb-resource "$work/inputs/wrong-kind.json" \
  --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update --now 2026-09-13T09:00:00Z
negative stale-evidence 11 --project mariadb-operator --mariadb-resource "$work/inputs/fixed.json" \
  --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update --now 2027-01-01T00:00:00Z
printf 'Inputs, hashes and reports retained in %s\n' "$work"
```

`broken.json` declares `spec.updateStrategy.autoUpdateDataPlane: false`.
`fixed.json` is the explicit intermediate artifact with that field set to
`true`; the second command evaluates its actual bytes, not the previous
report. The digest option binds each evaluation to the raw input bytes. The
source files and hashes are retained so a later change requires a new digest
and evaluation. `unknown.json` omits the field and remains UNKNOWN.

The fixed `--now` value makes this a reproducible historical example. It does
not assert that evidence is current at the time you run it; use an appropriate
evaluation time for a real check. Each JSON report records the selected input
and rule digests, embedded knowledge revision, scoped claim, and immutable
source citations. The reviewed upgrade guidance is among the `sources` in each
claim. A scoped PASS is not evidence that the configuration was applied or
that the data plane completed its update.
