# OpenTelemetry Collector native check

This example selects a small YAML subset: a non-empty top-level `exporters`
map and optional pipeline exporter references. It checks only whether a
top-level `logging` or `logging/name` exporter is configured for the reviewed
`0.110.0` to `0.111.0` transition. It does not run a Collector or validate
pipeline startup, connectors, providers, environment expansion, or delivery.

Run this from a checkout root with Go 1.26.8 and copy the tracked example to a
private `0600` file before checking it. Set `PRUFYX_BIN` to an existing
checkout-root binary, or let the command build a temporary binary outside the
checkout. The `official` distribution and the two completeness flags are
caller-declared.

```sh
set -eu
umask 077
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
test "$(go env GOVERSION)" = go1.26.8
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
if [ -n "${PRUFYX_BIN:-}" ]; then
  test -x "$PRUFYX_BIN"
else
  (cd cli && GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
    go build -trimpath -buildvcs=false -o "$task_dir/prufyx-community" ./cmd/prufyx-community)
  PRUFYX_BIN="$task_dir/prufyx-community"
fi
cp cli/examples/cncf/opentelemetry-collector/native-config.yaml "$task_dir/collector.yaml"
chmod 600 "$task_dir/collector.yaml"
blocked_result=0
"$PRUFYX_BIN" check cncf --project opentelemetry \
  --otel-collector-config "$task_dir/collector.yaml" \
  --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --from 0.110.0 --to 0.111.0 --now 2026-09-12T02:35:00Z --format json || blocked_result=$?
test "$blocked_result" -eq 10

cp cli/examples/cncf/opentelemetry-collector/native-fixed.yaml "$task_dir/collector-fixed.yaml"
chmod 600 "$task_dir/collector-fixed.yaml"
fixed_output=$("$PRUFYX_BIN" check cncf --project opentelemetry \
  --otel-collector-config "$task_dir/collector-fixed.yaml" \
  --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --from 0.110.0 --to 0.111.0 --now 2026-09-12T02:35:00Z --format json)
printf '%s\n' "$fixed_output" | grep -q '"status":"PASS"'

cp cli/examples/cncf/opentelemetry-collector/native-unknown.yaml "$task_dir/collector-unknown.yaml"
chmod 600 "$task_dir/collector-unknown.yaml"
unknown_result=0
"$PRUFYX_BIN" check cncf --project opentelemetry \
  --otel-collector-config "$task_dir/collector-unknown.yaml" \
  --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --from 0.110.0 --to 0.111.0 --now 2026-09-12T02:35:00Z --format json || unknown_result=$?
test "$unknown_result" -eq 11
```

This selected configuration is expected to produce a scoped `BLOCKED` claim.
The fixed fixture uses a matching `debug` pipeline reference and produces the
scoped absence `PASS` when the same declarations are complete. The unknown
fixture references a connector-only `logging` ID and produces `UNKNOWN`.

## Internal metrics default bind

The explicitly selected `internal-telemetry-default-bind` route covers only
the source-defined `0.110.0` → `0.111.0` default. It needs a complete,
precedence-resolved official Collector declaration, plus the caller's effective
feature-gate and remote-scrape requirement. With no `service.telemetry.metrics`
override, a localhost default and a required remote scrape produce `BLOCKED`;
a wildcard default or no remote-scrape requirement produces `PASS`. An override,
missing authority, unsupported syntax, or ambiguous scope produces `UNKNOWN`.
These are declared configuration outcomes; they do not observe a running
Collector, listener, Service, scrape, or network.

Copy each tracked fixture to a private file before checking it. The commands
below use `mktemp -d` and an explicit mode change so they work in both Bash and
Zsh. Set `PRUFYX_BIN` to an existing checkout-root binary (or `prufyx` on your
`PATH`). Expected exit codes are `10` for `BLOCKED`, `0` for `PASS`, and `11`
for `UNKNOWN`.

```sh
umask 077
PRUFYX_BIN=${PRUFYX_BIN:-prufyx}
otel_dir=$(mktemp -d)
chmod 700 "$otel_dir"
cp cli/examples/cncf/opentelemetry-collector/internal-metrics-blocked.yaml "$otel_dir/blocked.yaml"
cp cli/examples/cncf/opentelemetry-collector/internal-metrics-fixed.yaml "$otel_dir/fixed.yaml"
cp cli/examples/cncf/opentelemetry-collector/internal-metrics-unknown.yaml "$otel_dir/unknown.yaml"
chmod 600 "$otel_dir"/*.yaml

prufyx_example_exit=0
"$PRUFYX_BIN" check cncf --project opentelemetry --otel-rule internal-telemetry-default-bind \
  --otel-collector-config "$otel_dir/blocked.yaml" --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --otel-metrics-localhost-default true --otel-metrics-remote-scrape-required true \
  --from 0.110.0 --to 0.111.0 --now 2026-09-13T10:00:00Z --format json >"$otel_dir/blocked.json" || prufyx_example_exit=$?
test "$prufyx_example_exit" -eq 10
grep -q '"status":"BLOCKED"' "$otel_dir/blocked.json"

"$PRUFYX_BIN" check cncf --project opentelemetry --otel-rule internal-telemetry-default-bind \
  --otel-collector-config "$otel_dir/fixed.yaml" --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --otel-metrics-localhost-default false --otel-metrics-remote-scrape-required true \
  --from 0.110.0 --to 0.111.0 --now 2026-09-13T10:00:00Z --format json >"$otel_dir/fixed.json"
grep -q '"status":"PASS"' "$otel_dir/fixed.json"

prufyx_example_exit=0
"$PRUFYX_BIN" check cncf --project opentelemetry --otel-rule internal-telemetry-default-bind \
  --otel-collector-config "$otel_dir/unknown.yaml" --otel-distribution official \
  --otel-config-complete --otel-config-precedence-resolved \
  --otel-metrics-localhost-default false --otel-metrics-remote-scrape-required true \
  --from 0.110.0 --to 0.111.0 --now 2026-09-13T10:00:00Z --format json >"$otel_dir/unknown.json" || prufyx_example_exit=$?
test "$prufyx_example_exit" -eq 11
grep -q '"status":"UNKNOWN"' "$otel_dir/unknown.json"
```
