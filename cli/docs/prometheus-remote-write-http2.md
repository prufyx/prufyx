# Prometheus remote-write HTTP/2 default check

This source-bound check covers exactly Prometheus `2.55.1` to `3.14.0`. For one
caller-selected `remote_write` entry, an omitted direct `enable_http2` changes
from the old `true` default to the target `false` default. The check compares
that direct setting with an explicit requirement for this endpoint to use
HTTP/2.

`enable_http2` is an inline key of the `remote_write` entry, beside `name` and
`url`. It is not nested under `http_config`.

From the repository root, build the preview and copy an example into an
explicit private directory outside the checkout. This command creates the
directory with mode 0700, keeps the copied input at mode 0600, and removes both
the preview binary and input when the shell exits:

```sh
set -eu
umask 077
PREVIEW_DIR="$(mktemp -d)"
chmod 700 "$PREVIEW_DIR"
cleanup_preview() { rm -rf "$PREVIEW_DIR"; }
trap cleanup_preview 0 HUP INT TERM
test "$(go env GOVERSION)" = go1.26.8
(cd cli && \
  GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o "$PREVIEW_DIR/prufyx-community" ./cmd/prufyx-community)
cp cli/examples/cncf/native-resources/prometheus/remote-write-http2-blocked.yml \
  "$PREVIEW_DIR/prometheus.yml"
chmod 600 "$PREVIEW_DIR/prometheus.yml"
config_digest="sha256:$(shasum -a 256 "$PREVIEW_DIR/prometheus.yml" | awk '{print $1}')"

prometheus_result=0
"$PREVIEW_DIR/prufyx-community" check cncf --project prometheus \
  --prometheus-config "$PREVIEW_DIR/prometheus.yml" \
  --prometheus-config-digest "$config_digest" \
  --prometheus-config-complete \
  --prometheus-config-precedence-resolved \
  --prometheus-rule remote-write-http2-default \
  --prometheus-remote-write-name primary \
  --prometheus-remote-write-http2-required=true \
  --from 2.55.1 --to 3.14.0 \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json || prometheus_result=$?
test "$prometheus_result" -eq 10
```

The omitted example is scoped `BLOCKED` when HTTP/2 is required. A direct
`enable_http2: false` is also `BLOCKED` as a declared policy contradiction. The
fixed example is scoped `PASS`. If HTTP/2 is explicitly not required, any known
direct setting, including omission, is scoped `PASS`; “not required” does not
mean “forbidden.”

Missing declarations, another version pair, no unique literal entry name,
duplicate keys, YAML aliases, merges, custom tags, substitutions, nonliteral
values, and a nested `http_config.enable_http2` lookalike stay `UNKNOWN`.

`prufyx prepare cncf` accepts the same Prometheus flags and `--format input`.
The preparation and check paths use the same canonical input. The canonical
input retains the setting class (`true`, `false`, or `omitted`) and the derived
requirement-conflict boolean. It discards the selected name, URL, credentials,
and unrelated configuration values.

A scoped `PASS` proves only that this supplied entry does not conflict with the
declared requirement under the reviewed source default. It does not validate
the whole Prometheus configuration, includes, runtime flags, endpoint HTTP/2
support, protocol negotiation, TLS or TCP behavior, sample delivery, startup,
or whole-upgrade compatibility. The command makes no network request and does
not execute Prometheus.
