# Fluentd literal treatment preview

This narrow offline check compares one caller-selected classic-config literal
for Fluentd 1.17.1 to 1.18.0. It recognizes a strict JSON declaration and
records only whether one simple `#{...}` marker is present. It does not parse
Fluentd files, Ruby, interpolation, plugins, or runtime behavior.

Keep declarations private. From the `cli` directory, use Go 1.26.8 and a
private temporary copy:

```sh
set -eu
umask 077
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
go build -buildvcs=false -o "$tmp/prufyx-community" ./cmd/prufyx-community
cp examples/cncf/fluentd-literal-treatment/broken.json "$tmp/input.json"
chmod 600 "$tmp/input.json"
"$tmp/prufyx-community" prepare cncf --project fluentd --input "$tmp/input.json" --from 1.17.1 --to 1.18.0 --format input >"$tmp/prepared.json"
chmod 600 "$tmp/prepared.json"
set +e
"$tmp/prufyx-community" check cncf --project fluentd --input "$tmp/prepared.json" --now 2026-09-12T01:00:00Z --format human
rc=$?
set -e
test "$rc" -eq 10
```

The marker-bearing unwrapped example is BLOCKED (exit 10). The `safe.json`
example has no marker and is PASS when prepared with the same command. The
single-quote wrapper form is accepted only when it is byte-identical around the
unchanged selected JSON. Missing declarations, changed bytes, escaped or
multiple markers, multiline input, and unsupported version pairs stay UNKNOWN
or fail local input admission. The check does not establish Ruby validity,
interpolation safety, plugin compatibility, or a complete Fluentd migration.
