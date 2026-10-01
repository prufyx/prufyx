# Fluentd 1.19.3 Ruby target requirement

These canonical examples cover only exact origins `1.14.6`, `1.15.3`,
`1.16.11`, `1.17.1`, and `1.18.0` to official Fluentd `1.19.3`. The target
gemspec requires Ruby 3.2 or newer. No Ruby interpreter, plugin, configuration,
or runtime is executed or inferred.

From `cli`, build the local Go command and copy a fixture to a private path:

```sh
umask 077
work="$(mktemp -d)"
chmod 700 "$work"
go build -mod=vendor -buildvcs=false -o "$work/prufyx-community" ./cmd/prufyx-community
cp examples/cncf/fluentd-ruby-v1.19.3/blocked.json "$work/input.json"
chmod 600 "$work/input.json"
"$work/prufyx-community" check cncf --project fluentd --input "$work/input.json" \
  --now 2026-09-12T08:06:00Z --format human
```

`blocked.json` declares official Fluentd 1.19.3 with Ruby 3.1 and is BLOCKED.
`fixed.json` declares Ruby 3.2 and is PASS. Custom builds, missing Ruby, and an
unreviewed version pair remain UNKNOWN. These facts are operator declarations;
they do not prove package provenance, installation, plugin compatibility, or a
complete upgrade.
