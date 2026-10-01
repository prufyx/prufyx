# OpenCost cloud-cost source selection

These inputs are operator declarations for the exact OpenCost source-selection
checks. The latest route covers 1.116.0, 1.117.6, 1.118.0, 1.119.2, and 1.120.4
to 1.121.2. The existing 1.119.0 to 1.120.0 route remains available. These are
not native OpenCost configuration files.

The first four latest-route origins have reviewed source that passes provider
configuration into cloud-cost initialization. Version 1.120.4 already passes
`nil`, so its route is a target revalidation check based only on the caller's
declared current reliance. It does not claim that 1.121.2 introduced that
initialization change or that upstream source proves deployment-specific
provider reliance.

Run from the `cli` directory with Go 1.26.8 available:

```sh
umask 077
opencost_tmp=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-opencost.XXXXXX")
trap 'rm -rf "$opencost_tmp"' EXIT HUP INT TERM
go build -trimpath -buildvcs=false -mod=vendor -o "$opencost_tmp/prufyx" ./cmd/prufyx-community
cp examples/cncf/opencost-cloud-source/provider-only-broken.json "$opencost_tmp/source.json"
chmod 600 "$opencost_tmp/source.json"
"$opencost_tmp/prufyx" prepare cncf --project opencost --input "$opencost_tmp/source.json" \
  --from 1.116.0 --to 1.121.2 --format input >"$opencost_tmp/facts.json"
chmod 600 "$opencost_tmp/facts.json"
"$opencost_tmp/prufyx" check cncf --project opencost --input "$opencost_tmp/facts.json" \
  --input-digest "sha256:$(shasum -a 256 "$opencost_tmp/facts.json" | awk '{print $1}')" \
  --now 2026-09-12T10:00:00Z --format human
opencost_exit=$?
test "$opencost_exit" -eq 10
```

The broken input declares continued provider-derived configuration for enabled
cloud-cost collection. The fixed input declares a selected cloud-integration
file present. That declaration can pass only the reviewed source-kind
predicate: the command does not open that file, inspect its schema or
credentials, validate a mount, contact a provider, or establish startup or
runtime behavior. The unresolved input remains `UNKNOWN`.
