#!/bin/sh
set -eu

# Compatibility entry point. The collector implementation is the native Go
# prufyx-collector executable; this shim performs no collection or projection.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cli_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)

for candidate in "$cli_root/bin/prufyx-collector" "$cli_root/prufyx-collector"; do
  if [ -x "$candidate" ] && [ ! -L "$candidate" ]; then
    exec "$candidate" collect "$@"
  fi
done

if command -v prufyx-collector >/dev/null 2>&1; then
  exec prufyx-collector collect "$@"
fi

if command -v go >/dev/null 2>&1 && [ -f "$cli_root/go.mod" ]; then
  cd "$cli_root"
  exec env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    GOFLAGS='-mod=vendor -buildvcs=false' \
    go run ./cmd/prufyx-collector collect "$@"
fi

cat >&2 <<'MESSAGE'
prufyx-collector is required. From the repository's cli directory, build it with:
  go build -o bin/prufyx-collector ./cmd/prufyx-collector
MESSAGE
exit 127
