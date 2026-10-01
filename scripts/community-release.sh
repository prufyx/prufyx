#!/usr/bin/env sh
# Compatibility launcher. Release workflow semantics are implemented by the Go
# maintainer command; this file only locates the repository checkout.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root/cli"
exec env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' \
  go run ./cmd/prufyx-maintainer release "$@"
