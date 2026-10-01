#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$script_dir/.."
exec env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' \
  go test ./internal/localcollector -run 'Component|Workload|CertManager'
