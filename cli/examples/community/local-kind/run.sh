#!/usr/bin/env sh
# Compatibility launcher. The manual kind proof is implemented by the Go
# maintainer command; this file only locates the checked-out CLI module.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: run.sh /absolute/prufyx /absolute/prufyx-collector /absolute/new-evidence-directory" >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)
cd "$root"
exec env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' \
  go run ./cmd/prufyx-maintainer local-kind \
  --prufyx "$1" --collector "$2" --evidence "$3"
