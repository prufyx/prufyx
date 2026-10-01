#!/usr/bin/env sh
# Compatibility entrypoint. The walkthrough itself is implemented in Go.
set -eu
if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
  printf '%s\n' "usage: $0 /absolute/path/to/prufyx-community" >&2
  exit 2
fi
exec "$1" community-preview example cncf-opentelemetry
