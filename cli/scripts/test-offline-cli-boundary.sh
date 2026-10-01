#!/usr/bin/env sh
# Compatibility entrypoint only. The scenario matrix, private fixture
# generation, JSON assertions, and namespace observer all live in Go.
set -eu

case "$(uname -s)" in
  Linux) exec env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    GOFLAGS='-mod=vendor -buildvcs=false' \
    go test ./internal/offlineboundary -run '^TestOfflineBoundaryLinuxCommunityJourneys$' "$@" ;;
  *) printf '%s\n' 'offline CLI boundary: SKIP (Linux integration gate only)' >&2 ;;
esac
