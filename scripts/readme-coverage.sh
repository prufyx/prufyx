#!/usr/bin/env sh
# Regenerates the coverage block of README.md between the markers
#   <!-- coverage:begin -->  and  <!-- coverage:end -->
# from the knowledge in the tree: its rule pack, the pinned release-line
# snapshot, the generated support inventory and the CRD version targets.
# Nothing in the block is typed by hand.
#
# This is a thin wrapper: the one implementation is
# `prufyx-maintainer coverage readme`, which the merge gate runs too.
#
# usage: scripts/readme-coverage.sh [--check]
#   --check  do not write; exit 1 if README.md differs from the generated block
# Requires go (vendored build, offline).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root/cli"
GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' \
  exec go run ./cmd/prufyx-maintainer coverage readme --root "$root" "$@"
