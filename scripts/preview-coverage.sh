#!/usr/bin/env sh
# Regenerates the rule-count sentences of cli/docs/CNCF-SOURCE-PREVIEW.md between
# the marker pairs
#   <!-- preview-counts-intro:begin -->  ...  <!-- preview-counts-intro:end -->
#   <!-- preview-counts-pack:begin -->   ...  <!-- preview-counts-pack:end -->
# from the generated support inventory (the same counts scripts/readme-coverage.sh
# uses for README.md). Nothing between the markers is typed by hand.
#
# This is a thin wrapper: the one implementation is
# `prufyx-maintainer coverage preview`, which the merge gate runs too.
#
# usage: scripts/preview-coverage.sh [--check]
#   --check  do not write; exit 1 if the document differs from the generated text
# Requires go (vendored build, offline).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root/cli"
GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' \
  exec go run ./cmd/prufyx-maintainer coverage preview --root "$root" "$@"
