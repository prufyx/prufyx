#!/usr/bin/env bash
# Runs one shard of the tests of one Go package, so a package that is slow on
# its own can be spread over several CI jobs.
#
# usage: scripts/ci-test-shard.sh INDEX TOTAL PACKAGE [flags...] [-- run-only flags...]
#   INDEX  1..TOTAL, this shard
#   TOTAL  number of shards (every shard 1..TOTAL must run)
#   Run from the cli/ directory. Flags before `--` (-tags, ...) go to both
#   `go test -list` and `go test`; flags after `--` (-timeout, -covermode,
#   -coverprofile, ...) go to `go test` only.
#
# The shard is derived from the full list of tests that `go test -list`
# reports for the package (the same build tags), sorted by name: test number
# N (1-based) belongs to shard ((N-1) mod TOTAL)+1. Every test is therefore in
# exactly one shard, with no list to keep in sync. A package that lists no
# tests, or an index outside 1..TOTAL, fails the job: a missing proof is a
# failure, never a pass.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 INDEX TOTAL PACKAGE [go test flags...]" >&2
  exit 2
fi
index=$1
total=$2
pkg=$3
shift 3

common=()
runonly=()
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--" ]; then
    shift
    runonly=("$@")
    break
  fi
  common+=("$1")
  shift
done

case "${index}${total}" in
  *[!0-9]* | "") echo "INDEX and TOTAL must be positive integers" >&2; exit 2 ;;
esac
if [ "${total}" -lt 1 ] || [ "${index}" -lt 1 ] || [ "${index}" -gt "${total}" ]; then
  echo "shard ${index}/${total} is outside 1..${total}" >&2
  exit 2
fi

listing=$(go test -list '.*' "${common[@]+"${common[@]}"}" "${pkg}")
all=$(printf '%s\n' "${listing}" | grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' | LC_ALL=C sort -u || true)
if [ -z "${all}" ]; then
  echo "go test -list reported no tests for ${pkg}" >&2
  exit 1
fi
count=$(printf '%s\n' "${all}" | grep -c .)

mine=$(printf '%s\n' "${all}" | awk -v i="${index}" -v n="${total}" '(NR - 1) % n + 1 == i')
if [ -z "${mine}" ]; then
  echo "shard ${index}/${total}: ${count} tests in ${pkg}, none for this shard"
  exit 0
fi
mycount=$(printf '%s\n' "${mine}" | grep -c .)
echo "shard ${index}/${total}: ${mycount} of ${count} tests in ${pkg}"

# Go test names are letters, digits and underscores, so they need no quoting
# inside the anchored alternation.
pattern="^($(printf '%s\n' "${mine}" | paste -sd '|' -))\$"
go test "${common[@]+"${common[@]}"}" "${runonly[@]+"${runonly[@]}"}" -run "${pattern}" "${pkg}"
